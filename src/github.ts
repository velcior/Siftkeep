import { z } from 'zod';
import { GitHubResponseSchema, ScanInputSchema } from './github-spec.ts';
import type { ScannerSpec, ScanResult } from './github-spec.ts';

export interface GitHubOptions {
  token: string;
  fetch?: (url: string, options?: RequestInit) => Promise<Response>;
}
export class GitHubScanner implements ScannerSpec {
  private readonly options: GitHubOptions;
  constructor(options: GitHubOptions) {
    z.string().min(1).parse(options.token);
    this.options = options;
  }
  async scan(input: unknown): Promise<ScanResult> {
    const parsed = ScanInputSchema.safeParse(input);
    if (!parsed.success) return { success: false, error: { code: 'INVALID_INPUT', message: 'Provide a valid marker and at least one owned repository.', recoverable: false } };
    try {
      const url = new URL('https://api.github.com/search/code');
      url.searchParams.set('q', `"${parsed.data.marker}"`);
      url.searchParams.set('per_page', '100');
      const response = await (this.options.fetch ?? fetch)(url.href, {
        headers: { authorization: `Bearer ${this.options.token}`, accept: 'application/vnd.github+json', 'user-agent': 'siftkeep/2.1' },
        redirect: 'error', signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) {
        await response.body?.cancel();
        return { success: false, error: { code: 'UPSTREAM_ERROR', message: `GitHub search returned HTTP ${response.status}; check credentials and rate limits.`, recoverable: true } };
      }
      let body: unknown;
      try { body = await response.json(); }
      catch { return { success: false, error: { code: 'INVALID_RESPONSE', message: 'GitHub returned invalid JSON.', recoverable: true } }; }
      const decoded = GitHubResponseSchema.safeParse(body);
      if (!decoded.success) return { success: false, error: { code: 'INVALID_RESPONSE', message: 'GitHub returned an unexpected response.', recoverable: true } };
      const owned = new Set(parsed.data.ownedRepositories.map(name => name.toLowerCase()));
      const seen = new Set<string>();
      const candidates = decoded.data.items.filter(item => {
        if (owned.has(item.repository.full_name.toLowerCase()) || seen.has(item.html_url)) return false;
        seen.add(item.html_url);
        return new URL(item.html_url).pathname.toLowerCase().startsWith('/' + item.repository.full_name.toLowerCase() + '/');
      }).map(item => ({ kind: 'possible_copy' as const, repository: item.repository.full_name,
        url: item.html_url, path: item.path, evidence: 'github_indexed_fingerprint' as const,
      }));
      return { success: true, data: { candidates,
        incomplete: decoded.data.incomplete_results || decoded.data.total_count > decoded.data.items.length,
        checkedAt: new Date().toISOString(),
      } };
    } catch {
      return { success: false, error: { code: 'NETWORK_ERROR', message: 'GitHub search could not complete; retry later.', recoverable: true } };
    }
  }
}
