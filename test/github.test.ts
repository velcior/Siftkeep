import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GitHubScanner } from '../src/github.ts';

test('GitHub discovery excludes owned repos and reports candidates, never confirmed clones', async () => {
  const calls: { url: string; options?: RequestInit }[] = [];
  const scanner = new GitHubScanner({ token: 'test-token', fetch: async (url: string, options?: RequestInit) => {
    calls.push({ url, options });
    return Response.json({ total_count: 2, incomplete_results: false, items: [
      { html_url: 'https://github.com/creator/product/blob/main/index.html', path: 'index.html', repository: { full_name: 'creator/product' } },
      { html_url: 'https://github.com/someone/copy/blob/main/index.html', path: 'index.html', repository: { full_name: 'someone/copy' } },
    ] });
  } });
  const result = await scanner.scan({ marker: 'ultron_' + 'a'.repeat(32), ownedRepositories: ['Creator/Product'] });
  assert.equal(result.success, true);
  assert.ok(result.success);
  assert.equal(result.data.candidates.length, 1);
  assert.ok(result.data.candidates[0]);
  assert.equal(result.data.candidates[0].kind, 'possible_copy');
  assert.equal(result.data.candidates[0].repository, 'someone/copy');
  assert.equal(result.data.incomplete, false);
  assert.equal(new URL(calls[0]!.url).hostname, 'api.github.com');
  assert.equal(new Headers(calls[0]!.options!.headers).get('authorization'), 'Bearer test-token');
  assert.ok(!JSON.stringify(result).includes('test-token'));
});

test('invalid upstream search data is a failed scan, not an empty list of copies', async () => {
  const scanner = new GitHubScanner({ token: 'test-token', fetch: async () => Response.json({ items: [] }) });
  const result = await scanner.scan({ marker: 'ultron_' + 'a'.repeat(32), ownedRepositories: ['creator/product'] });
  assert.equal(result.success, false);
  assert.ok(!result.success);
  assert.equal(result.error.code, 'INVALID_RESPONSE');
});
