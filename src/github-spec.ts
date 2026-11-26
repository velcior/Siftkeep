import { z } from 'zod';
import { MarkerSchema } from './fingerprint.ts';

const RepositorySchema = z.string().regex(/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/);
export const ScanInputSchema = z.object({
  marker: MarkerSchema,
  ownedRepositories: z.array(RepositorySchema).min(1).max(100),
});
export const CandidateSchema = z.object({
  kind: z.literal('possible_copy'), repository: RepositorySchema,
  url: z.url(), path: z.string(), evidence: z.literal('github_indexed_fingerprint'),
});
export const ScanOutputSchema = z.object({
  candidates: z.array(CandidateSchema), incomplete: z.boolean(), checkedAt: z.string(),
});
export const ScanErrorSchema = z.object({
  code: z.enum(['INVALID_INPUT', 'NETWORK_ERROR', 'UPSTREAM_ERROR', 'INVALID_RESPONSE']),
  message: z.string(), recoverable: z.boolean(),
});
export type ScanResult = { success: true; data: z.infer<typeof ScanOutputSchema> } | { success: false; error: z.infer<typeof ScanErrorSchema> };
export interface ScannerSpec { scan(input: unknown): Promise<ScanResult> }
export const GitHubResponseSchema = z.object({
  total_count: z.number().int().nonnegative(), incomplete_results: z.boolean(),
  items: z.array(z.object({
    html_url: z.url().refine(value => { const url = new URL(value); return url.protocol === 'https:' && url.hostname === 'github.com' && !url.username && !url.password; }),
    path: z.string().max(2048), repository: z.object({ full_name: RepositorySchema }),
  })).max(100),
});
