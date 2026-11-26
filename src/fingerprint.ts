import { createHmac } from 'node:crypto';
import { z } from 'zod';
import { ConfigSchema } from './spec.ts';

// The stored marker format stays stable across product renames.
export const MarkerSchema = z.string().regex(/^ultron_[a-f0-9]{32}$/);
export function createFingerprint(config: unknown): string {
  const { secret, projectId } = ConfigSchema.parse(config);
  return 'ultron_' + createHmac('sha256', secret).update('ultron:fingerprint:v1:' + projectId).digest('hex').slice(0, 32);
}
export function fingerprintTag(marker: string): string {
  return `<meta name="siftkeep-fingerprint" content="${MarkerSchema.parse(marker)}">`;
}
