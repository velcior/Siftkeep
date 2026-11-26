import { createHmac } from 'node:crypto';
import { z } from 'zod';

export interface WebhookOptions {
  /** Operator-configured destination. Do not accept this value from app visitors. */
  url: string;
  signingSecret: string;
  fetch?: (url: string, options: RequestInit) => Promise<Response>;
}
export function createWebhookSink(options: WebhookOptions): (event: unknown) => Promise<void> {
  const destination = z.url().refine(value => {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password;
  }, 'An HTTPS URL without embedded credentials is required').parse(options.url);
  z.string().min(32).parse(options.signingSecret);
  return async event => {
    const body = JSON.stringify(event);
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = createHmac('sha256', options.signingSecret).update(timestamp + '.' + body).digest('hex');
    const response = await (options.fetch ?? fetch)(destination, {
      method: 'POST', body, redirect: 'error', signal: AbortSignal.timeout(5000),
      headers: { 'content-type': 'application/json', 'x-ultron-timestamp': timestamp, 'x-ultron-signature': 'sha256=' + signature, 'x-siftkeep-timestamp': timestamp, 'x-siftkeep-signature': 'sha256=' + signature },
    });
    await response.body?.cancel();
    if (!response.ok) throw new Error(`Alert delivery returned HTTP ${response.status}`);
  };
}
