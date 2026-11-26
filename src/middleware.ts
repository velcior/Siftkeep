import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { GuardSpec } from './spec.ts';

export interface MiddlewareOptions {
  /** Resolve from server-validated auth/session state. Never trust a user-supplied identity header. */
  identify: (request: IncomingMessage) => { identity: string; trusted?: boolean } | undefined;
  /** Optional application route template, e.g. /app/projects/:id, to avoid counting each record as a new feature. */
  normalizePath?: (pathname: string) => string;
  onError?: () => void;
}

export function createMiddleware(guard: GuardSpec, options: MiddlewareOptions) {
  return (request: IncomingMessage, response: ServerResponse, next: () => void): void => {
    let limited = false;
    let retryAfterSeconds = 1;
    try {
      const subject = options.identify(request);
      if (subject) {
        const pathname = new URL(request.url ?? '/', 'http://siftkeep.invalid').pathname;
        const result = guard.evaluate({ ...subject, pathname: options.normalizePath?.(pathname) ?? pathname,
          method: request.method ?? 'GET', requestId: randomUUID(),
        });
        if (!result.success) options.onError?.();
        else if (result.data.action === 'rate_limit') {
          limited = true;
          retryAfterSeconds = result.data.retryAfterSeconds ?? 1;
        }
      }
    } catch {
      try { options.onError?.(); } catch { /* Fail open if telemetry fails too. */ }
    }
    if (!limited) { next(); return; }
    response.writeHead(429, { 'content-type': 'application/json', 'retry-after': String(retryAfterSeconds), 'cache-control': 'private, no-store' });
    response.end(JSON.stringify({ error: { code: 'RATE_LIMITED', message: 'Too many read requests. Please retry shortly.' } }));
  };
}
