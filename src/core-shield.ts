import type { IncomingMessage, ServerResponse } from 'node:http';

type InteractivePrincipal = { kind: 'interactive'; identity: string; sessionId: string };
export type CorePrincipal = InteractivePrincipal | { kind: 'automation'; identity: string };

export interface CoreShieldOptions {
  /** Resolve identity and credential type from verified server-side authentication. */
  resolvePrincipal: (request: IncomingMessage) => CorePrincipal | undefined | Promise<CorePrincipal | undefined>;
  /** Check permission for the specific operation and resource. */
  authorize: (request: IncomingMessage, principal: InteractivePrincipal) => boolean | Promise<boolean>;
  /** Verify and consume fresh user verification bound to the session and exact operation. */
  consumeUserVerification: (request: IncomingMessage, principal: InteractivePrincipal) => boolean | Promise<boolean>;
}

const errors = {
  403: { code: 'CORE_ACCESS_DENIED', message: 'Core access denied.' },
  503: { code: 'CORE_VERIFICATION_UNAVAILABLE', message: 'Core verification is unavailable.' },
};

export function createCoreShield(options: CoreShieldOptions) {
  return async (request: IncomingMessage, response: ServerResponse, next: () => void): Promise<void> => {
    let rejection: keyof typeof errors | undefined;
    try {
      const principal = await options.resolvePrincipal(request);
      const allowed = principal?.kind === 'interactive'
        && typeof principal.identity === 'string' && principal.identity.trim() !== ''
        && typeof principal.sessionId === 'string' && principal.sessionId.trim() !== ''
        && await options.authorize(request, principal) === true
        && await options.consumeUserVerification(request, principal) === true;
      if (!allowed) rejection = 403;
    } catch {
      rejection = 503;
    }

    if (rejection === undefined) {
      next();
      return;
    }
    response.writeHead(rejection, { 'content-type': 'application/json', 'cache-control': 'private, no-store' });
    response.end(JSON.stringify({ error: errors[rejection] }));
  };
}
