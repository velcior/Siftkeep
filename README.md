# Ultron

**Protect private SaaS operations and catch accidental source disclosure in public web builds.**

Ultron is an early prototype for Node.js HTTP and Express apps. Mount the core shield in front of sensitive handlers. It requires an interactive user session, permission for the operation, and fresh user verification. Traffic monitoring, rate limits, and fingerprint searches are separate tools for the public-facing surface.

## V2 public web release protection

With Node.js 24+, run `npm ci` and `npm run build` in the Ultron checkout. After building your web app, run `node dist/cli.js audit path/to/web-build` from the compiled Ultron checkout. Findings produce JSON and exit code 1 for CI. Use a finished, idle build directory containing only public assets.

Run `node dist/cli.js harden path/to/web-build` to create a fresh sibling directory. Use the JSON output path for deployment and run your application smoke tests against it first. External .map files are omitted. Inline map markers in JS, CSS, HTML or SVG, development source extensions, environment files, Git metadata, dependencies and unsupported file types block staging. Fix these in your build configuration and retry. External map references can remain in bundles and produce missing-map messages in developer tools.

This feature reduces accidental source disclosure. Delivered JavaScript remains readable and copyable. Keep proprietary operations behind the server-side shield. The audit is a filename and text-marker check with no coverage for arbitrary embedded secrets, compressed assets or remotely hosted source maps.

## Protect the app core

`createCoreShield` checks each request before running the protected handler, including reads and writes.

1. **Identity.** Resolve the principal from authenticated server state. Anonymous callers and unrecognized credentials are denied.
2. **Credential type.** Deny automation credentials, including agent integrations, skill API keys, and service accounts. Keep the credential type in trusted authentication state.
3. **Operation permission.** Check the account's permission for the exact action, tenant, and resource.
4. **Fresh verification.** Verify and atomically consume a short-lived approval tied to the session and exact action. A valid session alone cannot reach the handler.

```ts
import { createCoreShield } from './dist/index.js';

// Mount after your authentication middleware and input validation.
app.post('/api/core/export', createCoreShield({
  resolvePrincipal: resolveVerifiedPrincipal,
  authorize: canExportRequestedData,
  consumeUserVerification: consumeExportApproval,
}), exportPrivateData);
```

The callbacks belong to your app. Return `{ kind: 'interactive', identity, sessionId }` for a verified user session, `{ kind: 'automation', identity }` for a verified machine credential, or `undefined` for an unknown caller. Derive this from verified credentials and server-side state. Browser signatures, user-agent strings, and caller-supplied flags cannot establish credential type or approval.

For a passkey step-up, require WebAuthn user verification and verify the assertion on the server. Bind the challenge to the account, session, and operation parameters the user approved. Consume it once in a store shared by all app instances that can accept the request. [W3C WebAuthn verification steps](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion)

Failed checks return `403`. A verification callback that throws or rejects returns `503` and the handler stays closed. These decisions are independent of the traffic monitor's `off`, `observe`, and `protect` modes.

Keep sensitive logic and data server-side, and apply the shield at every client-accessible entry point to the protected operation. An agent can drive a normal browser, so the app relies on fresh, action-bound verification even for a valid interactive session. A user can still choose to approve an action an agent initiated.

Run `node --test test/core-shield.test.ts` with Node.js 24+ to exercise the gate over HTTP with test authentication and approvals.

## Try traffic monitoring locally

Requires Node.js 24+.

1. Run `npm ci`.
2. Run `npm run demo`. Open <http://127.0.0.1:4317>.
3. In a second terminal, run `npm run simulate`.

The simulator makes 16 read requests with one signed demo session. Default **observe** mode preserves the app responses and prints one `suspected_extraction` event in the server terminal. No external alerts are sent unless you configure a webhook.

To try enforcement in PowerShell, stop the demo and run:

```powershell
$env:ULTRON_MODE = 'protect'
npm run demo
```

Run the simulator again: the last four reads should return HTTP 429. Set the mode to `observe` or `off` and restart to remove enforcement. `off` also disables monitoring. The demo issues anonymous sessions for illustration; clearing a cookie can evade that identity. It is not production authentication.

## What exists

| Component | Behavior |
| --- | --- |
| Core shield | Node HTTP and Express middleware that gates sensitive handlers on verified session type, operation permission, and fresh approval |
| Traffic middleware | Observes selected routes and applies optional rate limits |
| Behavior detector | Per-identity request volume and distinct pathname counts in a fixed window |
| Optional enforcement | HTTP 429 with `Retry-After` only when both thresholds are exceeded, in protect mode, on eligible GET routes |
| Owner alerts | Structured events and optional signed HTTPS webhooks, isolated from delivery failures |
| Copy discovery | Optional stable HTML fingerprint and authenticated GitHub code search for indexed matches outside owned repositories |

Two signals are correlated observations, not independent proof. An automated test, a customer, or a permitted agent can also trigger them. A slow cloner can avoid them.

## Add traffic monitoring to a SaaS

Build with `npm run build`; import the resulting module. The local package name is `ultron-saas-guard`; it is not published to npm.

```ts
import { Ultron, createMiddleware, createWebhookSink } from './dist/index.js';

const guard = new Ultron({
  projectId: 'my-product',
  secret: process.env.ULTRON_SECRET!, // Server-only, random, at least 32 characters
  mode: 'observe',
  protectedPaths: ['/app', '/api/reports'],
  requestLimit: 120,
  uniquePathLimit: 40,
  windowMs: 60_000,
}, {
  onAlert: createWebhookSink({
    url: process.env.ULTRON_WEBHOOK_URL!,
    signingSecret: process.env.ULTRON_WEBHOOK_SECRET!,
  }),
  onDiagnostic: event => console.warn(JSON.stringify(event)),
});

// Express example: mount AFTER your real session/authentication middleware.
app.use(createMiddleware(guard, {
  identify: req => {
    const session = readYourVerifiedSession(req); // Application-owned integration
    if (!session) return undefined; // Unidentified traffic passes through unmonitored
    return { identity: session.userId, trusted: session.isApprovedAutomation };
  },
  normalizePath: pathname => normalizeYourRecordRoutes(pathname),
  onError: () => console.warn('Ultron allowed a request after a metadata/guard failure'),
}));
```

`readYourVerifiedSession`, `normalizeYourRecordRoutes`, and `app` above are placeholders for your app's existing integrations. For example, normalize `/app/projects/123` and `/app/projects/456` to `/app/projects/:id` so browsing many records does not look like discovering many features. Do not normalize unrelated feature routes into one value.

For public pages, the host application must supply a validated anonymous session or another identity source. The library does not automatically mint cookies or infer identity from IP addresses. Never trust visitor-supplied identity, bot-score, or bypass headers. A proxy signal must come from a validated proxy integration. An IP alone also groups unrelated users together.

`evaluate(unknown)` returns a discriminated result with either `success: true` and a decision or `success: false` and a typed error. The traffic middleware lets requests proceed on metadata and detector failures. Invalid traffic configuration throws during startup.

## Keep customers working

1. Start in **observe**, measure real traffic, and review alerts before enabling enforcement. Do not use the demo thresholds in production.
2. Protect only explicitly chosen routes. Defaults exclude common auth, checkout, billing, webhook, and health paths. Add your actual critical route names; overriding `excludedPaths` replaces the default list.
3. Preserve approved automation using server-controlled policy. Missing JavaScript, a user-agent name, or one hidden-link visit is not grounds to block.
4. Keep normal responses unchanged. Only eligible GET requests can be throttled; writes and other methods bypass the detector. Ultron never invents results in a real workflow.
5. Monitor app latency, 429s, support reports, alert failures, and `state_evicted` diagnostics. `mode: 'off'` is the kill switch; restart/reload the configured guard to apply it.

The middleware does not modify HTML, response headers, or response bodies on allowed requests. It adds local computation and can still produce false positives when enforcement is enabled. No zero-impact claim is made.

## Alert evidence

An extraction event contains a random event ID, request correlation ID, project ID, timestamp, project-specific HMAC of the identity, signals, action, and lower-bound counts (`requestsAtLeast`, `uniquePathsAtLeast`). Counters saturate to bound memory; these are not exact totals. It contains no raw identity, request body, cookies, IP, query string, or raw pathname. Identity hashes remain pseudonymous identifiers; restrict access to them.

Alerts are emitted at most once per identity per fixed window. The guard keeps bounded per-process state (5,000 identities by default, bounded path sets and saturating request counts). Metadata remains resident until that entry is reused, evicted, or the process exits; a window reset is not a retention guarantee. State and deduplication reset on restart and are not shared across instances.

Delivery is best effort: at most 32 in-flight alerts; overflow emits `alert_dropped`. Failures emit `alert_failed`. There is no durable queue or retry worker yet. Call `await guard.flush()` on graceful shutdown. Custom callbacks must return quickly and avoid synchronous blocking work.

Configure an HTTPS endpoint you control with `ULTRON_WEBHOOK_URL` and a separate `ULTRON_WEBHOOK_SECRET`. The generic JSON payload is not a native Slack or email message. Your receiver can forward it to the owner's chosen channel.

Each POST includes `x-ultron-timestamp` (Unix seconds) and `x-ultron-signature` (`sha256=HEX`). Verify an HMAC-SHA256 over `timestamp + '.' + rawRequestBody` with the webhook secret using a constant-time comparison. Reject timestamps outside a short replay window and deduplicate the event ID. Requests time out after five seconds and do not follow redirects.

## Discover possible copies

Generate an optional fingerprint:

```powershell
$env:ULTRON_SECRET = node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))"
npm run ultron -- fingerprint --project my-product
```

Save the secret in your deployment's secret store. Keep it stable across deployments; rotating it changes the generated marker, so you must retain old markers separately if you want to search for them later.

The command prints a safe `<meta name="ultron-fingerprint" ...>` tag. You can explicitly place it in the document head. It runs no browser code, calls no tracking endpoint, and changes no workflow. It is publicly visible and removable; it is not an ownership signature or DRM.

Search GitHub with the same project ID and secret:

```powershell
# Supply GITHUB_TOKEN through your local/deployment secret store first.
npm run ultron -- scan-github --project my-product --owned-repo yourname/your-product
```

Repeat `--owned-repo` to exclude additional repositories you control. Results are labeled `possible_copy`, with repository, source URL, and `github_indexed_fingerprint` evidence. A search hit is not independent verification of file contents, malicious intent, or copyright infringement. Forks, examples, authorized mirrors, and licensed reuse need review.

If webhook environment variables are set, a scan with candidates sends one summary alert. A failed scan exits with an error rather than reporting a clean result. Scans are manual by default. `examples/github-clone-watch.yml` is an optional workflow template to run from a protected product's repository. It sends repeated candidate summaries on repeated runs; persistent finding deduplication is future work.

**Coverage limit:** GitHub search can only find markers present in code indexed for that token. A marker rendered only at runtime may never appear in a searchable repository. Private/unindexed copies, removed markers, rewritten implementations, and screenshot-based recreations are invisible to this method. This prototype does not discover or screenshot competing domains across the web.

GitHub code search requires authentication and has search-specific rate limits. This client fetches one page of at most 100 hits and reports `incomplete: true` when coverage is partial. [GitHub search documentation](https://docs.github.com/en/rest/search/search#search-code).

## Architecture and next milestones

```text
Sensitive operation -> core shield -> verified session -> permission -> fresh approval -> private handler

SaaS read -> verified identity -> local behavior window -> decision and optional owner alert

Optional public fingerprint -> GitHub search -> candidate evidence -> review/alert
```

Keep valuable algorithms, data, credentials, and authorization on your own backend. No library can hide code already shipped to a browser or prevent someone from independently rebuilding visible behavior.

1. Add Redis-backed atomic windows and a durable alert outbox before multi-instance enforcement.
2. Calibrate on authorized test traffic; compare legitimate completion, false positives, request latency, and cloning time/cost with protection on and off.
3. Add candidate-domain comparison using distinctive text, asset hashes, and screenshots, with evidence retention and manual review. Similar layouts alone are weak evidence.
4. Integrate trusted edge bot signals and owner-configured endpoint quotas, with approved automation and customer recovery paths.
5. Experiment with isolated decoy routes on an owned test app only after measuring customer impact. Do not corrupt live workflows or rely on prompt injection as the security boundary.

Cloudflare already provides crawler deception through [AI Labyrinth](https://developers.cloudflare.com/bots/additional-configurations/ai-labyrinth/). Ultron would need demonstrated additional value in authenticated workflow monitoring and useful copy evidence. JavaScript detection failures alone are not reliable block decisions; [Cloudflare documents legitimate failure cases](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/).

## Development

```sh
npm test
npm run check
npm run build
```

Tests use Node's built-in runner and mocked external services. They cover observation, enforcement, critical-flow bypasses, window reset/deduplication, the kill switch, CLI boundaries, fingerprint safety, and webhook failure isolation. No GitHub credentials or live alert receiver is required for tests.
