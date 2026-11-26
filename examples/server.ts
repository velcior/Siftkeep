import { createServer } from 'node:http';
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { ConfigSchema, Ultron, createMiddleware, createWebhookSink } from '../src/index.ts';

const config = ConfigSchema.parse({
  projectId: 'ultron-demo', secret: process.env.ULTRON_SECRET ?? randomBytes(32).toString('hex'),
  mode: process.env.ULTRON_MODE ?? 'observe', requestLimit: 12, uniquePathLimit: 6,
});
const sink = process.env.ULTRON_WEBHOOK_URL ? createWebhookSink({
  url: process.env.ULTRON_WEBHOOK_URL, signingSecret: process.env.ULTRON_WEBHOOK_SECRET ?? '',
}) : undefined;
const guard = new Ultron(config, {
  onAlert: async event => { console.log(JSON.stringify(event)); await sink?.(event); },
  onDiagnostic: event => { console.error(JSON.stringify(event)); },
});
const sign = (id: string) => createHmac('sha256', config.secret).update('demo-session:' + id).digest('hex');
const middleware = createMiddleware(guard, {
  identify: req => {
    const cookie = /(?:^|;\s*)ultron_demo=([a-f0-9-]{36})\.([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie ?? '');
    if (!cookie?.[1] || !cookie[2]) return undefined;
    if (!timingSafeEqual(Buffer.from(cookie[2], 'hex'), Buffer.from(sign(cookie[1]), 'hex'))) return undefined;
    return { identity: cookie[1] };
  },
  onError: () => { console.error(JSON.stringify({ event: 'middleware_failed_open' })); },
});
const server = createServer((req, res) => {
  const path = new URL(req.url ?? '/', 'http://localhost').pathname;
  if (path === '/') {
    const id = randomUUID();
    // Demo-only anonymous session. Production: use existing server-validated sessions, Secure cookies, and account quotas.
    res.setHeader('set-cookie', `ultron_demo=${id}.${sign(id)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600`);
    res.setHeader('cache-control', 'private, no-store');
    res.setHeader('content-type', 'text/html; charset=utf-8');
    res.end('<!doctype html><title>Ultron demo</title><h1>Ultron demo</h1><p>Mode: ' + config.mode + '. Requests are monitored on the server. No page rewriting.</p><a href="/app/reports/1">Open a report</a><p>Run npm run simulate in another terminal to trigger a local demonstration alert.</p>');
    return;
  }
  middleware(req, res, () => {
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'private, no-store' });
    res.end(JSON.stringify({ message: 'Original demo application response', path }));
  });
});
server.listen(4317, '127.0.0.1', () => {
  console.log(`Ultron demo: http://127.0.0.1:4317 (${config.mode})`);
});
const shutdown = () => { server.close(() => { void guard.flush(); }); };
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
