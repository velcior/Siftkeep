import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { once } from 'node:events';
import { Ultron } from '../src/guard.ts';
import { createMiddleware } from '../src/middleware.ts';

test('protect mode throttles read enumeration while auth and writes still work', async t => {
  const guard = new Ultron({ projectId: 'demo', secret: 's'.repeat(32), mode: 'protect', requestLimit: 3, uniquePathLimit: 2 });
  const middleware = createMiddleware(guard, { identify: () => ({ identity: 'server-verified-account' }) });
  const server = createServer((req, res) => middleware(req, res, () => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('Original application response');
  }));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise<void>((resolve, reject) => { server.close(error => error ? reject(error) : resolve()); }));
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const origin = `http://127.0.0.1:${address.port}`;
  for (const path of ['a', 'b', 'c']) assert.equal((await fetch(`${origin}/app/${path}`)).status, 200);
  const denied = await fetch(`${origin}/app/d`);
  assert.equal(denied.status, 429);
  assert.equal(denied.headers.get('retry-after'), '60');
  assert.equal(denied.headers.get('cache-control'), 'private, no-store');
  assert.equal((await fetch(`${origin}/api/auth/session`)).status, 200);
  const write = await fetch(`${origin}/api/save`, { method: 'POST' });
  assert.equal(await write.text(), 'Original application response');
});

test('identity integration and diagnostics failures still run the application exactly once', () => {
  const guard = new Ultron({ projectId: 'demo', secret: 's'.repeat(32), mode: 'protect' });
  const middleware = createMiddleware(guard, {
    identify: () => { throw new Error('Session store unavailable'); },
    onError: () => { throw new Error('Logging unavailable'); },
  });
  let applicationCalls = 0;
  middleware({} as IncomingMessage, {} as ServerResponse, () => { applicationCalls++; });
  assert.equal(applicationCalls, 1);
});
