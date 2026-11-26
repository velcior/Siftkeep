import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { createCoreShield, type CoreShieldOptions } from '../src/index.ts';

const principal = { kind: 'interactive', identity: 'account-1', sessionId: 'session-1' } as const;
const allowed: CoreShieldOptions = {
  resolvePrincipal: async () => principal,
  authorize: async () => true,
  consumeUserVerification: async () => true,
};

async function startCore(t: TestContext, options: CoreShieldOptions) {
  const shield = createCoreShield(options);
  const server = createServer((req, res) => {
    void shield(req, res, () => res.end('private operation result')).catch(() => {
      res.writeHead(500).end();
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise<void>((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
  }));
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  return `http://127.0.0.1:${address.port}/api/core`;
}

test('core denies a caller without a verified principal despite browser and identity headers', async t => {
  const core = await startCore(t, { ...allowed, resolvePrincipal: () => undefined });
  const response = await fetch(core, { method: 'POST', headers: {
    'user-agent': 'Mozilla/5.0', 'x-user-id': 'account-1', 'x-client-type': 'interactive',
  } });
  assert.equal(response.status, 403);
  assert.equal(response.headers.get('cache-control'), 'private, no-store');
  assert.equal((await response.json()).error.code, 'CORE_ACCESS_DENIED');
});

test('core denies a verified automation credential before checking operation permissions', async t => {
  const authorize = t.mock.fn(() => true);
  const core = await startCore(t, {
    ...allowed, authorize,
    resolvePrincipal: () => ({ kind: 'automation', identity: 'agent-skill' }),
  });
  const response = await fetch(core);
  assert.equal(response.status, 403);
  assert.equal(authorize.mock.callCount(), 0);
  await response.body?.cancel();
});

test('core requires a usable identity and session ID for interactive credentials', async t => {
  for (const field of ['identity', 'sessionId'] as const) {
    const core = await startCore(t, { ...allowed, resolvePrincipal: () => ({ ...principal, [field]: '' }) });
    const response = await fetch(core);
    assert.equal(response.status, 403, field);
    await response.body?.cancel();
  }
});

test('core checks permission for the requested operation before consuming verification', async t => {
  const authorize = t.mock.fn<CoreShieldOptions['authorize']>(() => false);
  const consumeUserVerification = t.mock.fn(() => true);
  const core = await startCore(t, { ...allowed, authorize, consumeUserVerification });
  const response = await fetch(core, { method: 'POST' });
  assert.equal(response.status, 403);
  assert.equal(authorize.mock.calls[0]?.arguments[0].method, 'POST');
  assert.equal(authorize.mock.calls[0]?.arguments[1], principal);
  assert.equal(consumeUserVerification.mock.callCount(), 0);
  await response.body?.cancel();
});

test('an authorized session reaches the core only with fresh verification accepted by the app', async t => {
  let pendingVerification = false;
  const core = await startCore(t, {
    ...allowed,
    consumeUserVerification: async (_request, session) => {
      assert.equal(session.sessionId, principal.sessionId);
      const verified = pendingVerification;
      pendingVerification = false;
      return verified;
    },
  });
  const request = () => fetch(core, { method: 'POST', headers: { 'x-user-verified': 'true' } });
  assert.equal((await (await request()).json()).error.code, 'CORE_ACCESS_DENIED');
  pendingVerification = true;
  const permitted = await request();
  assert.equal(permitted.status, 200);
  assert.equal(await permitted.text(), 'private operation result');
  assert.equal((await (await request()).json()).error.code, 'CORE_ACCESS_DENIED');
});

test('the core stays closed when any verification dependency fails', async t => {
  for (const check of ['resolvePrincipal', 'authorize', 'consumeUserVerification'] as const) {
    const core = await startCore(t, {
      ...allowed, [check]: async () => { throw new Error('Private provider details'); },
    });
    const response = await fetch(core);
    assert.equal(response.status, 503, check);
    assert.deepEqual(await response.json(), {
      error: { code: 'CORE_VERIFICATION_UNAVAILABLE', message: 'Core verification is unavailable.' },
    });
  }
});
