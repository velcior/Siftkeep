import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Siftkeep } from '../src/guard.ts';

const config = { projectId: 'demo', secret: 's'.repeat(32), requestLimit: 3, uniquePathLimit: 2 };
const input = (pathname = '/app/reports') => ({ identity: 'customer-123', pathname, requestId: 'req-1' });

test('observe mode reports combined extraction signals but never changes the response', () => {
  const alerts: any[] = [];
  const guard = new Siftkeep(config, { onAlert: (event: unknown) => { alerts.push(event); } });
  guard.evaluate(input('/app/a'));
  guard.evaluate(input('/app/b'));
  guard.evaluate(input('/app/c'));
  const result = guard.evaluate(input('/app/d'));
  assert.equal(result.success, true);
  assert.equal(result.data.action, 'allow');
  assert.equal(result.data.risk, 'high');
  assert.deepEqual(result.data.signals, ['request_volume', 'route_enumeration']);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].kind, 'suspected_extraction');
  assert.ok(!JSON.stringify(alerts).includes('customer-123'));
  assert.ok(!JSON.stringify(alerts).includes('/app/'));
});

test('off mode is a kill switch that emits nothing and never throttles', () => {
  const alerts: unknown[] = [];
  const guard = new Siftkeep({ ...config, mode: 'off', requestLimit: 1, uniquePathLimit: 1 }, { onAlert: event => { alerts.push(event); } });
  for (let i = 0; i < 10; i++) {
    const result = guard.evaluate(input('/app/' + i));
    assert.equal(result.success && result.data.action, 'allow');
    assert.equal(result.success && result.data.risk, 'low');
  }
  assert.equal(alerts.length, 0);
});

test('one signal never enforces; alerts deduplicate and expire with the window', () => {
  let now = 10_000;
  const alerts: unknown[] = [];
  const guard = new Siftkeep({ ...config, mode: 'protect', requestLimit: 1, uniquePathLimit: 1, windowMs: 1000 }, {
    now: () => now, onAlert: event => { alerts.push(event); },
  });
  guard.evaluate(input('/app/a'));
  const repeated = guard.evaluate(input('/app/a'));
  assert.ok(repeated.success);
  assert.equal(repeated.data.risk, 'medium');
  assert.equal(repeated.data.action, 'allow');
  assert.equal(guard.evaluate(input('/app/b')).success, true);
  guard.evaluate(input('/app/c'));
  assert.equal(alerts.length, 1);
  now += 1000;
  const reset = guard.evaluate(input('/app/a'));
  assert.ok(reset.success);
  assert.equal(reset.data.risk, 'low');
  guard.evaluate(input('/app/b'));
  assert.equal(alerts.length, 2);
});
