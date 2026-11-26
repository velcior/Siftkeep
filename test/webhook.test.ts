import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createWebhookSink } from '../src/webhook.ts';
import { Siftkeep } from '../src/guard.ts';

test('webhooks are signed and delivery failure cannot interrupt the application', async () => {
  const signingSecret = 'webhook-secret-'.repeat(4);
  const diagnostics: unknown[] = [];
  let deliveries = 0;
  let deliveredOptions: RequestInit | undefined;
  const sink = createWebhookSink({ url: 'https://alerts.example.test/siftkeep', signingSecret,
    fetch: async (_url: string, options: RequestInit) => {
      deliveries++;
      deliveredOptions = options;
      return new Response(null, { status: 503 });
    },
  });
  const guard = new Siftkeep({ projectId: 'demo', secret: 's'.repeat(32), requestLimit: 1, uniquePathLimit: 1 }, {
    onAlert: sink, onDiagnostic: event => { diagnostics.push(event); },
  });
  guard.evaluate({ identity: 'account', pathname: '/app/a', requestId: '1' });
  const result = guard.evaluate({ identity: 'account', pathname: '/app/b', requestId: '2' });
  assert.equal(result.success && result.data.action, 'allow');
  await guard.flush();
  assert.equal(deliveries, 1);
  assert.ok(deliveredOptions);
  const headers = new Headers(deliveredOptions.headers);
  const timestamp = headers.get('x-siftkeep-timestamp');
  const expected = createHmac('sha256', signingSecret).update(timestamp + '.' + deliveredOptions.body).digest('hex');
  assert.equal(headers.get('x-siftkeep-signature'), 'sha256=' + expected);
  assert.equal(headers.get('x-ultron-signature'), headers.get('x-siftkeep-signature'));
  assert.equal(headers.get('x-ultron-timestamp'), timestamp);
  assert.equal(deliveredOptions.redirect, 'error');
  assert.deepEqual(diagnostics, [{ event: 'alert_failed' }]);
});
