import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFingerprint, fingerprintTag } from '../src/fingerprint.ts';

test('fingerprints are stable per project, disclose no secret, and add no browser code', () => {
  const config = { projectId: 'demo', secret: 'private-secret-'.repeat(4) };
  const marker = createFingerprint(config);
  assert.match(marker, /^ultron_[a-f0-9]{32}$/);
  assert.equal(createFingerprint(config), marker);
  assert.notEqual(createFingerprint({ ...config, projectId: 'other' }), marker);
  assert.equal(fingerprintTag(marker), `<meta name="ultron-fingerprint" content="${marker}">`);
  assert.throws(() => fingerprintTag('"><script>bad</script>'));
  assert.ok(!marker.includes(config.secret));
});
