import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('CLI emits a copy fingerprint without exposing the server secret', () => {
  const secret = 'a-secret-for-cli-'.repeat(4);
  const child = spawnSync(process.execPath, [fileURLToPath(new URL('../src/cli.ts', import.meta.url)), 'fingerprint', '--project', 'demo'], {
    env: { ...process.env, ULTRON_SECRET: secret }, encoding: 'utf8',
  });
  assert.equal(child.status, 0, child.stderr);
  assert.match(child.stdout, /^<meta name="ultron-fingerprint" content="ultron_[a-f0-9]{32}">\r?\n$/);
  assert.ok(!child.stdout.includes(secret));
});

test('scan CLI requires a GitHub token rather than reporting a failed scan as no copies found', () => {
  const child = spawnSync(process.execPath, [fileURLToPath(new URL('../src/cli.ts', import.meta.url)), 'scan-github', '--project', 'demo', '--owned-repo', 'creator/product'], {
    env: { ...process.env, ULTRON_SECRET: 's'.repeat(32), GITHUB_TOKEN: '' }, encoding: 'utf8',
  });
  assert.equal(child.status, 1);
  assert.match(child.stderr, /GITHUB_TOKEN is required/);
  assert.equal(child.stdout, '');
});
