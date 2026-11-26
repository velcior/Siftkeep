import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { inspectRelease } from '../src/release.ts';

test('release staging omits external maps, preserves assets, and blocks embedded source', async t => {
  const base = await mkdtemp(join(tmpdir(), 'siftkeep-test-'));
  t.after(() => rm(base, { recursive: true, force: true }));
  const root = join(base, 'web');
  await mkdir(root);
  await writeFile(join(root, 'app.js'), 'export default 42');
  await writeFile(join(root, 'app.js.map'), '{}');
  const audit = await inspectRelease(root, false);
  assert.deepEqual(audit.findings, [{ file: 'app.js.map', reason: 'external source map' }]);
  const staged = await inspectRelease(root, true);
  assert.deepEqual(await readdir(staged.output!), ['app.js']);
  assert.equal(await readFile(join(staged.output!, 'app.js'), 'utf8'), 'export default 42');
  assert.equal(await readFile(join(root, 'app.js.map'), 'utf8'), '{}');
  await writeFile(join(root, 'app.js'), '//# sourceMappingURL=data:application/json;base64,e30=');
  assert.equal((await inspectRelease(root, true)).output, undefined);
});
