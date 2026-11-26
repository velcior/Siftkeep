import { copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm } from 'node:fs/promises';
import { basename, dirname, join, parse } from 'node:path';

type Finding = { file: string; reason: string };

export async function inspectRelease(directory: string, stage: boolean) {
  if (!(await lstat(directory)).isDirectory()) throw new Error('Choose a regular build directory.');
  const root = await realpath(directory);
  if (root === parse(root).root) throw new Error('Choose a build directory below the filesystem root.');
  const findings: Finding[] = [];
  const files: string[] = [];
  const directories: string[] = [];
  async function visit(relative: string) {
    for (const entry of await readdir(join(root, relative), { withFileTypes: true })) {
      const file = join(relative, entry.name);
      if (entry.isSymbolicLink() || (!entry.isFile() && !entry.isDirectory())) {
        findings.push({ file, reason: 'unsupported file type' });
      } else if (/^(?:\.git|node_modules|\.env(?:\..*)?)$/i.test(entry.name)) {
        findings.push({ file, reason: 'private build input' });
      } else if (entry.isDirectory()) {
        directories.push(file);
        await visit(file);
      } else if (/\.map$/i.test(file)) {
        findings.push({ file, reason: 'external source map' });
      } else {
        files.push(file);
        if (/\.(?:[cm]?tsx?|jsx|vue|svelte)$/i.test(file)) {
          findings.push({ file, reason: 'development source' });
        } else if (/\.(?:[cm]?js|css|html?|svg)$/i.test(file)) {
          const code = await readFile(join(root, file), 'utf8');
          if (/sourceMappingURL\s*=\s*data:/i.test(code)) findings.push({ file, reason: 'inline source map' });
        }
      }
    }
  }
  await visit('');
  let output: string | undefined;
  if (stage && findings.every(issue => issue.reason === 'external source map')) {
    output = await mkdtemp(join(dirname(root), basename(root) + '-siftkeep-'));
    try {
      for (const dir of directories) await mkdir(join(output, dir), { recursive: true });
      for (const file of files) await copyFile(join(root, file), join(output, file));
    } catch (error) {
      await rm(output, { recursive: true, force: true });
      throw error;
    }
  }
  return { root, findings, output };
}
