#!/usr/bin/env node
import { inspectRelease } from './release.ts';
import { parseArgs } from 'node:util';
import { randomUUID } from 'node:crypto';
import { createFingerprint, fingerprintTag } from './fingerprint.ts';
import { GitHubScanner } from './github.ts';
import { createWebhookSink } from './webhook.ts';

async function main(): Promise<void> {
  const { positionals, values } = parseArgs({ allowPositionals: true, options: {
    project: { type: 'string' }, help: { type: 'boolean', short: 'h' },
    'owned-repo': { type: 'string', multiple: true },
  } });
  const command = positionals[0];
  if (values.help || !command) {
    console.log('Ultron\n  audit BUILD_DIR\n  harden BUILD_DIR\n  fingerprint --project PROJECT\n  scan-github --project PROJECT --owned-repo OWNER/REPO\n\nFingerprint and scan require ULTRON_SECRET (32+ characters). Scans also require GITHUB_TOKEN.\nOptional alert delivery: ULTRON_WEBHOOK_URL + ULTRON_WEBHOOK_SECRET.');
    return;
  }
  if (command === 'audit' || command === 'harden') {
    if (positionals.length !== 2) throw new Error('Specify one public web build directory.');
    const report = await inspectRelease(positionals[1]!, command === 'harden');
    console.log(JSON.stringify(report, null, 2));
    if (command === 'audit' ? report.findings.length > 0 : !report.output) process.exitCode = 1;
    return;
  }
  if (!['fingerprint', 'scan-github'].includes(command)) throw new Error('Unknown command. Run with --help.');
  if (!values.project) throw new Error('--project is required.');
  if (!process.env.ULTRON_SECRET || process.env.ULTRON_SECRET.length < 32) throw new Error('ULTRON_SECRET must have at least 32 characters.');
  const marker = createFingerprint({ projectId: values.project, secret: process.env.ULTRON_SECRET });
  if (command === 'fingerprint') { console.log(fingerprintTag(marker)); return; }
  if (!process.env.GITHUB_TOKEN) throw new Error('GITHUB_TOKEN is required for GitHub code search.');
  const result = await new GitHubScanner({ token: process.env.GITHUB_TOKEN }).scan({ marker, ownedRepositories: values['owned-repo'] ?? [] });
  if (!result.success) throw new Error(result.error.message);
  console.log(JSON.stringify(result.data, null, 2));
  if (result.data.candidates.length && process.env.ULTRON_WEBHOOK_URL) {
    if (!process.env.ULTRON_WEBHOOK_SECRET) throw new Error('ULTRON_WEBHOOK_SECRET is required for alert delivery.');
    await createWebhookSink({ url: process.env.ULTRON_WEBHOOK_URL, signingSecret: process.env.ULTRON_WEBHOOK_SECRET })({
      id: randomUUID(), kind: 'possible_copy', projectId: values.project, ...result.data,
    });
  }
}
try { await main(); }
catch (error) {
  console.error(error instanceof Error && error.name !== 'ZodError' ? error.message : 'Invalid configuration. Check project ID and environment variables.');
  process.exitCode = 1;
}

