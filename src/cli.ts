#!/usr/bin/env node
import { setting } from './settings.ts';
import { inspectRelease } from './release.ts';
import { parseArgs } from 'node:util';
import { randomUUID } from 'node:crypto';
import { createFingerprint, fingerprintTag } from './fingerprint.ts';
import { GitHubScanner } from './github.ts';
import { createWebhookSink } from './webhook.ts';

async function main(): Promise<void> {
  const webhookSecret = setting('WEBHOOK_SECRET');
  const webhookUrl = setting('WEBHOOK_URL');
  const secret = setting('SECRET');
  const { positionals, values } = parseArgs({ allowPositionals: true, options: {
    project: { type: 'string' }, help: { type: 'boolean', short: 'h' },
    'owned-repo': { type: 'string', multiple: true },
  } });
  const command = positionals[0];
  if (values.help || !command) {
    console.log('Siftkeep\n  audit BUILD_DIR\n  harden BUILD_DIR\n  fingerprint --project PROJECT\n  scan-github --project PROJECT --owned-repo OWNER/REPO\n\nFingerprint and scan require SIFTKEEP_SECRET (32+ characters). Scans also require GITHUB_TOKEN.\nOptional alert delivery: SIFTKEEP_WEBHOOK_URL + SIFTKEEP_WEBHOOK_SECRET.');
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
  if (!secret || secret.length < 32) throw new Error('SIFTKEEP_SECRET must have at least 32 characters.');
  const marker = createFingerprint({ projectId: values.project, secret: secret });
  if (command === 'fingerprint') { console.log(fingerprintTag(marker)); return; }
  if (!process.env.GITHUB_TOKEN) throw new Error('GITHUB_TOKEN is required for GitHub code search.');
  const result = await new GitHubScanner({ token: process.env.GITHUB_TOKEN }).scan({ marker, ownedRepositories: values['owned-repo'] ?? [] });
  if (!result.success) throw new Error(result.error.message);
  console.log(JSON.stringify(result.data, null, 2));
  if (result.data.candidates.length && webhookUrl) {
    if (!webhookSecret) throw new Error('SIFTKEEP_WEBHOOK_SECRET is required for alert delivery.');
    await createWebhookSink({ url: webhookUrl, signingSecret: webhookSecret })({
      id: randomUUID(), kind: 'possible_copy', projectId: values.project, ...result.data,
    });
  }
}
try { await main(); }
catch (error) {
  console.error(error instanceof Error && error.name !== 'ZodError' ? error.message : 'Invalid configuration. Check project ID and environment variables.');
  process.exitCode = 1;
}

