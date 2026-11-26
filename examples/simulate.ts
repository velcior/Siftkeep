const origin = 'http://127.0.0.1:4317';
try {
  const initial = await fetch(origin);
  const cookie = initial.headers.get('set-cookie')?.split(';')[0];
  if (!cookie) throw new Error('Demo session was not issued.');
  await initial.body?.cancel();
  const statuses: Record<string, number> = {};
  for (let i = 0; i < 16; i++) {
    const response = await fetch(`${origin}/app/reports/${i}`, { headers: { cookie } });
    statuses[response.status] = (statuses[response.status] ?? 0) + 1;
    await response.body?.cancel();
  }
  console.log(JSON.stringify({ requests: 16, statuses, next: 'Check the demo server terminal for one suspected_extraction alert.' }, null, 2));
} catch {
  console.error('Demo unavailable. Start npm run demo first.');
  process.exitCode = 1;
}
