/** Read canonical settings first, with support for pre-rename deployments. */
export function setting(name: string): string | undefined {
  return process.env['SIFTKEEP_' + name] ?? process.env['ULTRON_' + name];
}
