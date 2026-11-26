import { createHmac, randomUUID } from 'node:crypto';
import { ConfigSchema, RequestSchema } from './spec.ts';
import type { Config, Dependencies, Diagnostic, EvaluateResult, ExtractionEvent, GuardSpec } from './spec.ts';

interface WindowState { start: number; count: number; paths: Set<string>; alerted: boolean }
const matches = (pathname: string, prefix: string) => prefix === '/' || pathname === prefix || pathname.startsWith(prefix.replace(/\/$/, '') + '/');

export class Ultron implements GuardSpec {
  private readonly config: ReturnType<typeof ConfigSchema.parse>;
  private readonly dependencies: Dependencies;
  private readonly windows = new Map<string, WindowState>();
  private readonly pending = new Set<Promise<void>>();

  constructor(config: Config, dependencies: Dependencies = {}) {
    this.config = ConfigSchema.parse(config);
    this.dependencies = dependencies;
  }

  private hash(value: string): string {
    return createHmac('sha256', this.config.secret).update(this.config.projectId + ':' + value).digest('hex');
  }

  private diagnose(event: Diagnostic['event']): void {
    try { this.dependencies.onDiagnostic?.({ event }); } catch { /* Diagnostics cannot affect the app. */ }
  }

  private emit(event: ExtractionEvent): void {
    if (!this.dependencies.onAlert) return;
    if (this.pending.size >= 32) { this.diagnose('alert_dropped'); return; }
    try {
      const delivery = Promise.resolve(this.dependencies.onAlert(event)).catch(() => { this.diagnose('alert_failed'); });
      this.pending.add(delivery);
      void delivery.finally(() => { this.pending.delete(delivery); });
    } catch { this.diagnose('alert_failed'); }
  }

  async flush(): Promise<void> { await Promise.all([...this.pending]); }

  evaluate(input: unknown): EvaluateResult {
    try {
      if (this.config.mode === 'off') return { success: true, data: { action: 'allow', risk: 'low', signals: [] } };
      const parsed = RequestSchema.safeParse(input);
      if (!parsed.success) {
        this.diagnose('invalid_input');
        return { success: false, error: { code: 'INVALID_INPUT', message: 'Invalid request metadata; allow the request.', recoverable: true } };
      }
      const request = parsed.data;
      const allow: EvaluateResult = { success: true, data: { action: 'allow', risk: 'low', signals: [] } };
      if (request.trusted || request.method !== 'GET' || this.config.excludedPaths.some(p => matches(request.pathname, p)) || !this.config.protectedPaths.some(p => matches(request.pathname, p))) return allow;
      const now = (this.dependencies.now ?? Date.now)();
      const subjectHash = this.hash('identity:' + request.identity);
      let state = this.windows.get(subjectHash);
      if (!state || now - state.start >= this.config.windowMs) {
        if (!state && this.windows.size >= this.config.maxIdentities) {
          const oldest = this.windows.keys().next().value;
          if (oldest !== undefined) this.windows.delete(oldest);
          this.diagnose('state_evicted');
        }
        state = { start: now, count: 0, paths: new Set(), alerted: false };
        this.windows.delete(subjectHash);
        this.windows.set(subjectHash, state);
      }
      state.count = Math.min(state.count + 1, this.config.requestLimit + 1);
      if (state.paths.size <= this.config.uniquePathLimit) state.paths.add(this.hash('path:' + request.pathname));
      const signals: ExtractionEvent['signals'] = [];
      if (state.count > this.config.requestLimit) signals.push('request_volume');
      if (state.paths.size > this.config.uniquePathLimit) signals.push('route_enumeration');
      const risk = signals.length === 2 ? 'high' : signals.length === 1 ? 'medium' : 'low';
      const action = risk === 'high' && this.config.mode === 'protect' ? 'rate_limit' : 'allow';
      if (risk === 'high' && !state.alerted) {
        state.alerted = true;
        this.emit({ id: randomUUID(), kind: 'suspected_extraction', projectId: this.config.projectId,
          subjectHash, requestId: request.requestId, occurredAt: new Date(now).toISOString(),
          mode: this.config.mode, action, signals,
          counts: { requestsAtLeast: state.count, uniquePathsAtLeast: state.paths.size, windowMs: this.config.windowMs },
        });
      }
      return { success: true, data: { action, risk, signals,
        ...(action === 'rate_limit' ? { retryAfterSeconds: Math.max(1, Math.ceil((state.start + this.config.windowMs - now) / 1000)) } : {}),
      } };
    } catch {
      this.diagnose('guard_failed');
      return { success: false, error: { code: 'INTERNAL_ERROR', message: 'Guard unavailable; allow the request.', recoverable: true } };
    }
  }
}
