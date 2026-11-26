import { z } from 'zod';

const Path = z.string().min(1).max(2048).startsWith('/').refine(p => !/[?#]/.test(p), 'Supply a pathname without query or fragment');
export const ConfigSchema = z.object({
  projectId: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/),
  secret: z.string().min(32).max(512),
  mode: z.enum(['off', 'observe', 'protect']).default('observe'),
  requestLimit: z.number().int().min(1).max(100_000).default(120),
  uniquePathLimit: z.number().int().min(1).max(10_000).default(40),
  windowMs: z.number().int().min(1000).max(3_600_000).default(60_000),
  maxIdentities: z.number().int().min(1).max(100_000).default(5000),
  protectedPaths: z.array(Path).min(1).max(100).default(['/app', '/api']),
  excludedPaths: z.array(Path).max(100).default([
    '/login', '/logout', '/auth', '/api/auth', '/checkout', '/api/checkout',
    '/billing', '/api/billing', '/webhooks', '/api/webhooks', '/health',
  ]),
});
export type Config = z.input<typeof ConfigSchema>;
export const RequestSchema = z.object({
  identity: z.string().min(1).max(512),
  pathname: Path,
  requestId: z.string().min(1).max(128),
  method: z.string().max(16).default('GET'),
  trusted: z.boolean().default(false),
});
export const DecisionSchema = z.object({
  action: z.enum(['allow', 'rate_limit']),
  risk: z.enum(['low', 'medium', 'high']),
  signals: z.array(z.enum(['request_volume', 'route_enumeration'])),
  retryAfterSeconds: z.number().int().positive().optional(),
});
export type Decision = z.infer<typeof DecisionSchema>;
export const ExtractionEventSchema = z.object({
  id: z.string(), kind: z.literal('suspected_extraction'), projectId: z.string(),
  subjectHash: z.string(), requestId: z.string(), occurredAt: z.string(),
  mode: z.enum(['observe', 'protect']), action: DecisionSchema.shape.action,
  signals: DecisionSchema.shape.signals,
  counts: z.object({ requestsAtLeast: z.number(), uniquePathsAtLeast: z.number(), windowMs: z.number() }),
});
export type ExtractionEvent = z.infer<typeof ExtractionEventSchema>;
export type EvaluateResult = { success: true; data: Decision } | {
  success: false; error: { code: 'INVALID_INPUT' | 'INTERNAL_ERROR'; message: string; recoverable: true };
};
export interface GuardSpec { evaluate(input: unknown): EvaluateResult }
export interface Diagnostic {
  event: 'alert_failed' | 'alert_dropped' | 'guard_failed' | 'invalid_input' | 'state_evicted';
}
export interface Dependencies {
  now?: () => number;
  onAlert?: (event: ExtractionEvent) => void | Promise<void>;
  onDiagnostic?: (event: Diagnostic) => void;
}
