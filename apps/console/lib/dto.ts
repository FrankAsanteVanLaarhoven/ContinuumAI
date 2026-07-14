/**
 * Console state DTO. Pure types only (type-only imports from @continuum/core
 * are erased at build), so this module is safe to reference from client
 * components without pulling server-only crypto into the browser bundle.
 */
import type {
  ActionRecord,
  AuthorizationDecision,
  Classification,
  DisclosurePackage,
  EvidenceEnvelope,
  MemoryObject,
  MetricsSnapshot,
  ModelCallResult,
  Principal,
  SliceAssertion,
  SliceStep,
  Tenant,
} from "@continuum/core";

export interface CapabilityView {
  token_id: string;
  actor: string;
  subject: string;
  purpose: string;
  audience: string;
  environment: string;
  operations: string[];
  resources: string[];
  data_classification: Classification;
  maximum_disclosure: number;
  issued_at: string;
  expires_at: string;
  revocation_handle: string;
  holder_fingerprint: string;
}

export interface GateRow {
  name: string;
  value: string;
  target: string;
  pass: boolean;
}

export interface ConsoleState {
  generated_at: string;
  passed: boolean;
  intent_id: string;
  purpose: string;
  platform_fingerprint: string;
  tenants: Tenant[];
  principals: Principal[];
  steps: SliceStep[];
  assertions: SliceAssertion[];
  decision: AuthorizationDecision;
  disclosure: DisclosurePackage;
  capability: CapabilityView | null;
  model_calls: ModelCallResult[];
  actions: ActionRecord[];
  memory: Array<Omit<MemoryObject, "content">>;
  evidence: { entries: EvidenceEnvelope[]; valid: boolean; detail: string };
  metrics: MetricsSnapshot;
  gates: GateRow[];
}
