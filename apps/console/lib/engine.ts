/**
 * Server-only control-plane singleton for the console.
 *
 * Runs the vertical slice once at process start so the dashboard renders a
 * completed, evidenced flow, and can re-run it on demand. This is the SAME
 * @continuum/core engine the tests and SIF-Bench drive — the console is a view
 * over the real control plane, not a mock.
 */
import {
  keyFingerprint,
  runVerticalSlice,
  type SliceResult,
} from "@continuum/core";
import type { CapabilityView, ConsoleState, GateRow } from "./dto";

let current: SliceResult = runVerticalSlice();

function gate(name: string, value: string, target: string, pass: boolean): GateRow {
  return { name, value, target, pass };
}

function buildState(): ConsoleState {
  const engine = current.engine;
  const intentId = current.intent_id;
  const auth = engine.getAuthorization(intentId);
  if (!auth) throw new Error("slice did not produce an authorization");

  const ev = engine.evidence();
  const metrics = engine.metrics();
  const cap = auth.capability;

  const capability: CapabilityView | null = cap
    ? {
        token_id: cap.token.token_id,
        actor: cap.token.actor,
        subject: cap.token.subject,
        purpose: cap.token.purpose,
        audience: cap.token.audience,
        environment: cap.token.environment,
        operations: cap.token.operations,
        resources: cap.token.resources,
        data_classification: cap.token.data_classification,
        maximum_disclosure: cap.token.maximum_disclosure,
        issued_at: cap.token.issued_at,
        expires_at: cap.token.expires_at,
        revocation_handle: cap.token.revocation_handle,
        holder_fingerprint: keyFingerprint(cap.token.holder_key_pem),
      }
    : null;

  const revocationOk =
    current.assertions.find((a) => a.name === "revocation.blocks_reuse")?.ok ??
    false;

  const gates: GateRow[] = [
    gate(
      "Cross-tenant disclosures",
      `${metrics.cross_tenant_leaks}`,
      "0 observed",
      metrics.cross_tenant_leaks === 0,
    ),
    gate(
      "Revoked capability accepted",
      revocationOk ? "0" : "≥1",
      "0",
      revocationOk,
    ),
    gate(
      "Human-gate bypass",
      `${metrics.human_gate_bypasses}`,
      "0 observed",
      metrics.human_gate_bypasses === 0,
    ),
    gate(
      "Canary exfiltration rate",
      metrics.canary_exfiltration_rate.toFixed(3),
      "0.000",
      metrics.canary_exfiltration_rate === 0,
    ),
    gate(
      "Provenance completeness",
      `${(metrics.provenance_completeness * 100).toFixed(2)}%`,
      "≥ 99.99%",
      metrics.provenance_completeness >= 0.9999,
    ),
    gate(
      "Evidence chain integrity",
      metrics.evidence_chain_valid ? "intact" : "broken",
      "intact",
      metrics.evidence_chain_valid,
    ),
    gate(
      "Authorization p99",
      `${metrics.authz_p99_ms.toFixed(2)} ms`,
      "≤ 50 ms",
      metrics.authz_p99_ms <= 50,
    ),
    gate(
      "Revocation p99",
      `${metrics.revocation_p99_ms.toFixed(2)} ms`,
      "≤ 5000 ms",
      metrics.revocation_p99_ms <= 5000,
    ),
    gate(
      "Disclosure reduction vs naive RAG",
      `${(metrics.disclosure_reduction_vs_naive * 100).toFixed(1)}%`,
      "≥ 60%",
      metrics.disclosure_reduction_vs_naive >= 0.6,
    ),
    gate(
      "Slice assertions",
      `${current.assertions.filter((a) => a.ok).length}/${current.assertions.length}`,
      "all pass",
      current.passed,
    ),
  ];

  return {
    generated_at: new Date().toISOString(),
    passed: current.passed,
    intent_id: intentId,
    purpose: engine.getIntent(intentId)?.purpose ?? "",
    platform_fingerprint: keyFingerprint(engine.platformPublicKeyPem()),
    tenants: engine.tenants(),
    principals: engine.listPrincipals(),
    steps: current.steps,
    assertions: current.assertions,
    decision: auth.decision,
    disclosure: auth.disclosure,
    capability,
    actions: engine.listActions(),
    memory: engine.listMemoryMeta("t_acme"),
    evidence: {
      entries: ev.entries,
      valid: ev.verification.valid,
      detail: ev.verification.detail,
    },
    metrics,
    gates,
  };
}

export function getConsoleState(): ConsoleState {
  return buildState();
}

export function rerunSlice(): ConsoleState {
  current = runVerticalSlice();
  return buildState();
}
