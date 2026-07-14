/**
 * C2 — human-gate and action races (in-memory engine, unmodified).
 *
 * The action state machine is synchronous and transition-guarded, so most
 * double-execution and skip attacks are structurally refused. These cases probe
 * what is guarded (state, approver identity/tenant, illegal transitions) versus
 * what is not bound (policy version at execution, idempotency of a client id) and
 * what has no API at all (withdrawal, compensation, approval expiry).
 */
import { ContinuumEngine, canTransition } from "@continuum/core";
import { INTENT_INPUT, OWNER, GLOBEX_OWNER, AGENT, NOW, mkRecord, nowPerf } from "./harness";
import type { Outcome, FailureClass, ResultRecord } from "./records";

interface Adv {
  expected: Outcome;
  observed: Outcome;
  failure_class: FailureClass;
  detail: string;
  interleaving: string[];
  worker_count: number;
  ids?: ResultRecord["ids"];
}

/** Fresh engine with an intent and a high-consequence action resting at the gate. */
function gated(op = "publish:recommendation", cls = "external_commitment") {
  const engine = new ContinuumEngine();
  const intent = engine.submitIntent(INTENT_INPUT, NOW);
  engine.authorize(intent.intent_id, NOW);
  const action = engine.proposeAction(
    { intent_id: intent.intent_id, actor: AGENT, operation: op, action_class: cls, expected_effect: "e" },
    NOW,
  );
  return { engine, intentId: intent.intent_id, action };
}

function seqControl(caseId: string): ResultRecord {
  const g = gated();
  const t0 = nowPerf();
  const done = g.engine.approveAction(g.action.action_id, OWNER, NOW);
  return mkRecord({
    case_id: caseId, family: "C2", control: "sequential_valid", worker_count: 1,
    description: "propose high-consequence action → owner approves → executes",
    interleaving: ["propose", "approve", "execute"],
    expected_outcome: "valid_pass",
    observed_outcome: done.state === "SUCCEEDED" ? "valid_pass" : "false_failure",
    failure_class: "none", detail: `state=${done.state}`,
    latency_ms: nowPerf() - t0, ids: { action_id: g.action.action_id },
  });
}

function concControl(caseId: string): ResultRecord {
  const t0 = nowPerf();
  const engine = new ContinuumEngine();
  const intent = engine.submitIntent(INTENT_INPUT, NOW);
  engine.authorize(intent.intent_id, NOW);
  const a1 = engine.proposeAction({ intent_id: intent.intent_id, actor: AGENT, operation: "publish:a", action_class: "external_commitment", expected_effect: "e" }, NOW);
  const a2 = engine.proposeAction({ intent_id: intent.intent_id, actor: AGENT, operation: "publish:b", action_class: "external_commitment", expected_effect: "e" }, NOW);
  const r1 = engine.approveAction(a1.action_id, OWNER, NOW);
  const r2 = engine.approveAction(a2.action_id, OWNER, NOW);
  const ok = r1.state === "SUCCEEDED" && r2.state === "SUCCEEDED";
  return mkRecord({
    case_id: caseId, family: "C2", control: "concurrent_valid", worker_count: 2,
    description: "two distinct actions approved by the owner both execute (permitted concurrency)",
    interleaving: ["approve#a", "approve#b"],
    expected_outcome: "valid_pass",
    observed_outcome: ok ? "valid_pass" : "false_failure",
    failure_class: "none", detail: `a=${r1.state} b=${r2.state}`,
    latency_ms: nowPerf() - t0, ids: {},
  });
}

const ADVERSARIAL: Record<string, () => Adv> = {
  "C2-01-approval-races-withdrawal": () => {
    return {
      expected: "held", observed: "not_realizable", failure_class: "not_applicable",
      detail: "the state machine permits POLICY_APPROVED→REVOKED, but the engine exposes NO method to withdraw/cancel a pending approval. The withdrawal race is unreachable via the public API — itself a finding (no cancellation path).",
      interleaving: ["propose", "(no withdraw API)"], worker_count: 1,
    };
  },
  "C2-02-approval-races-capability-revocation": () => {
    const g = gated();
    // revoke a data capability (unrelated to the action), then approve
    const auth = g.engine.getAuthorization(g.intentId);
    if (auth?.capability) g.engine.revoke(auth.capability.token.revocation_handle, NOW);
    const done = g.engine.approveAction(g.action.action_id, OWNER, NOW);
    return {
      expected: "held", observed: done.state === "SUCCEEDED" ? "held" : "false_failure",
      failure_class: "none",
      detail: "the action gate is independent of data capabilities; revoking a capability does not block a separately-authorized human approval. Documented design property — a deployment expecting capability revocation to cascade to pending actions would not get it.",
      interleaving: ["propose", "revoke-capability", "approve"], worker_count: 2,
      ids: { action_id: g.action.action_id },
    };
  },
  "C2-03-duplicate-approvals-concurrent": () => {
    const g = gated();
    const first = g.engine.approveAction(g.action.action_id, OWNER, NOW);
    let secondBlocked = false; let reason = "";
    try { g.engine.approveAction(g.action.action_id, OWNER, NOW); }
    catch (e) { secondBlocked = true; reason = (e as Error).message; }
    const held = first.state === "SUCCEEDED" && secondBlocked;
    return {
      expected: "held", observed: held ? "held" : "gap",
      failure_class: held ? "none" : "duplicate_execution",
      detail: `first→${first.state}; second approval refused (${reason || "n/a"}). The action is terminal after execution, so no double-execution.`,
      interleaving: ["approve#1", "approve#2"], worker_count: 2, ids: { action_id: g.action.action_id },
    };
  },
  "C2-04-approval-expires-during-execution": () => ({
    expected: "held", observed: "not_realizable", failure_class: "not_applicable",
    detail: "approvals carry no TTL, and approve→execute is atomic within approveAction; there is no window for an approval to expire mid-execution.",
    interleaving: ["approve→execute:atomic"], worker_count: 1,
  }),
  "C2-05-two-workers-consume-same-action": () => {
    const g = gated();
    const r1 = g.engine.approveAction(g.action.action_id, OWNER, NOW);
    let secondBlocked = false;
    try { g.engine.approveAction(g.action.action_id, OWNER, NOW); } catch { secondBlocked = true; }
    const held = r1.state === "SUCCEEDED" && secondBlocked;
    return {
      expected: "held", observed: held ? "held" : "gap",
      failure_class: held ? "none" : "duplicate_execution",
      detail: "two workers consuming the same approved action: the transition guard makes the second consume illegal once the action is terminal.",
      interleaving: ["w1:approve", "w2:approve"], worker_count: 2, ids: { action_id: g.action.action_id },
    };
  },
  "C2-06-approve-v1-execute-v2": () => {
    const g = gated();
    g.engine.store.config.policy_version = "policy-2026.99.0-rotated";
    const done = g.engine.approveAction(g.action.action_id, OWNER, NOW);
    return {
      expected: "held", observed: done.state === "SUCCEEDED" ? "gap" : "held",
      failure_class: done.state === "SUCCEEDED" ? "policy_version_mismatch" : "none",
      detail: "policy version rotated between proposal and approval; the action carries no policy-version binding and executed without re-validation against the new policy (staleness; bounded to the gate window).",
      interleaving: ["propose", "rotate-policy", "approve→execute"], worker_count: 2, ids: { action_id: g.action.action_id },
    };
  },
  "C2-07-valid-vs-foreign-tenant-approval": () => {
    const g = gated();
    // foreign-tenant human tries first
    g.engine.approveAction(g.action.action_id, GLOBEX_OWNER, NOW);
    const afterForeign = g.engine.getAction(g.action.action_id)!.state;
    const done = g.engine.approveAction(g.action.action_id, OWNER, NOW);
    const held = afterForeign === "POLICY_APPROVED" && done.state === "SUCCEEDED";
    return {
      expected: "held", observed: held ? "held" : "gap",
      failure_class: held ? "none" : "human_gate_bypass",
      detail: `foreign-tenant approval left state=${afterForeign} (refused); the owner then executed. The Stage A approver guard holds under the race.`,
      interleaving: ["foreign:approve(refused)", "owner:approve"], worker_count: 2, ids: { action_id: g.action.action_id },
    };
  },
  "C2-08-approval-races-explicit-denial": () => {
    // a prohibited action is DENIED at proposal; then someone tries to approve it
    const g = gated("place_order", "financial_execution");
    const denied = g.action.state; // DENIED
    let blocked = false; let reason = "";
    try { g.engine.approveAction(g.action.action_id, OWNER, NOW); }
    catch (e) { blocked = true; reason = (e as Error).message; }
    const held = denied === "DENIED" && blocked;
    return {
      expected: "held", observed: held ? "held" : "gap",
      failure_class: held ? "none" : "invalid_approval",
      detail: `prohibited action rested at ${denied}; approving it was refused (${reason || "n/a"}). A denial cannot be raced into execution.`,
      interleaving: ["propose→DENIED", "approve(refused)"], worker_count: 2, ids: { action_id: g.action.action_id },
    };
  },
  "C2-09-execution-races-quarantine": () => ({
    expected: "held", observed: "not_realizable", failure_class: "not_applicable",
    detail: "action execution is synchronous inside approveAction; there is no window between tool execution and quarantine to race (output quarantine exists only on the separate model-gateway path).",
    interleaving: ["execute:atomic"], worker_count: 1,
  }),
  "C2-10-compensation-races-execution": () => ({
    expected: "held", observed: "not_realizable", failure_class: "not_applicable",
    detail: "the state machine defines FAILED→COMPENSATED, but the engine exposes no method to drive execution failure or compensation; the race is unreachable via the public API.",
    interleaving: ["(no compensation API)"], worker_count: 1,
  }),
  "C2-11-idempotency-key-reused": () => {
    const engine = new ContinuumEngine();
    const intent = engine.submitIntent(INTENT_INPUT, NOW);
    engine.authorize(intent.intent_id, NOW);
    const first = engine.proposeAction({ intent_id: intent.intent_id, actor: AGENT, action_id: "act_dup_key", operation: "publish:x", action_class: "external_commitment", expected_effect: "e" }, NOW);
    const second = engine.proposeAction({ intent_id: intent.intent_id, actor: AGENT, action_id: "act_dup_key", operation: "publish:y", action_class: "external_commitment", expected_effect: "e" }, NOW);
    const stored = engine.getAction("act_dup_key")!;
    const overwritten = stored.operation === "publish:y" && engine.listActions().filter((x) => x.action_id === "act_dup_key").length === 1;
    return {
      expected: "held", observed: overwritten ? "gap" : "held",
      failure_class: overwritten ? "idempotency_reuse" : "none",
      detail: "a client-supplied action_id reused across two proposals silently OVERWROTE the first record rather than being rejected or deduplicated — there is no idempotency-key enforcement.",
      interleaving: ["propose(id=dup,x)", "propose(id=dup,y)"], worker_count: 2, ids: { action_id: "act_dup_key" },
    };
  },
  "C2-12-state-transition-skips": () => {
    const skips: Array<[string, string]> = [
      ["PROPOSED", "SUCCEEDED"], ["PROPOSED", "EXECUTING"], ["POLICY_APPROVED", "SUCCEEDED"], ["VALIDATED", "EXECUTING"],
    ];
    const allRejected = skips.every(([f, t]) => !canTransition(f as never, t as never));
    return {
      expected: "held", observed: allRejected ? "held" : "gap",
      failure_class: allRejected ? "none" : "invalid_state_transition",
      detail: `illegal skips ${JSON.stringify(skips)} all rejected=${allRejected} by canTransition — mandatory states cannot be skipped.`,
      interleaving: ["force-illegal-transition(rejected)"], worker_count: 1,
    };
  },
};

export function runC2(): ResultRecord[] {
  const out: ResultRecord[] = [];
  for (const [caseId, fn] of Object.entries(ADVERSARIAL)) {
    out.push(seqControl(caseId));
    out.push(concControl(caseId));
    const t0 = nowPerf();
    const adv = fn();
    out.push(mkRecord({
      case_id: caseId, family: "C2", control: "adversarial", worker_count: adv.worker_count,
      description: caseId, interleaving: adv.interleaving,
      expected_outcome: adv.expected, observed_outcome: adv.observed,
      failure_class: adv.failure_class, detail: adv.detail,
      latency_ms: nowPerf() - t0, ids: adv.ids ?? {},
    }));
  }
  return out;
}
