/**
 * C1 — authorization and scope races (in-memory engine, unmodified).
 *
 * The engine's operations are atomic synchronous calls, so the real TOCTOU
 * window is *between* calls: authority is issued as a capability snapshot, then
 * used later. These cases measure what the point-of-use path re-checks
 * (signature / expiry / revocation / PoP) versus what it does not (consent,
 * policy version, object lifecycle, the intent).
 */
import { clone, INTENT_INPUT, NOW, authorized, holderPop, directVerify, mkRecord, nowPerf } from "./harness";
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

function seqControl(caseId: string): ResultRecord {
  const a = authorized();
  const t0 = nowPerf();
  // Intended-live: evaluate against the benchmark's logical clock, never the host
  // wall clock — otherwise a run past issuance-time + TTL measures expiry, not the race.
  const d = a.engine.disclose(a.cap.token.token_id, "seq", NOW);
  return mkRecord({
    case_id: caseId, family: "C1", control: "sequential_valid", worker_count: 1,
    description: "sequential authorize→disclose of a live capability",
    interleaving: ["authorize", "disclose"],
    expected_outcome: "valid_pass",
    observed_outcome: d.verification.valid && !d.canary_present ? "valid_pass" : "false_failure",
    failure_class: "none",
    detail: `valid=${d.verification.valid}`,
    latency_ms: nowPerf() - t0,
    ids: { intent_id: a.intentId, capability_id: a.cap.token.token_id },
  });
}

function concControl(caseId: string): ResultRecord {
  const a = authorized();
  const t0 = nowPerf();
  const d1 = a.engine.disclose(a.cap.token.token_id, "conc-1", NOW);
  const d2 = a.engine.disclose(a.cap.token.token_id, "conc-2", NOW);
  const ok = d1.verification.valid && d2.verification.valid;
  return mkRecord({
    case_id: caseId, family: "C1", control: "concurrent_valid", worker_count: 2,
    description: "two legitimate uses of the same live capability (multi-use within TTL is permitted)",
    interleaving: ["disclose#1", "disclose#2"],
    expected_outcome: "valid_pass",
    observed_outcome: ok ? "valid_pass" : "false_failure",
    failure_class: "none",
    detail: `both valid=${ok}`,
    latency_ms: nowPerf() - t0,
    ids: { capability_id: a.cap.token.token_id },
  });
}

const ADVERSARIAL: Record<string, () => Adv> = {
  "C1-01-intent-scope-change-during-eval": () => ({
    expected: "held", observed: "not_realizable", failure_class: "not_applicable",
    detail: "authorize() evaluates a snapshot atomically in a single-threaded engine; there is no intra-evaluation mutation window. The related self-declared-scope issue is GAP-1 (see C1-06).",
    interleaving: ["authorize:atomic"], worker_count: 1,
  }),
  "C1-02-policy-ceiling-change-after-permit": () => {
    const a = authorized();
    a.engine.store.config.risk_threshold = 0; // a NEW authorize would now deny (risk 0.12 > 0)
    const d = a.engine.disclose(a.cap.token.token_id, "adv", NOW);
    return {
      expected: "held", observed: d.verification.valid ? "gap" : "held",
      failure_class: d.verification.valid ? "stale_permit_acceptance" : "none",
      detail: "risk threshold tightened to 0 after issuance; disclose still released — the capability/disclosure is a snapshot and is not re-evaluated against the changed request gate at point of use (bounded by TTL).",
      interleaving: ["authorize", "adversary:tighten-policy", "disclose"], worker_count: 2,
      ids: { capability_id: a.cap.token.token_id },
    };
  },
  "C1-03-consent-revoked-after-selection": () => {
    const a = authorized();
    a.engine.store.consent[0]!.granted = false; // owner withdraws consent post-issuance
    const d = a.engine.disclose(a.cap.token.token_id, "adv", NOW);
    return {
      expected: "held", observed: d.verification.valid ? "gap" : "held",
      failure_class: d.verification.valid ? "stale_permit_acceptance" : "none",
      detail: "consent withdrawn after capability issuance; disclose still released. Point-of-use verification checks signature/expiry/revocation/PoP but NOT consent — only explicit capability revocation or expiry stops a live capability.",
      interleaving: ["authorize", "adversary:withdraw-consent", "disclose"], worker_count: 2,
      ids: { capability_id: a.cap.token.token_id },
    };
  },
  "C1-04-purpose-mutation-after-issuance": () => {
    const a = authorized();
    // mutate the stored intent's purpose; the capability's purpose is immutable
    const intent = a.engine.getIntent(a.intentId) as { purpose: string } | null;
    if (intent) intent.purpose = "payroll_run";
    const d = a.engine.disclose(a.cap.token.token_id, "adv", NOW);
    return {
      expected: "held", observed: d.verification.valid ? "held" : "false_failure",
      failure_class: "none",
      detail: "the capability's purpose is immutable; mutating the intent neither grants nor revokes authority. Correctly ignored (contrast GAP-1, where the intent grants authority at issuance).",
      interleaving: ["authorize", "adversary:mutate-intent-purpose", "disclose"], worker_count: 2,
      ids: { capability_id: a.cap.token.token_id },
    };
  },
  "C1-05-use-after-policy-version-change": () => {
    const a = authorized();
    a.engine.store.config.policy_version = "policy-2026.99.0-rotated";
    const d = a.engine.disclose(a.cap.token.token_id, "adv", NOW);
    return {
      expected: "held", observed: d.verification.valid ? "gap" : "held",
      failure_class: d.verification.valid ? "policy_version_mismatch" : "none",
      detail: "policy version rotated after issuance; the capability does not bind a policy version and continued to authorize disclosure (bounded by TTL).",
      interleaving: ["authorize", "adversary:rotate-policy-version", "disclose"], worker_count: 2,
      ids: { capability_id: a.cap.token.token_id },
    };
  },
  "C1-06-two-concurrent-scope-escalations": () => {
    const esc = clone(INTENT_INPUT) as unknown as { requested_operations: string[] };
    esc.requested_operations = [...esc.requested_operations, "read:source_code"];
    const a1 = authorized(undefined, esc);
    const a2 = authorized(undefined, esc);
    const got1 = a1.engine.getAuthorization(a1.intentId)!.decision.permitted_ids.includes("mem_src_code");
    const got2 = a2.engine.getAuthorization(a2.intentId)!.decision.permitted_ids.includes("mem_src_code");
    const both = got1 && got2;
    return {
      expected: "held", observed: both ? "gap" : "held",
      failure_class: both ? "scope_escalation" : "none",
      detail: "two concurrent workers each self-declared read:source_code and both obtained mem_src_code — GAP-1 (agent-declared scope) reproduces under concurrency.",
      interleaving: ["w1:authorize", "w2:authorize"], worker_count: 2,
    };
  },
  "C1-07-use-races-revocation-commit": () => {
    const a = authorized();
    const t0 = nowPerf();
    a.engine.revoke(a.cap.token.revocation_handle);
    const d = a.engine.disclose(a.cap.token.token_id, "adv", NOW);
    return {
      expected: "held", observed: d.verification.valid ? "gap" : "held",
      failure_class: d.verification.valid ? "post_revocation_disclosure" : "none",
      detail: `revocation committed, then use attempted: ${d.verification.denied_reason ?? "released"}. Point-of-use reads the current revoked set, so post-revocation disclosure is refused; overrun ${(nowPerf() - t0).toFixed(3)}ms.`,
      interleaving: ["authorize", "revoke:commit", "disclose"], worker_count: 2,
      ids: { capability_id: a.cap.token.token_id },
    };
  },
  "C1-08-expiry-during-gateway-execution": () => {
    const a = authorized();
    const ttl = a.engine.store.config.capability_ttl_seconds;
    const expiredMs = NOW + ttl * 1000 + 1; // deliberately advanced: the ONLY C1 case that tests expiry
    const r = a.engine.callModel(a.cap.token.token_id, { agentPrompt: "compare quotes" }, expiredMs);
    return {
      expected: "held", observed: r.allowed ? "gap" : "held",
      failure_class: r.allowed ? "stale_permit_acceptance" : "none",
      detail: `capability expired mid-flight; gateway refused: ${r.denied_reason ?? "allowed"}. Expiry is checked at point of use.`,
      interleaving: ["authorize", "clock:advance-past-expiry", "callModel"], worker_count: 1,
      ids: { capability_id: a.cap.token.token_id },
    };
  },
  "C1-09-replay-two-workers": () => {
    const a = authorized();
    const d1 = a.engine.disclose(a.cap.token.token_id, "w1", NOW);
    const d2 = a.engine.disclose(a.cap.token.token_id, "w2", NOW);
    const both = d1.verification.valid && d2.verification.valid;
    return {
      expected: "held", observed: both ? "held" : "false_failure",
      failure_class: "none",
      detail: "two workers holding the bound key both used the capability — capabilities are intentionally multi-use within their TTL; there is NO one-time-use option. Recorded as a design property, not a gap.",
      interleaving: ["w1:disclose", "w2:disclose"], worker_count: 2,
      ids: { capability_id: a.cap.token.token_id },
    };
  },
  "C1-10-pop-replay-simultaneous": () => {
    const a = authorized();
    const pop = holderPop(a, "fixed-challenge");
    const v1 = directVerify(a, pop);
    const v2 = directVerify(a, pop); // same (challenge, signature) replayed
    const replayable = v1.valid && v2.valid;
    return {
      expected: "held", observed: replayable ? "gap" : "held",
      failure_class: replayable ? "pop_replay" : "none",
      detail: "a captured proof-of-possession (challenge, signature) verified more than once; the verifier does not enforce challenge freshness / single-use, so a captured proof is replayable within the TTL (candidate GAP).",
      interleaving: ["capture-pop", "verify#1", "verify#2(replay)"], worker_count: 2,
      ids: { capability_id: a.cap.token.token_id },
    };
  },
  "C1-11-stale-context-after-object-revocation": () => {
    const a = authorized();
    const obj = a.engine.store.memory.get("mem_q_apex");
    if (obj) obj.revocation_state = "revoked"; // object revoked AFTER authorization
    const d = a.engine.disclose(a.cap.token.token_id, "adv", NOW);
    const released = d.disclosure?.disclosed.some((o) => o.memory_id === "mem_q_apex") ?? false;
    return {
      expected: "held", observed: released ? "gap" : "held",
      failure_class: released ? "stale_permit_acceptance" : "none",
      detail: "an object was revoked after authorization; disclose released the cached disclosure package that still contains it — there is no per-object re-check at release time (bounded by TTL).",
      interleaving: ["authorize", "adversary:revoke-object", "disclose"], worker_count: 2,
      ids: { capability_id: a.cap.token.token_id },
    };
  },
  "C1-12-requested-tenant-changed": () => {
    const a = authorized();
    const intent = a.engine.getIntent(a.intentId) as { tenant_id: string } | null;
    if (intent) intent.tenant_id = "t_globex";
    const d = a.engine.disclose(a.cap.token.token_id, "adv", NOW);
    const stillAcme = a.cap.token.tenant_id === "t_acme" && d.verification.valid;
    return {
      expected: "held", observed: stillAcme ? "held" : "false_failure",
      failure_class: "none",
      detail: "the capability's tenant is immutable and bound into its signature; mutating the intent's tenant cannot cross tenants. Correctly unaffected.",
      interleaving: ["authorize", "adversary:mutate-intent-tenant", "disclose"], worker_count: 2,
      ids: { capability_id: a.cap.token.token_id },
    };
  },
};

export function runC1(): ResultRecord[] {
  const out: ResultRecord[] = [];
  for (const [caseId, fn] of Object.entries(ADVERSARIAL)) {
    out.push(seqControl(caseId));
    out.push(concControl(caseId));
    const t0 = nowPerf();
    const adv = fn();
    out.push(mkRecord({
      case_id: caseId, family: "C1", control: "adversarial", worker_count: adv.worker_count,
      description: caseId,
      interleaving: adv.interleaving,
      expected_outcome: adv.expected,
      observed_outcome: adv.observed,
      failure_class: adv.failure_class,
      detail: adv.detail,
      latency_ms: nowPerf() - t0,
      ids: adv.ids ?? {},
    }));
  }
  return out;
}
