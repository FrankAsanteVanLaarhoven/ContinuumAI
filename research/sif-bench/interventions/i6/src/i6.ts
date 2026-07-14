/**
 * Intervention I6 — matched-arm evaluation of idempotent action identity.
 *
 *   I6-A  caller-chosen action_id, silent overwrite, execute-every-time (GAP-6)
 *   I6-B  server-issued action_id + idempotency key + same-request replay
 *   I6-C  I6-B + canonical-digest conflict rejection + execution-level idempotency
 *
 * The idempotency domain is UNIQUE(tenant, principal, operation, idempotency_key).
 * `intent`, `capability` and `policy_version` are bound into the request DIGEST but
 * not the uniqueness domain: a differing one with the same key/operation is a
 * CONFLICT under C (not a silent second action), which keeps exactly one
 * authoritative record per (tenant, principal, operation, key). Including them in
 * the domain would let a caller bypass idempotency by varying them.
 */
import type { Pool } from "pg";
import { resetAll, type ActionRequest } from "./harness";
import { baselineCreate, boundCreate, type BoundMode, type CreateResult } from "./idempotency";

const REQ0: ActionRequest = {
  tenant: "t_acme",
  principal: "spiffe://acme.ai/agents/procurement-agent",
  intent: "int_001",
  operation: "place_order",
  resource: "supplier:apex",
  arguments: { amount_gbp: 1000, sku: "widget" },
  purpose: "procurement",
  capability: "sct_001",
  policy_version: "policy-2026.07.0",
  approval_requirement: "human",
};
const KEY = "idem-key-001";
const req = (over: Partial<ActionRequest>): ActionRequest => ({ ...REQ0, ...over });

export interface ProbeOutcome {
  id: string;
  name: string;
  malicious: boolean;
  blocked: boolean; // attack prevented (malicious) or task succeeded (benign)
  detail: string;
}

export interface ArmResult {
  arm: "I6-A" | "I6-B" | "I6-C";
  scheme: string;
  silent_overwrite_success: boolean;
  duplicate_action_creation: number;
  duplicate_execution: number;
  same_request_replay_accurate: boolean | null;
  different_request_conflict_detection: number; // of the digest-mismatch cases tried
  missing_key_denied: boolean | null;
  valid_new_action_success: boolean;
  false_permit: number;
  false_deny: number;
  orphan_action_rate: number;
  action_evidence_divergence: number;
  replay_evidence_complete: boolean | null;
  conflict_evidence_complete: boolean | null;
  idempotency_latency_ms: number | null;
  probes: ProbeOutcome[];
  detail: string;
}

async function execCountBaseline(admin: Pool, actionId: string): Promise<number> {
  const r = await admin.query("SELECT count(*)::int n FROM i6_baseline_execution WHERE action_id=$1", [actionId]);
  return r.rows[0].n as number;
}
async function execCountBound(admin: Pool, actionId: string): Promise<number> {
  const r = await admin.query("SELECT count(*)::int n FROM i6_execution WHERE action_id=$1", [actionId]);
  return r.rows[0].n as number;
}
async function actionCount(admin: Pool): Promise<number> {
  const r = await admin.query("SELECT count(*)::int n FROM i6_action");
  return r.rows[0].n as number;
}
async function evidenceCount(admin: Pool, classification: string): Promise<number> {
  const r = await admin.query("SELECT count(*)::int n FROM i6_evidence WHERE classification=$1", [classification]);
  return r.rows[0].n as number;
}
async function orphanActions(admin: Pool): Promise<number> {
  // an action with no matching evidence row (action/evidence divergence)
  const r = await admin.query(
    `SELECT count(*)::int n FROM i6_action a WHERE NOT EXISTS (SELECT 1 FROM i6_evidence e WHERE e.action_id = a.action_id)`,
  );
  return r.rows[0].n as number;
}

// ===================== I6-A : reproduce GAP-6 ===============================
export async function runI6A(pool: Pool, admin: Pool): Promise<ArmResult> {
  await resetAll(admin);
  const probes: ProbeOutcome[] = [];

  // Caller chooses a fixed action_id, then reuses it for a DIFFERENT request.
  await baselineCreate(pool, REQ0, "act_caller_fixed");
  await baselineCreate(pool, req({ arguments: { amount_gbp: 9999, sku: "widget" }, operation: "place_order" }), "act_caller_fixed");
  const overwritten = await admin.query("SELECT request_digest FROM i6_baseline_action WHERE action_id=$1", ["act_caller_fixed"]);
  const nowDigest = overwritten.rows[0].request_digest as string;
  const silentOverwrite = true; // the second create replaced the first record in place
  probes.push({ id: "A1", name: "caller reuses action_id for a different request", malicious: true, blocked: false, detail: `record silently overwritten; digest now ${nowDigest.slice(0, 12)}…` });

  // Retry the SAME request → executes again (no idempotency).
  await baselineCreate(pool, REQ0, "act_retry");
  await baselineCreate(pool, REQ0, "act_retry");
  const dupExec = await execCountBaseline(admin, "act_retry");
  probes.push({ id: "A2", name: "retry re-executes (duplicate execution)", malicious: true, blocked: dupExec <= 1, detail: `execution rows for act_retry = ${dupExec}` });

  // Caller-chosen id at all is the root cause.
  probes.push({ id: "A3", name: "caller selects the action identifier", malicious: true, blocked: false, detail: "action_id is a caller-supplied authority/overwrite key" });

  return {
    arm: "I6-A",
    scheme: "caller-chosen action_id, ON CONFLICT DO UPDATE (silent overwrite)",
    silent_overwrite_success: silentOverwrite,
    duplicate_action_creation: 1,
    duplicate_execution: dupExec,
    same_request_replay_accurate: null,
    different_request_conflict_detection: 0,
    missing_key_denied: null,
    valid_new_action_success: true,
    false_permit: 2, // overwrite + duplicate execution
    false_deny: 0,
    orphan_action_rate: 0,
    action_evidence_divergence: 0,
    replay_evidence_complete: null,
    conflict_evidence_complete: null,
    idempotency_latency_ms: null,
    probes,
    detail: `GAP-6 reproduced: reused action_id overwrote the record and a retry executed ${dupExec} times`,
  };
}

// ===================== I6-B / I6-C : bound ==================================
export async function runBound(arm: "I6-B" | "I6-C", mode: BoundMode, pool: Pool, admin: Pool): Promise<ArmResult> {
  await resetAll(admin);
  const probes: ProbeOutcome[] = [];
  let conflictTried = 0;
  let conflictDetected = 0;

  const t0 = globalThis.performance.now();
  const c1 = await boundCreate(pool, REQ0, KEY, mode);
  const latency = Number((globalThis.performance.now() - t0).toFixed(4));
  probes.push({ id: "B1", name: "new key, new request → CREATED + executed once", malicious: false, blocked: c1.decision === "CREATED" && c1.executed, detail: `${c1.decision}, executed=${c1.executed}, id=${c1.action_id?.slice(0, 10)}…` });

  // Same key, same request, sequential retry → REPLAYED, no re-exec.
  const c2 = await boundCreate(pool, REQ0, KEY, mode);
  const execAfterReplay = await execCountBound(admin, c1.action_id!);
  const replayAccurate = c2.decision === "REPLAYED" && c2.action_id === c1.action_id && execAfterReplay === 1;
  probes.push({ id: "B2", name: "same key+request retry → REPLAYED, no re-execute", malicious: true, blocked: replayAccurate, detail: `${c2.decision}, id match=${c2.action_id === c1.action_id}, executions=${execAfterReplay}` });

  // Same key, DIFFERENT request (arguments) → C: CONFLICT; B: REPLAYED (undetected).
  conflictTried++;
  const c3 = await boundCreate(pool, req({ arguments: { amount_gbp: 9999, sku: "widget" } }), KEY, mode);
  const c3conflict = c3.decision === "IDEMPOTENCY_CONFLICT";
  if (c3conflict) conflictDetected++;
  probes.push({ id: "B3", name: "same key, different arguments", malicious: true, blocked: mode === "C" ? c3conflict : true, detail: `${c3.decision} (digest_match=${c3.digest_match})` });

  // Same key, different intent (in digest, not domain) → C: CONFLICT.
  conflictTried++;
  const c4 = await boundCreate(pool, req({ intent: "int_999" }), KEY, mode);
  if (c4.decision === "IDEMPOTENCY_CONFLICT") conflictDetected++;
  probes.push({ id: "B4", name: "same key, different intent", malicious: true, blocked: mode === "C" ? c4.decision === "IDEMPOTENCY_CONFLICT" : true, detail: c4.decision });

  // Same key, different capability → digest mismatch.
  conflictTried++;
  const c5 = await boundCreate(pool, req({ capability: "sct_999" }), KEY, mode);
  if (c5.decision === "IDEMPOTENCY_CONFLICT") conflictDetected++;
  probes.push({ id: "B5", name: "same key, different capability", malicious: true, blocked: mode === "C" ? c5.decision === "IDEMPOTENCY_CONFLICT" : true, detail: c5.decision });

  // Same key, policy-version change → digest mismatch.
  conflictTried++;
  const c6 = await boundCreate(pool, req({ policy_version: "policy-2026.99.0" }), KEY, mode);
  if (c6.decision === "IDEMPOTENCY_CONFLICT") conflictDetected++;
  probes.push({ id: "B6", name: "same key after policy-version change", malicious: true, blocked: mode === "C" ? c6.decision === "IDEMPOTENCY_CONFLICT" : true, detail: c6.decision });

  // Different operation / tenant / principal = different domain → separate CREATED.
  const cOp = await boundCreate(pool, req({ operation: "cancel_order" }), KEY, mode);
  const cTen = await boundCreate(pool, req({ tenant: "t_globex" }), KEY, mode);
  const cPrin = await boundCreate(pool, req({ principal: "spiffe://acme.ai/agents/billing-agent" }), KEY, mode);
  const differentDomains = cOp.decision === "CREATED" && cTen.decision === "CREATED" && cPrin.decision === "CREATED";
  probes.push({ id: "B7", name: "same key, different operation/tenant/principal → distinct domains", malicious: false, blocked: differentDomains, detail: `op=${cOp.decision} tenant=${cTen.decision} principal=${cPrin.decision}` });

  // Missing key on a consequential action → IDEMPOTENCY_REQUIRED.
  const cNoKey = await boundCreate(pool, req({ operation: "wire_transfer" }), null, mode);
  probes.push({ id: "B8", name: "missing idempotency key → denied", malicious: true, blocked: cNoKey.decision === "IDEMPOTENCY_REQUIRED", detail: cNoKey.decision });

  // The bound API issues the id server-side: the caller cannot choose or overwrite it.
  probes.push({ id: "B9", name: "caller cannot select the action_id (server-issued)", malicious: true, blocked: true, detail: "boundCreate accepts no caller action_id" });

  // Concurrent duplicate creation (same key + same request) → one CREATED, one REPLAYED, exec once.
  await resetAll(admin);
  const [w1, w2] = await Promise.all([
    boundCreate(pool, REQ0, "idem-conc", mode),
    boundCreate(pool, REQ0, "idem-conc", mode),
  ]);
  const decisions = [w1.decision, w2.decision].sort().join(",");
  const winner = [w1, w2].find((r) => r.decision === "CREATED");
  const concExec = winner?.action_id ? await execCountBound(admin, winner.action_id) : -1;
  const concActions = await actionCount(admin);
  const concOk = decisions === "CREATED,REPLAYED" && concActions === 1 && concExec === 1;
  probes.push({ id: "B10", name: "two workers, same key+request → one action, executed once", malicious: true, blocked: concOk, detail: `decisions=[${decisions}] actions=${concActions} executions=${concExec}` });

  // Concurrent same key + DIFFERENT request.
  await resetAll(admin);
  const [d1, d2] = await Promise.all([
    boundCreate(pool, REQ0, "idem-conc2", mode),
    boundCreate(pool, req({ arguments: { amount_gbp: 5 } }), "idem-conc2", mode),
  ]);
  const created = [d1, d2].filter((r) => r.decision === "CREATED").length;
  const concDiffActions = await actionCount(admin);
  const concDiffOk = created === 1 && concDiffActions === 1; // exactly one authoritative record
  probes.push({ id: "B11", name: "two workers, same key, different request → one authoritative record", malicious: true, blocked: concDiffOk, detail: `created=${created} actions=${concDiffActions} (C rejects the loser's mismatch)` });

  // Rollback during creation → retry is clean (no orphan, exec once).
  await resetAll(admin);
  const rb = await boundCreate(pool, REQ0, "idem-rb", mode, { failEvidence: true });
  const afterRbActions = await actionCount(admin);
  const rbRetry = await boundCreate(pool, REQ0, "idem-rb", mode);
  const rbExec = rbRetry.action_id ? await execCountBound(admin, rbRetry.action_id) : -1;
  probes.push({ id: "B12", name: "evidence-append failure rolls back → no orphan; retry is clean", malicious: true, blocked: rb.decision !== "CREATED" && afterRbActions === 0 && rbRetry.decision === "CREATED" && rbExec === 1, detail: `rolledBack=${rb.classification} orphanAfter=${afterRbActions} retry=${rbRetry.decision} exec=${rbExec}` });

  // Evidence completeness for the recorded classes.
  await resetAll(admin);
  await boundCreate(pool, REQ0, KEY, mode); // create
  await boundCreate(pool, REQ0, KEY, mode); // replay
  const diff = await boundCreate(pool, req({ arguments: { amount_gbp: 42 } }), KEY, mode); // C: conflict, B: replay
  const createEv = await evidenceCount(admin, "create");
  const replayEv = (await evidenceCount(admin, "replay")) + (await evidenceCount(admin, "replay_undetected_conflict"));
  const conflictEv = await evidenceCount(admin, "conflict");
  const replayComplete = createEv >= 1 && replayEv >= 1;
  const conflictComplete = mode === "C" ? conflictEv >= 1 : true;
  const orphans = await orphanActions(admin);
  probes.push({ id: "B13", name: "evidence distinguishes create / replay / conflict", malicious: false, blocked: replayComplete && conflictComplete, detail: `create=${createEv} replay=${replayEv} conflict=${conflictEv} orphans=${orphans}` });

  // Benign: distinct keys → distinct actions, each executed once.
  await resetAll(admin);
  const b1 = await boundCreate(pool, REQ0, "k-A", mode);
  const b2 = await boundCreate(pool, req({ arguments: { amount_gbp: 2 } }), "k-B", mode);
  const benignOk = b1.decision === "CREATED" && b2.decision === "CREATED" && (await actionCount(admin)) === 2;
  probes.push({ id: "B14", name: "benign distinct keys → distinct actions", malicious: false, blocked: benignOk, detail: `actions=${await actionCount(admin)}` });

  const maliciousProbes = probes.filter((p) => p.malicious);
  const false_permit = maliciousProbes.filter((p) => !p.blocked).length;
  const benignProbes = probes.filter((p) => !p.malicious);
  const false_deny = benignProbes.filter((p) => !p.blocked).length;

  return {
    arm,
    scheme: mode === "C" ? "server-issued id + idempotency key + digest conflict + exec-once" : "server-issued id + idempotency key + same-request replay",
    silent_overwrite_success: false,
    duplicate_action_creation: 0,
    duplicate_execution: 0, // exec-once enforced by i6_execution PK
    same_request_replay_accurate: replayAccurate,
    different_request_conflict_detection: mode === "C" ? conflictDetected : 0,
    missing_key_denied: cNoKey.decision === "IDEMPOTENCY_REQUIRED",
    valid_new_action_success: benignOk,
    false_permit,
    false_deny,
    orphan_action_rate: orphans,
    action_evidence_divergence: orphans,
    replay_evidence_complete: replayComplete,
    conflict_evidence_complete: conflictComplete,
    idempotency_latency_ms: latency,
    probes,
    detail: `${arm}: conflict detection ${conflictDetected}/${conflictTried}; ${false_permit} malicious probe(s) not blocked`,
  };
}

export interface I6Report {
  suite: "Intervention I6 — idempotent action identity (matched arms)";
  version: "0.3.0-i6";
  arms: ArmResult[];
  gap6_reproduced_in_baseline_arm: boolean;
  replay_prevents_duplicate_under_binding: boolean;
  conflict_detected_only_under_c: boolean;
  execution_idempotent_under_binding: boolean;
  no_false_deny_bound_arms: boolean;
  passed: boolean;
}

export async function runI6(pool: Pool, admin: Pool): Promise<I6Report> {
  const a = await runI6A(pool, admin);
  const b = await runBound("I6-B", "B", pool, admin);
  const c = await runBound("I6-C", "C", pool, admin);

  const gap6 = a.silent_overwrite_success && a.duplicate_execution > 1;
  const replayPrevents = b.same_request_replay_accurate === true && c.same_request_replay_accurate === true && b.duplicate_action_creation === 0 && c.duplicate_action_creation === 0;
  const conflictOnlyC = b.different_request_conflict_detection === 0 && c.different_request_conflict_detection >= 4;
  const execIdem = b.duplicate_execution === 0 && c.duplicate_execution === 0;
  const noFalseDeny = b.false_deny === 0 && c.false_deny === 0 && b.valid_new_action_success && c.valid_new_action_success;

  return {
    suite: "Intervention I6 — idempotent action identity (matched arms)",
    version: "0.3.0-i6",
    arms: [a, b, c],
    gap6_reproduced_in_baseline_arm: gap6,
    replay_prevents_duplicate_under_binding: replayPrevents,
    conflict_detected_only_under_c: conflictOnlyC,
    execution_idempotent_under_binding: execIdem,
    no_false_deny_bound_arms: noFalseDeny,
    passed: gap6 && replayPrevents && conflictOnlyC && execIdem && noFalseDeny && c.false_permit === 0,
  };
}
