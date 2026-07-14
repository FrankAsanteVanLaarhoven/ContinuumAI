/**
 * Intervention I4 — matched-arm evaluation of proof-of-possession replay resistance.
 *
 *   I4-A  baseline  signature-only, no consumption            (reproduces GAP-4)
 *   I4-B  bound     + single-use nonce via transactional ledger
 *   I4-C  bound+    + request/capability/audience binding
 *
 * A holder signs a proof; the battery then presents it under attack. A "stale
 * acceptance" is a presentation the verifier accepts that it should not. I4-A
 * accepts sequential replay AND a concurrent double-spend; I4-B closes both but
 * still accepts a fresh-nonce proof LIFTED onto a different request/audience/
 * capability (3/3); I4-C closes the lifts too (0/3). Every arm must still accept the
 * benign proof and reject the expiry, non-holder, and missing-proof controls.
 */
import type { Pool } from "pg";
import { generateEd25519, signEd25519 } from "@continuum/core";
import { proofMessage, requestDigest, resetAll, type Arm, type Capability, type ProofContext } from "./harness";
import { verifyProof, type CurrentContext } from "./pop";

const HOLDER = generateEd25519();
const IMPOSTOR = generateEd25519();

const AUD1 = "gw-approved-llm-2026-06";
const AUD2 = "gw-other-model-2026";
const CAP1 = "cap_live";
const CAP2 = "cap_other";
const R1 = requestDigest({ operation: "read:supplier_quotes", resource: "mem_q_apex" });
const R2 = requestDigest({ operation: "place_order", resource: "mem_q_apex" }); // materially different

const TOKEN = "sct_i4_procurement";

function liveCap(nowMs: number): Capability {
  return { token_id: TOKEN, tenant: "t_acme", holder_public_key_pem: HOLDER.publicKeyPem, audience: AUD1, capability_id: CAP1, expires_at_ms: nowMs + 90_000 };
}
function expiredCap(nowMs: number): Capability {
  return { ...liveCap(nowMs), expires_at_ms: nowMs - 1 };
}

/** The holder produces a proof over a context, under the arm's message rule. */
function sign(arm: Arm, priv: string, ctx: ProofContext): string {
  return signEd25519(priv, proofMessage(arm, TOKEN, ctx));
}

const matching = (ctx: ProofContext): CurrentContext => ({ request_digest: ctx.request_digest, capability_id: ctx.capability_id, audience: ctx.audience });

export interface ArmResult {
  arm: "I4-A" | "I4-B" | "I4-C";
  scheme: string;
  benign_success: boolean;
  replay_accepted: boolean;
  replay_acceptances: number; // times the SAME proof was accepted (>=2 = replayable)
  concurrent_double_spend: boolean;
  lifted_request_accepted: boolean;
  lifted_audience_accepted: boolean;
  lifted_capability_accepted: boolean;
  lifted_accepted_count: number; // of 3
  expired_rejected: boolean;
  nonholder_rejected: boolean;
  missing_rejected: boolean;
  false_deny: number;
  detail: string;
}

async function runArm(pool: Pool, admin: Pool, armLabel: ArmResult["arm"], arm: Arm, nowMs: number): Promise<ArmResult> {
  await resetAll(admin);
  const cap = liveCap(nowMs);

  // --- benign control: fresh nonce, honest context ---
  const benignCtx: ProofContext = { nonce: "n_benign", request_digest: R1, capability_id: CAP1, audience: AUD1 };
  const benign = await verifyProof(pool, arm, cap, benignCtx, matching(benignCtx), sign(arm, HOLDER.privateKeyPem, benignCtx), nowMs, "benign");

  // --- sequential replay: present the SAME proof twice ---
  const replayCtx: ProofContext = { nonce: "n_replay", request_digest: R1, capability_id: CAP1, audience: AUD1 };
  const replaySig = sign(arm, HOLDER.privateKeyPem, replayCtx);
  const r1 = await verifyProof(pool, arm, cap, replayCtx, matching(replayCtx), replaySig, nowMs, "replay");
  const r2 = await verifyProof(pool, arm, cap, replayCtx, matching(replayCtx), replaySig, nowMs, "replay");
  const replay_acceptances = (r1.accepted ? 1 : 0) + (r2.accepted ? 1 : 0);

  // --- concurrent double-spend: two workers present one proof at once ---
  const concCtx: ProofContext = { nonce: "n_conc", request_digest: R1, capability_id: CAP1, audience: AUD1 };
  const concSig = sign(arm, HOLDER.privateKeyPem, concCtx);
  const [c1, c2] = await Promise.all([
    verifyProof(pool, arm, cap, concCtx, matching(concCtx), concSig, nowMs, "double_spend"),
    verifyProof(pool, arm, cap, concCtx, matching(concCtx), concSig, nowMs, "double_spend"),
  ]);
  const concurrent_accepted = (c1.accepted ? 1 : 0) + (c2.accepted ? 1 : 0);

  // --- proof lifted onto a different request (fresh nonce, holder-signed for R1) ---
  const lrCtx: ProofContext = { nonce: "n_lift_req", request_digest: R1, capability_id: CAP1, audience: AUD1 };
  const lr = await verifyProof(pool, arm, cap, lrCtx, { request_digest: R2, capability_id: CAP1, audience: AUD1 }, sign(arm, HOLDER.privateKeyPem, lrCtx), nowMs, "lift_request");

  // --- proof lifted onto a different audience ---
  const laCtx: ProofContext = { nonce: "n_lift_aud", request_digest: R1, capability_id: CAP1, audience: AUD1 };
  const la = await verifyProof(pool, arm, cap, laCtx, { request_digest: R1, capability_id: CAP1, audience: AUD2 }, sign(arm, HOLDER.privateKeyPem, laCtx), nowMs, "lift_audience");

  // --- proof lifted onto a different capability ---
  const lcCtx: ProofContext = { nonce: "n_lift_cap", request_digest: R1, capability_id: CAP1, audience: AUD1 };
  const lc = await verifyProof(pool, arm, cap, lcCtx, { request_digest: R1, capability_id: CAP2, audience: AUD1 }, sign(arm, HOLDER.privateKeyPem, lcCtx), nowMs, "lift_capability");

  // --- controls that must hold under EVERY arm ---
  const expCtx: ProofContext = { nonce: "n_expired", request_digest: R1, capability_id: CAP1, audience: AUD1 };
  const exp = await verifyProof(pool, arm, expiredCap(nowMs), expCtx, matching(expCtx), sign(arm, HOLDER.privateKeyPem, expCtx), nowMs, "expired");

  const nhCtx: ProofContext = { nonce: "n_nonholder", request_digest: R1, capability_id: CAP1, audience: AUD1 };
  const nh = await verifyProof(pool, arm, cap, nhCtx, matching(nhCtx), sign(arm, IMPOSTOR.privateKeyPem, nhCtx), nowMs, "nonholder");

  const msCtx: ProofContext = { nonce: "n_missing", request_digest: R1, capability_id: CAP1, audience: AUD1 };
  const ms = await verifyProof(pool, arm, cap, msCtx, matching(msCtx), "", nowMs, "missing");

  const lifted_accepted_count = (lr.accepted ? 1 : 0) + (la.accepted ? 1 : 0) + (lc.accepted ? 1 : 0);

  return {
    arm: armLabel,
    scheme:
      arm === "A" ? "signature-only, no consumption" : arm === "B" ? "single-use nonce (transactional ledger)" : "single-use nonce + request/capability/audience binding",
    benign_success: benign.accepted,
    replay_accepted: r2.accepted,
    replay_acceptances,
    concurrent_double_spend: concurrent_accepted === 2,
    lifted_request_accepted: lr.accepted,
    lifted_audience_accepted: la.accepted,
    lifted_capability_accepted: lc.accepted,
    lifted_accepted_count,
    expired_rejected: !exp.accepted,
    nonholder_rejected: !nh.accepted,
    missing_rejected: !ms.accepted,
    false_deny: benign.accepted ? 0 : 1,
    detail: `benign ${benign.accepted ? "ok" : "DENIED"}; replay×${replay_acceptances}; concurrent-accepted=${concurrent_accepted}; lifts ${lifted_accepted_count}/3`,
  };
}

export interface I4Report {
  suite: "Intervention I4 — proof-of-possession replay resistance (matched arms)";
  version: "0.3.0-i4";
  now_ms: number;
  arms: ArmResult[];
  gap4_reproduced_in_baseline_arm: boolean;
  consumption_prevents_replay: boolean;
  binding_only_under_c: boolean;
  controls_hold_all_arms: boolean;
  no_false_deny_any_arm: boolean;
  passed: boolean;
}

export async function runI4(pool: Pool, admin: Pool, nowMs = Date.parse("2026-07-14T12:00:00.000Z")): Promise<I4Report> {
  const a = await runArm(pool, admin, "I4-A", "A", nowMs);
  const b = await runArm(pool, admin, "I4-B", "B", nowMs);
  const c = await runArm(pool, admin, "I4-C", "C", nowMs);

  const gap4 = a.replay_accepted && a.concurrent_double_spend && a.lifted_accepted_count === 3;
  const consumption = !b.replay_accepted && !b.concurrent_double_spend;
  // B leaves the lift class open (3/3); C closes it (0/3) — the single variable is binding.
  const bindingOnlyC = b.lifted_accepted_count === 3 && c.lifted_accepted_count === 0;
  const controls = [a, b, c].every((x) => x.expired_rejected && x.nonholder_rejected && x.missing_rejected);
  const noFalseDeny = [a, b, c].every((x) => x.false_deny === 0 && x.benign_success);

  return {
    suite: "Intervention I4 — proof-of-possession replay resistance (matched arms)",
    version: "0.3.0-i4",
    now_ms: nowMs,
    arms: [a, b, c],
    gap4_reproduced_in_baseline_arm: gap4,
    consumption_prevents_replay: consumption,
    binding_only_under_c: bindingOnlyC,
    controls_hold_all_arms: controls,
    no_false_deny_any_arm: noFalseDeny,
    passed: gap4 && consumption && bindingOnlyC && controls && noFalseDeny,
  };
}
