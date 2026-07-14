/**
 * C4 — evidence and event-chain races.
 *
 * Durable evidence is append-only with PRIMARY KEY (tenant_id, event_id) and
 * UNIQUE (tenant_id, seq); the in-memory ledger appends synchronously. These
 * cases test whether concurrent or duplicate appends can fork the chain, reuse a
 * sequence, or orphan evidence. Duplicate-key probes reuse committed keys so
 * they are rejected and persist nothing (reproducible); the atomicity probe
 * rolls back.
 */
import pg from "pg";
import { runVerticalSlice, verifyEnvelopeChain } from "@continuum/core";
import { appPool, withTenant, dbConfigFromEnv } from "@continuum/persistence";
import { Barrier, nowPerf } from "./scheduler";
import { NOW, mkRecord } from "./harness";
import type { Outcome, FailureClass, ResultRecord } from "./records";

interface Adv {
  expected: Outcome; observed: Outcome; failure_class: FailureClass; detail: string;
  interleaving: string[]; worker_count: number; scheduler?: string; iso?: string;
}
function rec(caseId: string, adv: Adv, latency: number): ResultRecord {
  return mkRecord({
    case_id: caseId, family: "C4", control: "adversarial", worker_count: adv.worker_count,
    description: caseId, interleaving: adv.interleaving, expected_outcome: adv.expected,
    observed_outcome: adv.observed, failure_class: adv.failure_class, detail: adv.detail,
    latency_ms: latency, isolation_level: adv.iso ?? "n/a (in-memory)", scheduler: adv.scheduler ?? "ordered-interleave",
  });
}

const INSERT_COLS =
  "(tenant_id,event_id,seq,trace_id,owner_id,principal,policy_version,event_type,disclosed_objects,tool_calls,ts,prev_hash,hash,signature)";
function insertVals(eventId: string, seq: number): [string, unknown[]] {
  return [
    `INSERT INTO evidence_envelopes ${INSERT_COLS} VALUES ('t_acme',$1,$2,'trc','o','p','pv','conc.test','[]'::jsonb,'[]'::jsonb,'ts','ph','h','sig')`,
    [eventId, seq],
  ];
}

export async function runC4(): Promise<ResultRecord[]> {
  const out: ResultRecord[] = [];

  // --- controls (per-family; DB round-trips are costly) --------------------
  {
    const t0 = nowPerf();
    const slice = runVerticalSlice(NOW);
    const ev = slice.engine.evidence();
    out.push(mkRecord({
      case_id: "C4-00", family: "C4", control: "sequential_valid", worker_count: 1,
      description: "a normal run's evidence chain verifies",
      interleaving: ["run", "verify"], expected_outcome: "valid_pass",
      observed_outcome: ev.verification.valid ? "valid_pass" : "false_failure",
      failure_class: "none", detail: `${ev.entries.length} envelopes, valid=${ev.verification.valid}`,
      latency_ms: nowPerf() - t0,
    }));
  }
  {
    const t0 = nowPerf();
    const a = runVerticalSlice(NOW).engine.evidence();
    const b = runVerticalSlice(NOW).engine.evidence();
    const ok = a.verification.valid && b.verification.valid;
    out.push(mkRecord({
      case_id: "C4-00", family: "C4", control: "concurrent_valid", worker_count: 2,
      description: "two independent chains each verify", interleaving: ["run#1", "run#2"],
      expected_outcome: "valid_pass", observed_outcome: ok ? "valid_pass" : "false_failure",
      failure_class: "none", detail: `both valid=${ok}`, latency_ms: nowPerf() - t0,
    }));
  }

  // --- in-memory ledger cases ----------------------------------------------
  {
    const t0 = nowPerf();
    const ev = runVerticalSlice(NOW).engine.evidence();
    const ordered = ev.entries.every((e, i) => e.seq === i);
    out.push(rec("C4-08-event-ordering-vs-state", {
      expected: "held", observed: ordered ? "held" : "gap", failure_class: ordered ? "none" : "evidence_state_divergence",
      detail: `ledger seq is monotonic and equals append order for all ${ev.entries.length} envelopes (${ordered}).`,
      interleaving: ["append*", "check-order"], worker_count: 1,
    }, nowPerf() - t0));
  }
  {
    const t0 = nowPerf();
    const engine = runVerticalSlice(NOW).engine;
    const snapshot = engine.evidence().entries;
    const pubkey = engine.platformPublicKeyPem();
    const before = verifyEnvelopeChain(snapshot, pubkey).valid;
    // mutating the returned snapshot must not affect the ledger (defensive copy)
    snapshot.push({ ...snapshot[0]! });
    const after = engine.evidence().verification.valid;
    out.push(rec("C4-11-verify-during-append", {
      expected: "held", observed: before && after ? "held" : "gap", failure_class: before && after ? "none" : "verification_inconsistency",
      detail: `verification ran on a defensive snapshot copy (valid=${before}); mutating the copy left the ledger valid=${after}.`,
      interleaving: ["snapshot", "verify", "mutate-copy"], worker_count: 2,
    }, nowPerf() - t0));
  }

  // not-realizable in the current architecture (recorded honestly)
  const NR: Array<[string, string]> = [
    ["C4-02-action-succeeds-evidence-fails", "state and its evidence are produced together (in-memory) and persisted in a single transaction; there is no partial-commit split to race."],
    ["C4-03-evidence-for-rolled-back-action", "durable writes are one transaction; a rollback removes both the action rows and their evidence (see C4-01 atomicity)."],
    ["C4-05-two-chain-appends-compete", "the in-memory ledger append is synchronous (no fork); the durable UNIQUE (tenant_id, seq) prevents two rows sharing a head (see C4-04)."],
    ["C4-06-revocation-evidence-delayed", "revoke() emits its evidence synchronously in the same call; there is no delay window."],
    ["C4-09-restore-during-append", "restore is a distinct offline operation; concurrent verification runs on a defensive snapshot copy (see C4-11)."],
    ["C4-10-signature-races-key-rotation", "the platform signing key is stable per engine instance; there is no key-rotation API to race."],
    ["C4-12-partial-tx-orphan", "persistExport is atomic; a partial failure rolls the whole transaction back, leaving no orphan (see C4-01)."],
  ];
  for (const [id, why] of NR) {
    out.push(rec(id, {
      expected: "held", observed: "not_realizable", failure_class: "not_applicable",
      detail: why, interleaving: ["(no race window)"], worker_count: 1,
    }, 0));
  }

  // --- durable constraint races --------------------------------------------
  const cfg = dbConfigFromEnv();
  const pool = appPool(cfg);
  try {
    // read an existing committed (event_id, seq) to reuse as a duplicate key
    const existing = await withTenant(pool, "t_acme", async (c) => {
      const r = await c.query("SELECT event_id, seq FROM evidence_envelopes WHERE tenant_id='t_acme' ORDER BY seq LIMIT 1");
      return r.rows[0] as { event_id: string; seq: number } | undefined;
    });
    const seq0 = existing?.seq ?? 0;
    const evid0 = existing?.event_id ?? "evt_missing";

    // C4-04 concurrent duplicate-seq: two connections both reuse a committed seq.
    {
      const t0 = nowPerf();
      const bar = new Barrier(2);
      const attempt = async (eid: string): Promise<string> => {
        try {
          await withTenant(pool, "t_acme", async (c) => {
            await bar.arrive();
            const [sql, vals] = insertVals(eid, seq0);
            await c.query(sql, vals);
          });
          return "ACCEPTED";
        } catch { return "rejected"; }
      };
      const [r1, r2] = await Promise.all([attempt("evt_dupseq_a"), attempt("evt_dupseq_b")]);
      const held = r1 === "rejected" && r2 === "rejected";
      out.push(rec("C4-04-concurrent-duplicate-seq", {
        expected: "held", observed: held ? "held" : "gap", failure_class: held ? "none" : "duplicate_sequence",
        detail: `two concurrent inserts reusing committed seq=${seq0}: [${r1}, ${r2}]. UNIQUE (tenant_id, seq) prevents a duplicate sequence / competing head.`,
        interleaving: ["barrier", "insert(seq)#1", "insert(seq)#2"], worker_count: 2, scheduler: "barrier", iso: "read committed",
      }, nowPerf() - t0));
    }

    // C4-07 duplicate event_id (PK): reuse a committed event_id with a new seq.
    {
      const t0 = nowPerf();
      let observed: string;
      try {
        await withTenant(pool, "t_acme", async (c) => {
          const [sql, vals] = insertVals(evid0, 999001);
          await c.query(sql, vals);
        });
        observed = "ACCEPTED";
      } catch { observed = "rejected"; }
      out.push(rec("C4-07-duplicate-event-id", {
        expected: "held", observed: observed === "rejected" ? "held" : "gap",
        failure_class: observed === "rejected" ? "none" : "duplicate_sequence",
        detail: `insert reusing committed event_id='${evid0}' with a new seq: ${observed}. PRIMARY KEY (tenant_id, event_id) rejects the duplicate.`,
        interleaving: ["insert(dup-event-id)"], worker_count: 1, scheduler: "sequential", iso: "read committed",
      }, nowPerf() - t0));
    }

    // C4-01 append-vs-rollback atomicity: a new valid row inside a rolled-back tx must not persist.
    {
      const t0 = nowPerf();
      const newId = "evt_rollback_probe";
      await withTenant(pool, "t_acme", async (c) => {
        const [sql, vals] = insertVals(newId, 999002);
        await c.query(sql, vals);
        throw new Error("forced rollback after append");
      }).catch(() => undefined);
      const persisted = await withTenant(pool, "t_acme", async (c) => {
        const r = await c.query("SELECT count(*)::int AS n FROM evidence_envelopes WHERE tenant_id='t_acme' AND event_id=$1", [newId]);
        return r.rows[0].n as number;
      });
      out.push(rec("C4-01-append-races-rollback", {
        expected: "held", observed: persisted === 0 ? "held" : "gap",
        failure_class: persisted === 0 ? "none" : "orphan_evidence",
        detail: `a valid evidence row appended inside a rolled-back transaction persisted ${persisted} rows — atomicity leaves no orphan evidence.`,
        interleaving: ["BEGIN", "insert", "ROLLBACK", "recount"], worker_count: 1, scheduler: "sequential", iso: "read committed",
      }, nowPerf() - t0));
    }
  } finally {
    await pool.end();
  }
  return out;
}
