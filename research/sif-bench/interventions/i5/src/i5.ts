/**
 * Intervention I5 — matched-arm evaluation of database-bound tenant identity.
 *
 *   I5-A  direct application set_config('app.current_tenant', …)  — reproduces GAP-5
 *   I5-B  trusted wrapper: tenant resolved from mapping + tamper-evident lock
 *   I5-C  wrapper + caller↔session binding + context-establishment audit
 *
 * PostgreSQL RLS is only as trustworthy as the mechanism that sets
 * `app.current_tenant`. In I5-A the application role chooses its own tenant and
 * can re-key mid-transaction. I5-B/C establish the tenant from an authoritative
 * principal→tenant mapping the app cannot write and stamp a lock the app cannot
 * forge, so a re-key of the raw GUC fails the RLS predicate closed.
 */
import type { Pool, PoolClient } from "pg";
import { countVisible, rawRekey } from "./harness";

const LOCK_SECRET_TAIL = ":i5-tenant-binding-secret-2026"; // known to the DB definer only; used here only to forge-test

export interface ProbeOutcome {
  id: string;
  name: string;
  applies: boolean;
  malicious: boolean;
  blocked: boolean;
  detail: string;
}

export interface ArmResult {
  arm: "I5-A" | "I5-B" | "I5-C";
  scheme: string;
  arbitrary_rekey_success: boolean;
  caller_tenant_binding_violation: number;
  cross_tenant_observation: number;
  missing_context_denied: boolean;
  stale_mapping_accepted: number;
  connection_reuse_isolation_failure: number;
  valid_same_tenant_success: boolean;
  false_permit: number;
  false_deny: number;
  context_establishment_latency_ms: number | null;
  evidence_completeness: number;
  probes: ProbeOutcome[];
  detail: string;
}

async function inTxn<T>(pool: Pool, fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const r = await fn(c);
    await c.query("ROLLBACK");
    return r;
  } catch (err) {
    await c.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    c.release();
  }
}

/** True iff the definer wrapper raised (denied establishment). */
async function establishRaises(pool: Pool, sql: string, params: unknown[]): Promise<{ raised: boolean; reason: string }> {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    await c.query(sql, params);
    await c.query("ROLLBACK");
    return { raised: false, reason: "established (no exception)" };
  } catch (err) {
    await c.query("ROLLBACK").catch(() => undefined);
    return { raised: true, reason: (err as Error).message };
  } finally {
    c.release();
  }
}

// ===================== I5-A : reproduce GAP-5 ===============================
export async function runI5A(pool: Pool): Promise<ArmResult> {
  const probes: ProbeOutcome[] = [];

  const valid = await inTxn(pool, async (c) => {
    await rawRekey(c, "t_acme");
    return countVisible(c, "i5_baseline");
  });
  probes.push({ id: "A1", name: "valid same-tenant", applies: true, malicious: false, blocked: valid === 2, detail: `t_acme sees ${valid} row(s)` });

  const rekey = await inTxn(pool, async (c) => {
    await rawRekey(c, "t_acme");
    const before = await countVisible(c, "i5_baseline");
    await rawRekey(c, "t_globex"); // <-- cooperative re-key
    const after = await countVisible(c, "i5_baseline");
    return { before, after };
  });
  const rekeySucceeded = rekey.after > 0 && rekey.after !== rekey.before;
  probes.push({ id: "A2", name: "direct foreign re-key", applies: true, malicious: true, blocked: !rekeySucceeded, detail: `after re-key to t_globex the app read ${rekey.after} foreign row(s)` });

  const missing = await inTxn(pool, async (c) => countVisible(c, "i5_baseline"));
  probes.push({ id: "A3", name: "missing context", applies: true, malicious: true, blocked: missing === 0, detail: `no context → ${missing} row(s)` });

  return {
    arm: "I5-A",
    scheme: "direct set_config('app.current_tenant')",
    arbitrary_rekey_success: rekeySucceeded,
    caller_tenant_binding_violation: 1,
    cross_tenant_observation: rekey.after,
    missing_context_denied: missing === 0,
    stale_mapping_accepted: 0,
    connection_reuse_isolation_failure: 0,
    valid_same_tenant_success: valid === 2,
    false_permit: rekeySucceeded ? 1 : 0,
    false_deny: valid === 2 ? 0 : 1,
    context_establishment_latency_ms: null,
    evidence_completeness: 0, // baseline records no context-establishment audit
    probes,
    detail: `GAP-5 reproduced: the app re-keyed app.current_tenant to t_globex and read ${rekey.after} foreign row(s)`,
  };
}

// ===================== I5-B : trusted wrapper ==============================
export async function runI5B(pool: Pool): Promise<ArmResult> {
  const probes: ProbeOutcome[] = [];

  const t0 = globalThis.performance.now();
  const valid = await inTxn(pool, async (c) => {
    await c.query("SELECT i5_begin_b($1)", ["acme-principal"]);
    return countVisible(c, "i5_bound");
  });
  const latency = Number((globalThis.performance.now() - t0).toFixed(4));
  probes.push({ id: "B1", name: "valid same-tenant via wrapper", applies: true, malicious: false, blocked: valid === 2, detail: `resolved t_acme → ${valid} row(s)` });

  const rekey = await inTxn(pool, async (c) => {
    await c.query("SELECT i5_begin_b($1)", ["acme-principal"]);
    const before = await countVisible(c, "i5_bound");
    await rawRekey(c, "t_globex");
    const after = await countVisible(c, "i5_bound");
    return { before, after };
  });
  probes.push({ id: "B2", name: "foreign re-key after establishment", applies: true, malicious: true, blocked: rekey.after === 0, detail: `re-key to t_globex → ${rekey.after} row(s) (lock mismatch)` });

  // Forge the lock too — the app cannot compute md5(t_globex || secret).
  const forge = await inTxn(pool, async (c) => {
    await c.query("SELECT i5_begin_b($1)", ["acme-principal"]);
    await rawRekey(c, "t_globex");
    await c.query("SELECT set_config('app.tenant_lock', md5($1), true)", ["t_globex"]); // guess without the secret
    return countVisible(c, "i5_bound");
  });
  probes.push({ id: "B3", name: "forge tenant lock without secret", applies: true, malicious: true, blocked: forge === 0, detail: `forged lock → ${forge} row(s)` });

  const missing = await inTxn(pool, async (c) => countVisible(c, "i5_bound"));
  probes.push({ id: "B4", name: "missing context", applies: true, malicious: true, blocked: missing === 0, detail: `no begin → ${missing} row(s)` });

  // Rollback then reuse the connection with no context.
  const reuse = await (async () => {
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      await c.query("SELECT i5_begin_b($1)", ["acme-principal"]);
      await c.query("ROLLBACK");
      await c.query("BEGIN");
      const n = await countVisible(c, "i5_bound");
      await c.query("ROLLBACK");
      return n;
    } finally {
      c.release();
    }
  })();
  probes.push({ id: "B5", name: "rollback + connection reuse clears context", applies: true, malicious: true, blocked: reuse === 0, detail: `reused connection saw ${reuse} row(s)` });

  const maliciousBlocked = probes.filter((p) => p.malicious).every((p) => p.blocked);
  return {
    arm: "I5-B",
    scheme: "trusted wrapper i5_begin_b (tenant resolved + locked)",
    arbitrary_rekey_success: rekey.after > 0 || forge > 0,
    caller_tenant_binding_violation: 0,
    cross_tenant_observation: rekey.after + forge,
    missing_context_denied: missing === 0,
    stale_mapping_accepted: 0,
    connection_reuse_isolation_failure: reuse === 0 ? 0 : 1,
    valid_same_tenant_success: valid === 2,
    false_permit: probes.filter((p) => p.malicious && !p.blocked).length,
    false_deny: valid === 2 ? 0 : 1,
    context_establishment_latency_ms: latency,
    evidence_completeness: 0, // I5-B does not yet record an establishment audit
    probes,
    detail: `re-key neutralised: foreign reads ${rekey.after + forge}; all malicious probes blocked=${maliciousBlocked}`,
  };
}

// ===================== I5-C : + caller binding + audit ======================
export async function runI5C(pool: Pool, admin: Pool): Promise<ArmResult> {
  const probes: ProbeOutcome[] = [];

  // Valid establishment + audit read (within the same txn so the row is visible).
  const t0 = globalThis.performance.now();
  const ok = await inTxn(pool, async (c) => {
    await c.query("SELECT i5_begin_c($1,$2)", ["acme-principal", "acme-session"]);
    const rows = await countVisible(c, "i5_bound");
    const audit = await c.query(
      "SELECT principal_id, session_id, tenant_id, established_at FROM i5_context_audit WHERE principal_id=$1 ORDER BY seq DESC LIMIT 1",
      ["acme-principal"],
    );
    return { rows, audit: audit.rows[0] as Record<string, unknown> | undefined };
  });
  const latency = Number((globalThis.performance.now() - t0).toFixed(4));
  probes.push({ id: "C1", name: "valid session+principal establishment", applies: true, malicious: false, blocked: ok.rows === 2, detail: `resolved t_acme → ${ok.rows} row(s)` });

  const auditFields = ["principal_id", "session_id", "tenant_id", "established_at"];
  const auditComplete = ok.audit ? auditFields.every((f) => ok.audit![f] !== undefined && ok.audit![f] !== null) : false;
  probes.push({ id: "C2", name: "context-establishment audit recorded", applies: true, malicious: false, blocked: auditComplete, detail: auditComplete ? "audit row complete" : "audit incomplete" });

  // Denials — each must RAISE inside the definer wrapper.
  const cases: Array<[string, string, string, string]> = [
    ["C3", "forged session (session→other principal)", "acme-principal", "globex-session"],
    ["C4", "claim foreign principal", "globex-principal", "acme-session"],
    ["C5", "revoked session", "acme-principal", "revoked-session"],
    ["C6", "stale principal→tenant mapping", "stale-principal", "stale-session"],
    ["C7", "unknown principal", "ghost-principal", "acme-session"],
  ];
  for (const [id, name, principal, session] of cases) {
    const r = await establishRaises(pool, "SELECT i5_begin_c($1,$2)", [principal, session]);
    probes.push({ id, name, applies: true, malicious: true, blocked: r.raised, detail: r.raised ? r.reason.split("\n")[0]! : "unexpectedly established" });
  }

  // Re-key after a valid establishment.
  const rekey = await inTxn(pool, async (c) => {
    await c.query("SELECT i5_begin_c($1,$2)", ["acme-principal", "acme-session"]);
    await rawRekey(c, "t_globex");
    return countVisible(c, "i5_bound");
  });
  probes.push({ id: "C8", name: "foreign re-key after establishment", applies: true, malicious: true, blocked: rekey === 0, detail: `re-key to t_globex → ${rekey} row(s)` });

  // Concurrent establishment on two connections — each sees only its own tenant.
  const conc = await (async () => {
    const run = async (principal: string, session: string, table: string) => {
      const c = await pool.connect();
      try {
        await c.query("BEGIN");
        await c.query("SELECT i5_begin_c($1,$2)", [principal, session]);
        const rows = await c.query(`SELECT tenant_id, count(*)::int n FROM ${table} GROUP BY tenant_id`);
        await c.query("ROLLBACK");
        return rows.rows as Array<{ tenant_id: string; n: number }>;
      } finally {
        c.release();
      }
    };
    const [a, g] = await Promise.all([run("acme-principal", "acme-session", "i5_bound"), run("globex-principal", "globex-session", "i5_bound")]);
    const acmeOnly = a.every((r) => r.tenant_id === "t_acme");
    const globexOnly = g.every((r) => r.tenant_id === "t_globex");
    return acmeOnly && globexOnly && a.length === 1 && g.length === 1;
  })();
  probes.push({ id: "C9", name: "concurrent establishment isolation", applies: true, malicious: true, blocked: conc, detail: conc ? "each connection saw only its own tenant" : "cross-tenant bleed between connections" });

  // Documented boundary: the superuser bypasses RLS (a non-goal, not a fix).
  const superBypass = await (async () => {
    const c = await admin.connect();
    try {
      await c.query("BEGIN");
      const n = await countVisible(c, "i5_bound");
      await c.query("ROLLBACK");
      return n;
    } finally {
      c.release();
    }
  })();
  probes.push({ id: "C10", name: "superuser bypass (documented non-goal)", applies: true, malicious: false, blocked: superBypass >= 3, detail: `superuser sees all ${superBypass} row(s) — documented boundary, not remediated` });

  const staleAccepted = probes.find((p) => p.id === "C6")!.blocked ? 0 : 1;
  const maliciousProbes = probes.filter((p) => p.malicious);
  return {
    arm: "I5-C",
    scheme: "wrapper i5_begin_c (session-bound + audited)",
    arbitrary_rekey_success: rekey > 0,
    caller_tenant_binding_violation: probes.filter((p) => ["C3", "C4", "C7"].includes(p.id) && !p.blocked).length,
    cross_tenant_observation: rekey,
    missing_context_denied: true,
    stale_mapping_accepted: staleAccepted,
    connection_reuse_isolation_failure: conc ? 0 : 1,
    valid_same_tenant_success: ok.rows === 2,
    false_permit: maliciousProbes.filter((p) => !p.blocked).length,
    false_deny: ok.rows === 2 ? 0 : 1,
    context_establishment_latency_ms: latency,
    evidence_completeness: auditComplete ? 1 : 0,
    probes,
    detail: `caller-bound + audited; ${maliciousProbes.filter((p) => !p.blocked).length} malicious probe(s) accepted`,
  };
}

export interface I5Report {
  suite: "Intervention I5 — database-bound tenant identity (matched arms)";
  version: "0.3.0-i5";
  arms: ArmResult[];
  gap5_reproduced_in_baseline_arm: boolean;
  rekey_prevented_under_binding: boolean;
  caller_binding_enforced_under_c: boolean;
  no_false_deny_any_arm: boolean;
  superuser_bypass_documented: boolean;
  passed: boolean;
}

export async function runI5(appPoolRef: Pool, adminPoolRef: Pool): Promise<I5Report> {
  const a = await runI5A(appPoolRef);
  const b = await runI5B(appPoolRef);
  const c = await runI5C(appPoolRef, adminPoolRef);

  const gap5 = a.arbitrary_rekey_success && a.cross_tenant_observation > 0;
  const prevented = !b.arbitrary_rekey_success && !c.arbitrary_rekey_success;
  const callerBinding = c.caller_tenant_binding_violation === 0 && c.stale_mapping_accepted === 0 && c.false_permit === 0;
  const noFalseDeny = [a, b, c].every((x) => x.false_deny === 0 && x.valid_same_tenant_success);
  const superDoc = c.probes.find((p) => p.id === "C10")!.blocked; // observed to bypass = boundary honestly recorded

  return {
    suite: "Intervention I5 — database-bound tenant identity (matched arms)",
    version: "0.3.0-i5",
    arms: [a, b, c],
    gap5_reproduced_in_baseline_arm: gap5,
    rekey_prevented_under_binding: prevented,
    caller_binding_enforced_under_c: callerBinding,
    no_false_deny_any_arm: noFalseDeny,
    superuser_bypass_documented: superDoc,
    passed: gap5 && prevented && callerBinding && noFalseDeny && superDoc,
  };
}
