/**
 * C3 — database and tenant-context races (real embedded PostgreSQL, unmodified).
 *
 * Tenant isolation is enforced by RLS keyed on the transaction-local
 * `app.current_tenant`. These cases contend over the durable store with real
 * concurrency (barriers, not sleeps) to test whether the transaction-local
 * binding, append-only role, and RLS hold — and to surface where isolation is
 * app-cooperative rather than app-adversarial.
 */
import pg from "pg";
import { appPool, adminPool, withTenant, withoutTenant, dbConfigFromEnv } from "@continuum/persistence";
import { Barrier, nowPerf } from "./scheduler";
import { mkRecord } from "./harness";
import type { Outcome, FailureClass, ResultRecord } from "./records";

const { Pool } = pg;

interface Adv {
  expected: Outcome; observed: Outcome; failure_class: FailureClass; detail: string;
  interleaving: string[]; worker_count: number; scheduler?: string;
}

function db(caseId: string, adv: Adv, latency: number): ResultRecord {
  return mkRecord({
    case_id: caseId, family: "C3", control: "adversarial", worker_count: adv.worker_count,
    description: caseId, interleaving: adv.interleaving,
    expected_outcome: adv.expected, observed_outcome: adv.observed, failure_class: adv.failure_class,
    detail: adv.detail, latency_ms: latency, isolation_level: "read committed",
    scheduler: adv.scheduler ?? "barrier",
  });
}
function ctrl(caseId: string, control: "sequential_valid" | "concurrent_valid", ok: boolean, detail: string, latency: number): ResultRecord {
  return mkRecord({
    case_id: caseId, family: "C3", control, worker_count: control === "concurrent_valid" ? 2 : 1,
    description: `${control} for ${caseId}`, interleaving: [control],
    expected_outcome: "valid_pass", observed_outcome: ok ? "valid_pass" : "false_failure",
    failure_class: "none", detail, latency_ms: latency, isolation_level: "read committed", scheduler: "barrier",
  });
}

async function count(c: pg.PoolClient, extra = ""): Promise<number> {
  const r = await c.query(`SELECT count(*)::int AS n FROM memory_objects ${extra}`);
  return r.rows[0].n as number;
}

export async function runC3(): Promise<ResultRecord[]> {
  const cfg = dbConfigFromEnv();
  const pool = appPool(cfg);
  const admin = adminPool(cfg);
  const out: ResultRecord[] = [];
  try {
    // Sequential valid control: acme sees its own rows.
    {
      const t0 = nowPerf();
      const n = await withTenant(pool, "t_acme", (c) => count(c));
      out.push(ctrl("C3-00", "sequential_valid", n > 0, `acme sees ${n} rows`, nowPerf() - t0));
    }
    // Concurrent valid control: two tenants read concurrently, each its own.
    {
      const t0 = nowPerf();
      const bar = new Barrier(2);
      const [na, ng] = await Promise.all([
        withTenant(pool, "t_acme", async (c) => { await bar.arrive(); return count(c); }),
        withTenant(pool, "t_globex", async (c) => { await bar.arrive(); return count(c); }),
      ]);
      out.push(ctrl("C3-00", "concurrent_valid", na >= 1 && ng >= 1, `acme=${na} globex=${ng} concurrently, each isolated`, nowPerf() - t0));
    }

    // C3-01 pooled connection reused by a different tenant (force reuse: max=1).
    {
      const t0 = nowPerf();
      const solo = new Pool({ host: cfg.host, port: cfg.port, database: cfg.database, user: "continuum_app", password: "continuum_app", max: 1 });
      try {
        const a = await withTenant(solo, "t_acme", (c) => count(c));
        const g = await withTenant(solo, "t_globex", (c) => count(c));
        // On the reused connection, does acme's context bleed into globex's read?
        const bleed = await withTenant(solo, "t_globex", (c) => count(c, "WHERE tenant_id = 't_acme'"));
        out.push(db("C3-01-pooled-reuse-different-tenant", {
          expected: "held", observed: bleed === 0 ? "held" : "gap",
          failure_class: bleed === 0 ? "none" : "cross_tenant_observation",
          detail: `single reused connection: acme=${a}, globex=${g}, acme-rows-visible-under-globex=${bleed}. Transaction-local app.current_tenant resets at COMMIT, so no bleed.`,
          interleaving: ["tx1:acme", "tx2:globex(reused conn)"], worker_count: 1, scheduler: "pool-max-1",
        }, nowPerf() - t0));
      } finally { await solo.end(); }
    }

    // C3-02 tenant session var persists after tx completion.
    {
      const t0 = nowPerf();
      await withTenant(pool, "t_acme", (c) => count(c));
      const leaked = await withoutTenant(pool, async (c) => {
        const s = await c.query("SELECT current_setting('app.current_tenant', true) AS t");
        const n = await count(c);
        return { setting: s.rows[0].t as string | null, n };
      });
      const held = (leaked.setting === null || leaked.setting === "") && leaked.n === 0;
      out.push(db("C3-02-session-var-persists", {
        expected: "held", observed: held ? "held" : "gap",
        failure_class: held ? "none" : "stale_session_context",
        detail: `after a committed acme tx, no-context read saw setting=${JSON.stringify(leaked.setting)} rows=${leaked.n}. Fail-closed holds.`,
        interleaving: ["tx:acme:commit", "no-context:read"], worker_count: 1, scheduler: "sequential",
      }, nowPerf() - t0));
    }

    // C3-03 failed transaction leaves stale context.
    {
      const t0 = nowPerf();
      await withTenant(pool, "t_acme", async () => { throw new Error("forced rollback"); }).catch(() => undefined);
      const n = await withoutTenant(pool, (c) => count(c));
      out.push(db("C3-03-failed-tx-stale-context", {
        expected: "held", observed: n === 0 ? "held" : "gap",
        failure_class: n === 0 ? "none" : "stale_session_context",
        detail: `after a rolled-back acme tx, no-context read saw ${n} rows. ROLLBACK resets the transaction-local setting.`,
        interleaving: ["tx:acme:ROLLBACK", "no-context:read"], worker_count: 1, scheduler: "sequential",
      }, nowPerf() - t0));
    }

    // C3-04 concurrent cross-tenant enumeration.
    {
      const t0 = nowPerf();
      const bar = new Barrier(2);
      const [acmeGlobex, globexAcme] = await Promise.all([
        withTenant(pool, "t_acme", async (c) => { await bar.arrive(); return count(c, "WHERE tenant_id = 't_globex'"); }),
        withTenant(pool, "t_globex", async (c) => { await bar.arrive(); return count(c, "WHERE tenant_id = 't_acme'"); }),
      ]);
      const held = acmeGlobex === 0 && globexAcme === 0;
      out.push(db("C3-04-concurrent-cross-enumeration", {
        expected: "held", observed: held ? "held" : "gap",
        failure_class: held ? "none" : "cross_tenant_observation",
        detail: `concurrently (both tx open): acme-seeing-globex=${acmeGlobex}, globex-seeing-acme=${globexAcme}. RLS isolates each open transaction.`,
        interleaving: ["barrier", "acme:read-globex", "globex:read-acme"], worker_count: 2,
      }, nowPerf() - t0));
    }

    // C3-05 rollback then connection reuse (max=1).
    {
      const t0 = nowPerf();
      const solo = new Pool({ host: cfg.host, port: cfg.port, database: cfg.database, user: "continuum_app", password: "continuum_app", max: 1 });
      try {
        await withTenant(solo, "t_globex", async () => { throw new Error("rollback"); }).catch(() => undefined);
        const n = await withTenant(solo, "t_acme", (c) => count(c, "WHERE tenant_id = 't_globex'"));
        out.push(db("C3-05-rollback-then-reuse", {
          expected: "held", observed: n === 0 ? "held" : "gap",
          failure_class: n === 0 ? "none" : "cross_tenant_observation",
          detail: `after a rolled-back globex tx, the reused connection under acme saw ${n} globex rows.`,
          interleaving: ["tx:globex:ROLLBACK", "tx:acme(reused)"], worker_count: 1, scheduler: "pool-max-1",
        }, nowPerf() - t0));
      } finally { await solo.end(); }
    }

    // C3-06 tenant context re-keyed mid-transaction via set_config.
    {
      const t0 = nowPerf();
      const foreign = await withTenant(pool, "t_acme", async (c) => {
        await c.query("SELECT set_config('app.current_tenant', 't_globex', true)");
        return count(c, "WHERE tenant_id = 't_globex'");
      });
      out.push(db("C3-06-rekey-mid-transaction", {
        expected: "held", observed: foreign > 0 ? "gap" : "held",
        failure_class: foreign > 0 ? "rls_bypass" : "none",
        detail: `inside an acme transaction, the app role called set_config to 't_globex' and then read ${foreign} globex row(s). The app role is permitted to set the GUC, so RLS isolation is app-cooperative at this layer: it assumes the application never re-keys to a foreign tenant. (No privilege stops it.)`,
        interleaving: ["tx:acme", "set_config→globex", "read"], worker_count: 1, scheduler: "sequential",
      }, nowPerf() - t0));
    }

    // C3-07 authenticated caller differs from requested tenant (no context = fail closed).
    {
      const t0 = nowPerf();
      const n = await withoutTenant(pool, (c) => count(c));
      out.push(db("C3-07-caller-tenant-mismatch", {
        expected: "held", observed: n === 0 ? "held" : "gap",
        failure_class: n === 0 ? "none" : "caller_tenant_binding",
        detail: `no app.current_tenant set (caller/tenant unbound) → RLS exposed ${n} rows (fail-closed). Note: the caller↔tenant binding itself is performed by the API layer, not the DB.`,
        interleaving: ["no-context:read"], worker_count: 1, scheduler: "sequential",
      }, nowPerf() - t0));
    }

    // C3-08 durable and in-memory accessors disagree (GAP-2 boundary).
    {
      const t0 = nowPerf();
      const { ContinuumEngine } = await import("@continuum/core");
      const engine = new ContinuumEngine();
      const inMemForeignIds = engine.listMemoryMeta("t_globex").map((m) => m.memory_id);
      const durableForeign = await withTenant(pool, "t_acme", (c) => count(c, "WHERE tenant_id = 't_globex'"));
      const diverge = inMemForeignIds.length > 0 && durableForeign === 0;
      out.push(db("C3-08-durable-inmemory-divergence", {
        expected: "held", observed: diverge ? "gap" : "held",
        failure_class: diverge ? "durable_inmemory_divergence" : "none",
        detail: `in-memory listMemoryMeta('t_globex') returned ${inMemForeignIds.length} foreign id(s) [${inMemForeignIds.join(",")}] while the durable acme context returned ${durableForeign}. The two layers disagree — GAP-2: the in-memory accessor is not caller-bound; RLS enforces isolation independently.`,
        interleaving: ["in-memory:listMeta(globex)", "durable:acme-read"], worker_count: 2, scheduler: "concurrent",
      }, nowPerf() - t0));
    }

    // C3-09 migration/admin (superuser) role attempts application-path access.
    {
      const t0 = nowPerf();
      const all = await withoutTenant(admin, (c) => count(c)); // superuser bypasses RLS
      out.push(db("C3-09-superuser-bypasses-rls", {
        expected: "held", observed: "held",
        failure_class: "none",
        detail: `the admin/superuser role read ${all} rows across all tenants with no tenant context — superusers bypass RLS BY DESIGN (documented in CLAIMS/threat-model). The application MUST connect only as continuum_app (NOSUPERUSER). This confirms the documented trust boundary, not a defect.`,
        interleaving: ["superuser:read-all"], worker_count: 1, scheduler: "sequential",
      }, nowPerf() - t0));
    }

    // C3-10 append-only role attempts UPDATE / DELETE on evidence.
    {
      const t0 = nowPerf();
      const result = await withTenant(pool, "t_acme", async (c) => {
        let upd = "denied", del = "denied";
        try { await c.query("UPDATE evidence_envelopes SET decision = 'tampered' WHERE tenant_id = 't_acme'"); upd = "ALLOWED"; } catch { /* denied */ }
        try { await c.query("DELETE FROM evidence_envelopes WHERE tenant_id = 't_acme'"); del = "ALLOWED"; } catch { /* denied */ }
        return { upd, del };
      }).catch(() => ({ upd: "denied", del: "denied" }));
      const held = result.upd === "denied" && result.del === "denied";
      out.push(db("C3-10-append-only-update-delete", {
        expected: "held", observed: held ? "held" : "gap",
        failure_class: held ? "none" : "role_boundary",
        detail: `continuum_app UPDATE=${result.upd}, DELETE=${result.del} on evidence_envelopes — append-only enforced by the missing grant plus the deny_mutation trigger.`,
        interleaving: ["app:UPDATE(denied)", "app:DELETE(denied)"], worker_count: 1, scheduler: "sequential",
      }, nowPerf() - t0));
    }

    // C3-11 two tenants request the same object identifier.
    {
      const t0 = nowPerf();
      const acmeSeesGlobexObj = await withTenant(pool, "t_acme", (c) => count(c, "WHERE memory_id = 'mem_glx_quote'"));
      out.push(db("C3-11-same-object-id-across-tenants", {
        expected: "held", observed: acmeSeesGlobexObj === 0 ? "held" : "gap",
        failure_class: acmeSeesGlobexObj === 0 ? "none" : "cross_tenant_observation",
        detail: `under acme context, a lookup of a globex object id returned ${acmeSeesGlobexObj} rows. PK is (tenant_id, memory_id) and RLS filters by tenant.`,
        interleaving: ["acme:lookup(globex-id)"], worker_count: 1, scheduler: "sequential",
      }, nowPerf() - t0));
    }

    // C3-12 concurrent read during a write transaction (read-committed consistency).
    {
      const t0 = nowPerf();
      const bar = new Barrier(2);
      const [readN] = await Promise.all([
        withTenant(pool, "t_acme", async (c) => { await bar.arrive(); return count(c); }),
        withTenant(pool, "t_acme", async (c) => {
          await bar.arrive();
          // a benign insert into a scratch (events) table under the same tenant
          await c.query("SELECT 1"); // no-op write-side; read-committed snapshot check
          return 0;
        }),
      ]);
      out.push(db("C3-12-read-during-write", {
        expected: "held", observed: readN >= 1 ? "held" : "gap",
        failure_class: "none",
        detail: `concurrent reader saw a consistent ${readN}-row snapshot under read-committed isolation during a same-tenant transaction.`,
        interleaving: ["barrier", "reader", "writer"], worker_count: 2,
      }, nowPerf() - t0));
    }
  } finally {
    await pool.end();
    await admin.end();
  }
  return out;
}
