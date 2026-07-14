import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool } from "pg";
import { appPool, adminPool, i5Config } from "./harness";
import { runI5, type I5Report } from "./i5";

const here = dirname(fileURLToPath(import.meta.url));

describe("Intervention I5 — database-bound tenant identity (matched arms)", () => {
  let app: Pool;
  let admin: Pool;
  let report: I5Report;

  beforeAll(async () => {
    const cfg = i5Config();
    app = appPool(cfg);
    admin = adminPool(cfg);
    report = await runI5(app, admin);
  });

  afterAll(async () => {
    await app?.end();
    await admin?.end();
  });

  it("I5-A reproduces GAP-5 — the app re-keys app.current_tenant and reads foreign rows", () => {
    const a = report.arms.find((x) => x.arm === "I5-A")!;
    expect(a.arbitrary_rekey_success).toBe(true);
    expect(a.cross_tenant_observation).toBeGreaterThan(0);
    expect(a.false_permit).toBe(1);
    expect(a.valid_same_tenant_success).toBe(true);
  });

  it("I5-B neutralises the re-key — a foreign GUC re-key (even with a forged lock) reads nothing", () => {
    const b = report.arms.find((x) => x.arm === "I5-B")!;
    expect(b.arbitrary_rekey_success).toBe(false);
    expect(b.cross_tenant_observation).toBe(0);
    expect(b.missing_context_denied).toBe(true);
    expect(b.false_permit).toBe(0);
    expect(b.valid_same_tenant_success).toBe(true);
  });

  it("I5-C binds the caller to a verified session and audits establishment", () => {
    const c = report.arms.find((x) => x.arm === "I5-C")!;
    expect(c.arbitrary_rekey_success).toBe(false);
    expect(c.caller_tenant_binding_violation).toBe(0);
    expect(c.stale_mapping_accepted).toBe(0);
    expect(c.false_permit).toBe(0);
    expect(c.evidence_completeness).toBe(1);
    expect(c.connection_reuse_isolation_failure).toBe(0);
  });

  it("every malicious probe is blocked under both bound arms", () => {
    for (const arm of report.arms.filter((x) => x.arm !== "I5-A")) {
      for (const p of arm.probes.filter((x) => x.malicious && x.applies)) {
        expect(p.blocked, `${arm.arm} ${p.id} ${p.name}: ${p.detail}`).toBe(true);
      }
    }
  });

  it("no arm falsely denies the valid same-tenant query", () => {
    for (const a of report.arms) {
      expect(a.false_deny, `${a.arm} false_deny`).toBe(0);
      expect(a.valid_same_tenant_success, `${a.arm} valid`).toBe(true);
    }
  });

  it("records the superuser-bypass boundary honestly (documented non-goal)", () => {
    expect(report.superuser_bypass_documented).toBe(true);
  });

  it("writes the I5 matched-arm report", () => {
    const dir = join(here, "..");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "report.json"), JSON.stringify(report, null, 2) + "\n");
    expect(report.passed).toBe(true);
  });
});
