import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool } from "pg";
import { appPool, adminPool, i6Config } from "./harness";
import { runI6, type I6Report } from "./i6";

const here = dirname(fileURLToPath(import.meta.url));

describe("Intervention I6 — idempotent action identity (matched arms)", () => {
  let app: Pool;
  let admin: Pool;
  let report: I6Report;

  beforeAll(async () => {
    const cfg = i6Config();
    app = appPool(cfg);
    admin = adminPool(cfg);
    report = await runI6(app, admin);
  });

  afterAll(async () => {
    await app?.end();
    await admin?.end();
  });

  it("I6-A reproduces GAP-6 — reused action_id overwrites and retry re-executes", () => {
    const a = report.arms.find((x) => x.arm === "I6-A")!;
    expect(a.silent_overwrite_success).toBe(true);
    expect(a.duplicate_execution).toBeGreaterThan(1);
    expect(a.false_permit).toBeGreaterThanOrEqual(2);
  });

  it("I6-B prevents duplicate creation + execution for identical requests (replay)", () => {
    const b = report.arms.find((x) => x.arm === "I6-B")!;
    expect(b.same_request_replay_accurate).toBe(true);
    expect(b.silent_overwrite_success).toBe(false);
    expect(b.duplicate_execution).toBe(0);
    expect(b.missing_key_denied).toBe(true);
    // B intentionally does NOT detect a same-key/different-request conflict.
    expect(b.different_request_conflict_detection).toBe(0);
  });

  it("I6-C additionally rejects same-key/different-request conflicts", () => {
    const c = report.arms.find((x) => x.arm === "I6-C")!;
    expect(c.different_request_conflict_detection).toBeGreaterThanOrEqual(4);
    expect(c.duplicate_execution).toBe(0);
    expect(c.false_permit).toBe(0);
  });

  it("every malicious probe is blocked under I6-C", () => {
    const c = report.arms.find((x) => x.arm === "I6-C")!;
    for (const p of c.probes.filter((x) => x.malicious)) {
      expect(p.blocked, `I6-C ${p.id} ${p.name}: ${p.detail}`).toBe(true);
    }
  });

  it("no bound arm falsely denies a benign new action; no orphan actions", () => {
    for (const arm of report.arms.filter((x) => x.arm !== "I6-A")) {
      expect(arm.false_deny, `${arm.arm} false_deny`).toBe(0);
      expect(arm.valid_new_action_success, `${arm.arm} benign`).toBe(true);
      expect(arm.orphan_action_rate, `${arm.arm} orphans`).toBe(0);
    }
  });

  it("evidence distinguishes create / replay / conflict under I6-C", () => {
    const c = report.arms.find((x) => x.arm === "I6-C")!;
    expect(c.replay_evidence_complete).toBe(true);
    expect(c.conflict_evidence_complete).toBe(true);
  });

  it("writes the I6 matched-arm report", () => {
    const dir = join(here, "..");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "report.json"), JSON.stringify(report, null, 2) + "\n");
    expect(report.passed).toBe(true);
  });
});
