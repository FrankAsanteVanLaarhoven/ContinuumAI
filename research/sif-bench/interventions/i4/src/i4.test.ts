import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool } from "pg";
import { appPool, adminPool, i4Config } from "./harness";
import { runI4, type I4Report } from "./i4";

const here = dirname(fileURLToPath(import.meta.url));

describe("Intervention I4 — proof-of-possession replay resistance (matched arms)", () => {
  let app: Pool;
  let admin: Pool;
  let report: I4Report;

  beforeAll(async () => {
    const cfg = i4Config();
    app = appPool(cfg);
    admin = adminPool(cfg);
    report = await runI4(app, admin);
  });

  afterAll(async () => {
    await app?.end();
    await admin?.end();
  });

  const arm = (id: string) => report.arms.find((x) => x.arm === id)!;

  it("I4-A reproduces GAP-4 — a captured proof replays and concurrently double-spends", () => {
    const a = arm("I4-A");
    expect(a.replay_accepted).toBe(true);
    expect(a.replay_acceptances).toBe(2);
    expect(a.concurrent_double_spend).toBe(true);
    expect(a.lifted_accepted_count).toBe(3);
  });

  it("I4-B closes replay + concurrent double-spend via single-use consumption", () => {
    const b = arm("I4-B");
    expect(b.replay_accepted).toBe(false);
    expect(b.replay_acceptances).toBe(1);
    expect(b.concurrent_double_spend).toBe(false);
    // B intentionally does NOT bind request/audience/capability → lifts still accepted.
    expect(b.lifted_accepted_count).toBe(3);
  });

  it("I4-C additionally rejects proofs lifted onto a different request/audience/capability", () => {
    const c = arm("I4-C");
    expect(c.replay_accepted).toBe(false);
    expect(c.concurrent_double_spend).toBe(false);
    expect(c.lifted_request_accepted).toBe(false);
    expect(c.lifted_audience_accepted).toBe(false);
    expect(c.lifted_capability_accepted).toBe(false);
    expect(c.lifted_accepted_count).toBe(0);
  });

  it("expiry, non-holder, and missing-proof controls hold under every arm", () => {
    for (const a of report.arms) {
      expect(a.expired_rejected, `${a.arm} expired`).toBe(true);
      expect(a.nonholder_rejected, `${a.arm} nonholder`).toBe(true);
      expect(a.missing_rejected, `${a.arm} missing`).toBe(true);
    }
  });

  it("no arm falsely denies the benign proof", () => {
    for (const a of report.arms) {
      expect(a.false_deny, `${a.arm} false_deny`).toBe(0);
      expect(a.benign_success, `${a.arm} benign`).toBe(true);
    }
  });

  it("writes the I4 matched-arm report", () => {
    const dir = join(here, "..");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "report.json"), JSON.stringify(report, null, 2) + "\n");
    expect(report.passed).toBe(true);
  });
});
