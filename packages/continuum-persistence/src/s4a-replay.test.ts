/**
 * Phase 3 S4A — durable replay ledger on real embedded PostgreSQL.
 *
 * Proves atomic insert-first consumption (one acceptance under concurrency),
 * restart-safe denial, (issuer, kind) scoping with no cross-issuer collision,
 * digest-only storage, and least-privilege: the session-service role can verify
 * and prune-by-EXECUTE but cannot directly delete a live entry or reach any
 * tenant surface.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Pool } from "pg";
import { replayDigest, type ReplayConsumeInput } from "@continuum/core";
import { adminPool, sessionPool, type DbConfig } from "./pg";
import { migrate } from "./migrate";
import { PostgresReplayLedger } from "./replay-store";

const DB: DbConfig = { host: "127.0.0.1", port: 55444, database: "continuum_s4a_replay" };
const KEY = Buffer.from("replay-digest-key-0123456789abcdef").toString("base64");
const NOW = Date.parse("2026-07-16T00:00:00.000Z");
const ISS = "https://issuer.test";

let admin: Pool;
let sess: Pool;
let ledger: PostgresReplayLedger;

function entry(over: Partial<ReplayConsumeInput> = {}): ReplayConsumeInput {
  return {
    issuer: ISS, kind: "jti", digest: replayDigest(KEY, ISS, "jti", "jti-1"),
    expiresAt: new Date(NOW + 600_000), requestId: "r", at: new Date(NOW), ...over,
  };
}

beforeAll(async () => {
  const bootstrap = adminPool({ ...DB, database: "continuum" });
  try {
    await bootstrap.query("DROP DATABASE IF EXISTS continuum_s4a_replay");
    await bootstrap.query("CREATE DATABASE continuum_s4a_replay");
  } finally {
    await bootstrap.end();
  }
  await migrate(DB); // through 0006
  admin = adminPool(DB);
  sess = sessionPool(DB);
  ledger = new PostgresReplayLedger(sess);
});

afterAll(async () => {
  await admin.end();
  await sess.end();
});

describe("S4A durable replay ledger", () => {
  it("accepts the first use and rejects the second (durable)", async () => {
    const e = entry({ digest: replayDigest(KEY, ISS, "jti", "one") });
    expect(await ledger.consume(e)).toBe("fresh");
    expect(await ledger.consume(e)).toBe("replayed");
  });

  it("admits exactly one acceptance under concurrent duplicate attempts", async () => {
    const e = entry({ digest: replayDigest(KEY, ISS, "jti", "concurrent") });
    const outcomes = await Promise.all(Array.from({ length: 8 }, () => ledger.consume(e)));
    expect(outcomes.filter((o) => o === "fresh")).toHaveLength(1);
    expect(outcomes.filter((o) => o === "replayed")).toHaveLength(7);
  });

  it("scopes by (issuer, kind) — the same raw identifier under a different issuer does not collide", async () => {
    const a = entry({ issuer: "https://a.test", digest: replayDigest(KEY, "https://a.test", "jti", "shared") });
    const b = entry({ issuer: "https://b.test", digest: replayDigest(KEY, "https://b.test", "jti", "shared") });
    expect(await ledger.consume(a)).toBe("fresh");
    expect(await ledger.consume(b)).toBe("fresh");
  });

  it("preserves denial across a fresh connection pool (restart-safe)", async () => {
    const e = entry({ digest: replayDigest(KEY, ISS, "jti", "restart") });
    expect(await ledger.consume(e)).toBe("fresh");
    const reopened = sessionPool(DB);
    try {
      const ledger2 = new PostgresReplayLedger(reopened);
      expect(await ledger2.consume(e)).toBe("replayed");
    } finally {
      await reopened.end();
    }
  });

  it("stores only the keyed digest — no raw identifier column exists", async () => {
    const digest = replayDigest(KEY, ISS, "nonce", "raw-secret-value");
    await ledger.consume(entry({ kind: "nonce", digest }));
    const row = (await admin.query("SELECT * FROM continuum.replay_ledger WHERE digest=$1", [digest])).rows[0];
    expect(row.digest).toBe(digest);
    expect(Object.keys(row)).not.toContain("nonce");
    expect(Object.keys(row)).not.toContain("value");
    // The raw value never appears in any stored column.
    expect(JSON.stringify(row)).not.toContain("raw-secret-value");
  });

  it("prunes only expired entries via the EXECUTE-only pruner", async () => {
    const past = entry({ digest: replayDigest(KEY, ISS, "jti", "expired"), expiresAt: new Date(NOW - 1000) });
    const live = entry({ digest: replayDigest(KEY, ISS, "jti", "live"), expiresAt: new Date(NOW + 600_000) });
    await ledger.consume(past);
    await ledger.consume(live);
    const removed = await ledger.prune(new Date(NOW));
    expect(removed).toBeGreaterThanOrEqual(1);
    // Live entry survives (still a replay); the expired one was pruned (consumable again).
    expect(await ledger.consume(live)).toBe("replayed");
    expect(await ledger.consume(past)).toBe("fresh");
  });

  it("the session role cannot directly delete a live replay entry", async () => {
    await ledger.consume(entry({ digest: replayDigest(KEY, ISS, "jti", "nodelete") }));
    await expect(sess.query("DELETE FROM continuum.replay_ledger")).rejects.toThrow(/permission denied/i);
  });

  it("the replay role has no tenant path", async () => {
    await expect(sess.query("SELECT * FROM continuum.tenant_memberships")).rejects.toThrow(/permission denied/i);
    await expect(sess.query("SELECT * FROM public.intents")).rejects.toThrow(/permission denied/i);
  });
});
