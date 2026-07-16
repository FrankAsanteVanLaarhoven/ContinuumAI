/** S4A — replay digest + in-memory durable replay ledger semantics. */
import { describe, expect, it } from "vitest";
import { InMemoryDurableReplayLedger, replayDigest, type ReplayConsumeInput } from "./index";

const KEY = Buffer.from("replay-digest-key-0123456789abcdef").toString("base64");
const NOW = new Date(Date.parse("2026-07-16T00:00:00.000Z"));
const later = (s: number) => new Date(NOW.getTime() + s * 1000);

function entry(over: Partial<ReplayConsumeInput> = {}): ReplayConsumeInput {
  return { issuer: "https://issuer.test", kind: "jti", digest: "d1", expiresAt: later(600), requestId: "r", at: NOW, ...over };
}

describe("S4A replay digest", () => {
  it("is deterministic and keyed", () => {
    const a = replayDigest(KEY, "iss", "jti", "v");
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(replayDigest(KEY, "iss", "jti", "v")).toBe(a);
  });
  it("does not collide across issuer, kind, or value", () => {
    const base = replayDigest(KEY, "iss-a", "jti", "v");
    expect(replayDigest(KEY, "iss-b", "jti", "v")).not.toBe(base);
    expect(replayDigest(KEY, "iss-a", "nonce", "v")).not.toBe(base);
    expect(replayDigest(KEY, "iss-a", "jti", "w")).not.toBe(base);
  });
});

describe("S4A in-memory durable replay ledger", () => {
  it("accepts the first use and rejects the second", async () => {
    const l = new InMemoryDurableReplayLedger();
    expect(await l.consume(entry())).toBe("fresh");
    expect(await l.consume(entry())).toBe("replayed");
  });

  it("scopes by (issuer, kind, digest) — same digest under a different issuer is fresh", async () => {
    const l = new InMemoryDurableReplayLedger();
    expect(await l.consume(entry({ issuer: "https://a.test" }))).toBe("fresh");
    expect(await l.consume(entry({ issuer: "https://b.test" }))).toBe("fresh");
  });

  it("fails closed when the store is unavailable", async () => {
    const l = new InMemoryDurableReplayLedger();
    l.setAvailable(false);
    expect(await l.consume(entry())).toBe("unavailable");
  });

  it("prunes expired entries and lets a pruned identifier be consumed again", async () => {
    const l = new InMemoryDurableReplayLedger();
    await l.consume(entry({ expiresAt: later(100) }));
    expect(await l.prune(later(200))).toBe(1);
    expect(await l.consume(entry({ expiresAt: later(800) }))).toBe("fresh");
  });
});
