/**
 * GAP-4: restart-safe evidence continuation. A ledger resumed from a durably
 * persisted chain continues the seq + prev_hash from the last envelope, and
 * refuses to adopt a broken or foreign-signed chain (fail-closed) so a corrupted
 * store can never be silently extended.
 */
import { describe, it, expect } from "vitest";
import { EvidenceLedger } from "./evidence";
import { generateEd25519 } from "./crypto";

const POLICY = "policy-2026-07";
const T = Date.parse("2026-07-15T00:00:00.000Z");

function seededChain(keys = generateEd25519(), n = 3) {
  const ledger = new EvidenceLedger(keys.privateKeyPem, keys.publicKeyPem, POLICY);
  for (let i = 0; i < n; i++) {
    ledger.append({ tenant_id: "t_acme", owner_id: "o", principal: "p", event_type: `e${i}`, nowMs: T + i });
  }
  return { keys, entries: ledger.all() };
}

describe("EvidenceLedger.resume (GAP-4 restart-safe continuation)", () => {
  it("continues seq and prev_hash from the persisted chain", () => {
    const { keys, entries } = seededChain();
    const resumed = new EvidenceLedger(keys.privateKeyPem, keys.publicKeyPem, POLICY);

    const v = resumed.resume(entries);
    expect(v.valid).toBe(true);
    expect(resumed.size()).toBe(3);

    const next = resumed.append({ tenant_id: "t_acme", owner_id: "o", principal: "p", event_type: "e3", nowMs: T + 3 });
    expect(next.seq).toBe(3);
    expect(next.prev_hash).toBe(entries[2]!.hash);
    expect(resumed.verifyChain()).toMatchObject({ valid: true, length: 4 });
  });

  it("REFUSES a tampered chain and does not adopt it (fail-closed)", () => {
    const { keys, entries } = seededChain();
    const tampered = entries.map((e) => ({ ...e }));
    tampered[1] = { ...tampered[1]!, event_type: "mutated" };

    const resumed = new EvidenceLedger(keys.privateKeyPem, keys.publicKeyPem, POLICY);
    const v = resumed.resume(tampered);
    expect(v.valid).toBe(false);
    expect(v.broken_at).toBe(1);
    expect(resumed.size()).toBe(0); // not adopted
  });

  it("REFUSES a chain signed by a different platform key", () => {
    const { entries } = seededChain(); // signed by key A
    const other = generateEd25519(); // key B
    const resumed = new EvidenceLedger(other.privateKeyPem, other.publicKeyPem, POLICY);
    const v = resumed.resume(entries);
    expect(v.valid).toBe(false);
    expect(resumed.size()).toBe(0);
  });

  it("resuming an empty chain is a no-op valid start (genesis)", () => {
    const keys = generateEd25519();
    const resumed = new EvidenceLedger(keys.privateKeyPem, keys.publicKeyPem, POLICY);
    expect(resumed.resume([]).valid).toBe(true);
    const first = resumed.append({ tenant_id: "t", owner_id: "o", principal: "p", event_type: "e0", nowMs: T });
    expect(first.seq).toBe(0);
    expect(first.prev_hash).toBe("GENESIS");
  });
});
