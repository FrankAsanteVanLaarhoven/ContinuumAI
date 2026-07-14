/**
 * Canonical request-digest discipline (review requirement).
 *
 * The I6-C conflict decision is only as sound as the request digest. These tests
 * pin what the canonicalisation guarantees (so a regression is caught) AND the
 * boundaries it deliberately leaves to the caller (unicode/case normalisation),
 * documented honestly rather than assumed.
 *
 * Pure functions only (no database) but this file lives in the I6 workspace so the
 * digest under test is exactly the one the arms use.
 */
import { describe, it, expect } from "vitest";
import { canonicalRequestDigest, keyDigest, KEY_DIGEST_VERSION, type ActionRequest } from "./harness";

const BASE: ActionRequest = {
  tenant: "t_acme",
  principal: "spiffe://acme.ai/agents/procurement-agent",
  intent: "int_001",
  operation: "place_order",
  resource: "supplier:apex",
  arguments: { amount_gbp: 1000, sku: "widget" },
  purpose: "procurement",
  capability: "sct_001",
  policy_version: "policy-2026.07.0",
  approval_requirement: "human",
};
const d = (over: Partial<ActionRequest>) => canonicalRequestDigest({ ...BASE, ...over });

describe("I6 canonical request digest - guarantees", () => {
  it("is stable across two calls on the same request", () => {
    expect(d({})).toBe(d({}));
  });

  it("is independent of top-level object key insertion order", () => {
    const a: ActionRequest = { tenant: "t_acme", principal: "p", intent: "i", operation: "op", resource: "r", arguments: {}, purpose: "u", capability: "c", policy_version: "v", approval_requirement: "human" };
    const b: ActionRequest = { approval_requirement: "human", policy_version: "v", capability: "c", purpose: "u", arguments: {}, resource: "r", operation: "op", intent: "i", principal: "p", tenant: "t_acme" };
    expect(canonicalRequestDigest(a)).toBe(canonicalRequestDigest(b));
  });

  it("is independent of nested-argument key order", () => {
    expect(d({ arguments: { amount_gbp: 1000, sku: "widget" } })).toBe(d({ arguments: { sku: "widget", amount_gbp: 1000 } }));
  });

  it("treats 1 and 1.0 as identical (same IEEE-754 number)", () => {
    expect(d({ arguments: { amount_gbp: 1000 } })).toBe(d({ arguments: { amount_gbp: 1000.0 } }));
  });

  it("distinguishes a numeric value from its string encoding (materially different)", () => {
    expect(d({ arguments: { amount_gbp: 1000 } })).not.toBe(d({ arguments: { amount_gbp: "1000" } }));
  });

  it("treats array order as semantic (different order -> different digest)", () => {
    expect(d({ arguments: { tags: ["a", "b"] } })).not.toBe(d({ arguments: { tags: ["b", "a"] } }));
  });

  it("distinguishes a present-null field from an omitted one (empty != omitted)", () => {
    expect(d({ arguments: { note: null } })).not.toBe(d({ arguments: {} }));
  });

  it("serialises floats deterministically (pins IEEE-754 representation)", () => {
    const x = 0.1 + 0.2; // 0.30000000000000004
    expect(d({ arguments: { rate: x } })).toBe(d({ arguments: { rate: 0.30000000000000004 } }));
  });
});

describe("I6 canonical request digest - documented caller-normalisation boundaries", () => {
  // These are NOT normalised by the digest. The caller MUST normalise fields where
  // the difference is semantically insignificant (or the digest treats them as
  // materially different requests -> a CONFLICT under I6-C). Pinned so the boundary
  // is explicit and any future normalisation is a deliberate, tested change.
  // Strings are built from char codes so the source stays pure ASCII and the byte
  // difference is unambiguous.
  it("does NOT unicode-normalise (NFC vs NFD differ) - caller must normalise", () => {
    const nfc = "caf" + String.fromCharCode(0x00e9); // precomposed e-acute
    const nfd = "cafe" + String.fromCharCode(0x0301); // e + combining acute
    expect(nfc).not.toBe(nfd); // different byte sequences...
    expect(nfc.normalize("NFC")).toBe(nfd.normalize("NFC")); // ...but the same string once normalised
    expect(d({ resource: nfc })).not.toBe(d({ resource: nfd })); // the digest sees them as different
  });

  it("is case-sensitive (identifier case is the caller's responsibility)", () => {
    expect(d({ operation: "Place_Order" })).not.toBe(d({ operation: "place_order" }));
  });
});

describe("I6 evidence idempotency-key digest", () => {
  it("correlates the same key within a tenant (repeated use is linkable)", () => {
    expect(keyDigest("t_acme", "k1")).toBe(keyDigest("t_acme", "k1"));
  });

  it("is UNLINKABLE across tenants (same raw key -> different digests)", () => {
    expect(keyDigest("t_acme", "k1")).not.toBe(keyDigest("t_globex", "k1"));
  });

  it("distinguishes different keys within a tenant", () => {
    expect(keyDigest("t_acme", "k1")).not.toBe(keyDigest("t_acme", "k2"));
  });

  it("carries a version prefix so the construction can migrate", () => {
    expect(keyDigest("t_acme", "k1").startsWith(KEY_DIGEST_VERSION + ":")).toBe(true);
  });

  it("never contains the raw key", () => {
    expect(keyDigest("t_acme", "super-secret-key")).not.toContain("super-secret-key");
  });
});
