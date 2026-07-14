/**
 * Wall-clock-independence regression (guards the v0.1 → v0.2 C1 defect).
 *
 * The corrected C1 harness supplies the benchmark's logical `NOW` to every
 * intended-live operation, so its verdicts must not depend on the host wall
 * clock. This test proves that by running C1 while `Date.now()` reports host
 * times an hour, a day, and a year away from issuance — the semantic verdicts
 * (via `verdict()`, which excludes latency) must be identical every time.
 *
 * It is also the guard the review required: if any intended-live case ever again
 * calls a time-aware API WITHOUT an explicit logical time, its capability will
 * expire under the advanced host clock and its verdict will flip — failing here.
 *
 * NOTE: stubbing `Date.now` is a TEST-ONLY device to simulate a host clock; the
 * FIX itself uses explicit time injection, never monkey-patching.
 */
import { describe, it, expect, afterEach } from "vitest";
import { runC1 } from "./c1";
import { verdict } from "./records";
import { NOW } from "./harness";

const realNow = Date.now;

function verdictsAt(hostNowMs: number): Record<string, unknown>[] {
  globalThis.Date.now = () => hostNowMs;
  try {
    return runC1().map(verdict);
  } finally {
    globalThis.Date.now = realNow;
  }
}

describe("C1 wall-clock independence (benchmark v0.2 correction)", () => {
  afterEach(() => {
    globalThis.Date.now = realNow;
  });

  const HOUR = 3600_000;
  const DAY = 24 * HOUR;
  const reference = verdictsAt(NOW); // logical issuance instant

  it("produces identical C1 verdicts regardless of the host clock", () => {
    for (const offset of [0, HOUR, DAY, 365 * DAY, -DAY]) {
      const at = verdictsAt(NOW + offset);
      expect(at, `host clock NOW${offset >= 0 ? "+" : ""}${offset}ms`).toEqual(reference);
    }
  });

  it("keeps every intended-valid control passing under a host clock a day past TTL", () => {
    const at = runC1WithHost(NOW + DAY);
    const validControls = at.filter((r) => r.control !== "adversarial");
    expect(validControls.every((r) => r.observed_outcome === "valid_pass")).toBe(true);
  });

  it("still denies the deliberate expiry case (C1-08) — expiry is real and checked", () => {
    // C1-08 advances its OWN clock past TTL on purpose; it must stay 'held'.
    const at = runC1WithHost(NOW);
    const expiryCase = at.find((r) => r.case_id.startsWith("C1-08") && r.control === "adversarial");
    expect(expiryCase?.observed_outcome).toBe("held");
  });
});

function runC1WithHost(hostNowMs: number) {
  globalThis.Date.now = () => hostNowMs;
  try {
    return runC1();
  } finally {
    globalThis.Date.now = realNow;
  }
}
