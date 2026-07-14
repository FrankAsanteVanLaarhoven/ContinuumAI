/**
 * Intervention I3 — point-of-use authorization freshness (GAP-3).
 *
 * A capability is a snapshot. The frozen point-of-use path re-checks
 * signature/expiry/revocation/PoP but NOT consent, policy version, the risk
 * ceiling, or object lifecycle — so within the TTL a withdrawn consent, a rotated
 * policy, a tightened risk gate, or a revoked object still authorises disclosure.
 *
 *   off            no re-evaluation (frozen)
 *   version        bind + re-check policy version and a consent digest at use
 *   transactional  version + re-evaluate the risk ceiling and object lifecycle
 *                  against CURRENT state at use
 *
 * `version` is necessary but insufficient (it catches version/consent changes, not
 * a tightened risk gate or a revoked object); `transactional` closes all four.
 */
import { digestOf } from "../crypto";
import { findConsent, type Store } from "../store";

export type FreshnessMode = "off" | "version" | "transactional";

/**
 * Digest of the material consent state for (owner, purpose). Bound into the token
 * at issuance and recomputed at use; any change (withdrawal, basis/validity edit,
 * or absence) yields a different digest.
 */
export function consentDigest(store: Store, ownerId: string, purpose: string): string {
  const c = findConsent(store, ownerId, purpose);
  return digestOf(
    c === null
      ? { present: false }
      : { present: true, granted: c.granted, basis: c.basis, valid_until: c.valid_until },
  );
}
