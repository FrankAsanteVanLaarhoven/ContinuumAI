/**
 * S4A JWKS source abstraction (provider-neutral) + validation + an in-memory
 * fixture source. Every source — in-memory fixture and the HTTP source — runs
 * key sets through the SAME validation (`validateJwks`) so bounds and key-type
 * rules are identical regardless of transport. No source ever accepts private
 * key material in a public key set.
 */
import { digestOf } from "../crypto";
import type {
  Jwk,
  JwksLoadOptions,
  JwksLoadResult,
  JwksSnapshot,
  JwksSource,
} from "./jwt-types";

/** Reject any key set that carries private members — a public JWKS must not. */
function hasPrivateMaterial(jwk: Jwk): boolean {
  // RSA/EC private exponent `d`, RSA CRT params, or symmetric `k`.
  return jwk.d !== undefined || jwk.k !== undefined || jwk.p !== undefined || jwk.q !== undefined;
}

export type JwksValidation =
  | { readonly ok: true; readonly keys: readonly Jwk[] }
  | { readonly ok: false; readonly reason: "malformed" | "empty" | "too_large" | "unsupported_key_type" };

/** Validate raw JWKS content against the load options (count, size already bounded upstream). */
export function validateJwks(raw: unknown, options: JwksLoadOptions): JwksValidation {
  if (typeof raw !== "object" || raw === null) return { ok: false, reason: "malformed" };
  const keys = (raw as { keys?: unknown }).keys;
  if (!Array.isArray(keys)) return { ok: false, reason: "malformed" };
  if (keys.length === 0) return { ok: false, reason: "empty" };
  if (keys.length > options.maxKeyCount) return { ok: false, reason: "too_large" };

  const out: Jwk[] = [];
  for (const k of keys) {
    if (typeof k !== "object" || k === null) return { ok: false, reason: "malformed" };
    const jwk = k as Jwk;
    if (typeof jwk.kty !== "string") return { ok: false, reason: "malformed" };
    if (hasPrivateMaterial(jwk)) return { ok: false, reason: "malformed" };
    if (!options.acceptedKeyTypes.includes(jwk.kty)) return { ok: false, reason: "unsupported_key_type" };
    if ((jwk.kty === "EC" || jwk.kty === "OKP")) {
      if (typeof jwk.crv !== "string" || !options.acceptedCurves.includes(jwk.crv)) {
        return { ok: false, reason: "unsupported_key_type" };
      }
    }
    if (jwk.kid !== undefined && typeof jwk.kid !== "string") return { ok: false, reason: "malformed" };
    out.push(jwk);
  }
  return { ok: true, keys: out };
}

/** Build a validated snapshot (shared by all sources). */
export function snapshotFrom(
  issuer: string,
  raw: unknown,
  version: string,
  options: JwksLoadOptions,
): JwksLoadResult {
  const v = validateJwks(raw, options);
  if (!v.ok) return { ok: false, reason: v.reason };
  const digest = digestOf(v.keys);
  const snapshot: JwksSnapshot = { issuer, keys: v.keys, version, digest, fetchedAt: options.at };
  return { ok: true, snapshot };
}

interface FixtureEntry {
  readonly keys: readonly Jwk[];
  readonly version: string;
}

/**
 * In-memory JWKS source for tests and deterministic fixtures. Supports rotation
 * (setKeys with a new version), outage (markUnavailable) and explicit failures.
 */
export class InMemoryJwksSource implements JwksSource {
  private readonly entries = new Map<string, FixtureEntry>();
  private readonly unavailable = new Set<string>();
  private readonly failWith = new Map<string, "refresh_failed" | "too_large" | "malformed" | "empty">();

  setKeys(issuer: string, keys: readonly Jwk[], version: string): void {
    this.entries.set(issuer, { keys, version });
    this.unavailable.delete(issuer);
    this.failWith.delete(issuer);
  }
  markUnavailable(issuer: string): void {
    this.unavailable.add(issuer);
  }
  failWithReason(issuer: string, reason: "refresh_failed" | "too_large" | "malformed" | "empty"): void {
    this.failWith.set(issuer, reason);
  }

  async load(issuer: string, options: JwksLoadOptions): Promise<JwksLoadResult> {
    if (this.unavailable.has(issuer)) return { ok: false, reason: "unavailable" };
    const forced = this.failWith.get(issuer);
    if (forced) return { ok: false, reason: forced };
    const entry = this.entries.get(issuer);
    if (!entry) return { ok: false, reason: "issuer_unknown" };
    return snapshotFrom(issuer, { keys: entry.keys }, entry.version, options);
  }
}
