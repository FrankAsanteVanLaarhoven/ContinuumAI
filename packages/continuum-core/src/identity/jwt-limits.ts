/**
 * S4A hard input limits — applied to the opaque assertion BEFORE structural
 * parsing and BEFORE any remote key resolution, so an attacker cannot drive
 * unbounded work (large payloads, JWKS refresh amplification) with a crafted
 * assertion. Per-claim caps (audience count, method count, string lengths) are
 * enforced later, during claims validation, once the payload is parsed.
 */
import type { JwtInputLimits, JwtVerificationFailure } from "./jwt-types";

export interface AssertionEnvelope {
  readonly headerSegment: string;
  readonly payloadSegment: string;
  readonly signatureSegment: string;
  readonly signingInput: string;
  readonly headerBytes: Buffer;
  readonly payloadBytes: Buffer;
}

export type EnvelopeResult =
  | { readonly ok: true; readonly envelope: AssertionEnvelope }
  | { readonly ok: false; readonly reason: Extract<JwtVerificationFailure, "assertion_too_large" | "malformed_jwt"> };

const BASE64URL = /^[A-Za-z0-9_-]+$/;

/**
 * Validate the compact JWS envelope against the size limits and return the raw
 * segments + decoded header/payload bytes. Rejects oversized or structurally
 * malformed input without parsing JSON or touching the network.
 */
export function enforceAssertionEnvelope(assertion: string, limits: JwtInputLimits): EnvelopeResult {
  if (typeof assertion !== "string" || assertion.length === 0) return { ok: false, reason: "malformed_jwt" };
  if (assertion.length > limits.maxAssertionLength) return { ok: false, reason: "assertion_too_large" };

  const parts = assertion.split(".");
  if (parts.length !== 3) return { ok: false, reason: "malformed_jwt" };
  const [h, p, sig] = parts as [string, string, string];
  if (h.length === 0 || p.length === 0 || sig.length === 0) return { ok: false, reason: "malformed_jwt" };
  if (!BASE64URL.test(h) || !BASE64URL.test(p) || !BASE64URL.test(sig)) return { ok: false, reason: "malformed_jwt" };

  let headerBytes: Buffer;
  let payloadBytes: Buffer;
  try {
    headerBytes = Buffer.from(h, "base64url");
    payloadBytes = Buffer.from(p, "base64url");
  } catch {
    return { ok: false, reason: "malformed_jwt" };
  }
  if (headerBytes.length === 0 || payloadBytes.length === 0) return { ok: false, reason: "malformed_jwt" };
  if (headerBytes.length > limits.maxHeaderBytes) return { ok: false, reason: "assertion_too_large" };
  if (payloadBytes.length > limits.maxPayloadBytes) return { ok: false, reason: "assertion_too_large" };

  return {
    ok: true,
    envelope: {
      headerSegment: h,
      payloadSegment: p,
      signatureSegment: sig,
      signingInput: `${h}.${p}`,
      headerBytes,
      payloadBytes,
    },
  };
}

/** True when every string is within the configured maximum length. */
export function withinStringLimit(limits: JwtInputLimits, ...values: (string | null | undefined)[]): boolean {
  return values.every((v) => v == null || v.length <= limits.maxStringLength);
}
