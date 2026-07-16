/**
 * Phase 3 S4C — authenticated-request middleware contract.
 *
 * The middleware produces ONE normalized result. It resolves the internal principal
 * from a validated S3 session and NEVER returns tenant authority — tenant resolution
 * happens later through the S2B trusted database context, keyed on the principal,
 * never on the browser cookie. Route classification is default-protected: only an
 * explicitly enumerated public path is public, so a newly added route is protected
 * unless deliberately allowlisted.
 */
import type { PrincipalId } from "../async/context";
import type { SessionValidationFailure, ValidatedSession } from "../identity/types";

export type BrowserAuthDenyReason =
  | "missing_cookie"
  | "malformed_cookie"
  | "session_unknown"
  | "session_expired"
  | "session_revoked"
  | "session_stale"
  | "session_store_unavailable";

export type BrowserAuthenticationResult =
  | { readonly authenticated: true; readonly session: ValidatedSession; readonly principalId: PrincipalId }
  | { readonly authenticated: false; readonly reason: BrowserAuthDenyReason };

/** Map an S3 session-validation failure to the middleware deny reason. */
export function mapSessionFailure(failure: SessionValidationFailure): BrowserAuthDenyReason {
  switch (failure) {
    case "malformed_credential":
      return "malformed_cookie";
    case "unknown_session":
    case "digest_mismatch":
      return "session_unknown";
    case "idle_expired":
    case "absolute_expired":
      return "session_expired";
    case "revoked":
    case "rotated":
      return "session_revoked";
    case "principal_inactive":
    case "identity_mapping_stale":
    case "identity_version_stale":
    case "policy_version_stale":
    case "insufficient_strength":
      return "session_stale";
    case "store_unavailable":
      return "session_store_unavailable";
  }
}

/**
 * Whether a deny reason should clear the browser cookies. A transient store outage
 * must NOT clear (fail closed without destroying a possibly-valid session); a
 * genuinely missing cookie has nothing to clear.
 */
export function shouldClearOnDeny(reason: BrowserAuthDenyReason): boolean {
  return (
    reason === "malformed_cookie" ||
    reason === "session_unknown" ||
    reason === "session_expired" ||
    reason === "session_revoked" ||
    reason === "session_stale"
  );
}

/** Default-protected route classifier over an EXACT-match public allowlist. */
export interface RouteClassifier {
  isPublic(path: string): boolean;
}

export function makeRouteClassifier(publicPaths: readonly string[]): RouteClassifier {
  const set = new Set(publicPaths);
  return {
    // Exact match only — never a prefix/wildcard rule that could leak new routes.
    isPublic: (path: string) => set.has(path),
  };
}
