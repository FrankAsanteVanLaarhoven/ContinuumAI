/**
 * S4B deterministic fixture code exchanger (TEST/DEV ONLY — refused in production).
 * It NEVER contacts a real provider or token endpoint. Tests register a code with
 * the identity token a provider would return (or a forced failure class) plus the
 * bindings the provider would check, and it records the last exchange input so a
 * test can assert the exact persisted PKCE verifier reached the exchange step.
 */
import type {
  AuthorizationCodeExchangeFailure,
  AuthorizationCodeExchangeInput,
  AuthorizationCodeExchangeResult,
  AuthorizationCodeExchanger,
} from "./authz-types";

export interface FixtureCodeEntry {
  /** Returned on success (an id_token JWT the S4A verifier will verify). */
  readonly identityToken?: string;
  /** Force a specific exchange failure instead of returning a token. */
  readonly forceFailure?: AuthorizationCodeExchangeFailure;
  /** Provider-side binding checks (deny if the exchange input disagrees). */
  readonly expectIssuer?: string;
  readonly expectClientId?: string;
  readonly expectRedirectUri?: string;
  /** Return an unexpected token type (to exercise unexpected_token_type). */
  readonly tokenType?: "id_token" | "other";
}

export class FixtureAuthorizationCodeExchanger implements AuthorizationCodeExchanger {
  private readonly entries = new Map<string, FixtureCodeEntry>();
  private readonly used = new Set<string>();
  /** The most recent exchange input (tests assert the persisted verifier reached here). */
  lastInput: AuthorizationCodeExchangeInput | null = null;

  register(code: string, entry: FixtureCodeEntry): void {
    this.entries.set(code, entry);
  }

  async exchange(input: AuthorizationCodeExchangeInput): Promise<AuthorizationCodeExchangeResult> {
    this.lastInput = input;
    const e = this.entries.get(input.code);
    if (!e) return deny("invalid_code");
    if (e.forceFailure) return deny(e.forceFailure);
    if (e.expectIssuer !== undefined && e.expectIssuer !== input.issuer) return deny("issuer_mismatch");
    if (e.expectClientId !== undefined && e.expectClientId !== input.clientId) return deny("client_mismatch");
    if (e.expectRedirectUri !== undefined && e.expectRedirectUri !== input.redirectUri) return deny("redirect_uri_mismatch");
    if (this.used.has(input.code)) return deny("code_already_used");
    this.used.add(input.code);
    if (e.tokenType === "other") return deny("unexpected_token_type");
    if (!e.identityToken) return deny("missing_identity_token");
    return { ok: true, identityToken: e.identityToken, tokenType: "id_token" };
  }
}

function deny(reason: AuthorizationCodeExchangeFailure): AuthorizationCodeExchangeResult {
  return { ok: false, reason };
}
