/**
 * Deterministic local authorization server (TEST/DEV ONLY — refused in production
 * by `assertProductionBrowserAuthConfig`). It stands in for the browser's redirect
 * to a real identity provider: given the authorization-request URL produced by the
 * login route, it simulates the provider's decision and returns the callback query
 * the browser would arrive with, registering the code with the fixture exchanger so
 * that `complete()` runs the REAL S4A verification + nonce/issuer binding + mapping
 * path. It never mints a session directly and never bypasses verification.
 */
import type { FixtureAuthorizationCodeExchanger } from "../identity/fixture-exchanger";
import { mintJwt, type TestIssuerKey } from "../identity/jwt-test-support";

export type LocalAuthzScenario =
  | "success"
  | "user_denied"
  | "wrong_state"
  | "missing_code"
  | "duplicate_code"
  | "wrong_issuer"
  | "wrong_nonce"
  | "expired_transaction"
  | "code_reuse"
  | "malformed_token"
  | "exchanger_outage"
  | "delayed_response";

export interface LocalAuthzResult {
  /** The callback query the browser would arrive with. Feed into `controller.callback`. */
  readonly callbackQuery: Record<string, string | string[]>;
  /** The code issued (for tests that drive reuse/replay explicitly). */
  readonly code: string | null;
}

export interface LocalAuthorizationServerOptions {
  readonly exchanger: FixtureAuthorizationCodeExchanger;
  /** issuer → signing key. Must include the primary issuer; add alternates for
   *  issuer-mismatch scenarios. */
  readonly keys: Readonly<Record<string, TestIssuerKey>>;
  readonly primaryIssuer: string;
  /** Alternate issuer used by the `wrong_issuer` scenario (must be present in keys). */
  readonly alternateIssuer?: string;
}

export interface AuthorizeOptions {
  readonly scenario?: LocalAuthzScenario;
  /** The test's current time (the minted token's iat/exp are placed around it). */
  readonly now: Date;
  readonly subject?: string;
}

export class DeterministicLocalAuthorizationServer {
  private readonly o: LocalAuthorizationServerOptions;
  private counter = 0;

  constructor(opts: LocalAuthorizationServerOptions) {
    this.o = opts;
    if (!opts.keys[opts.primaryIssuer]) throw new Error("primary issuer key is required");
  }

  /** Simulate the provider's handling of an authorization request. */
  async authorize(authorizationRedirectUrl: string, opts: AuthorizeOptions): Promise<LocalAuthzResult> {
    const scenario = opts.scenario ?? "success";
    const u = new URL(authorizationRedirectUrl);
    const clientId = u.searchParams.get("client_id") ?? "";
    const state = u.searchParams.get("state") ?? "";
    const nonce = u.searchParams.get("nonce") ?? "";
    const subject = opts.subject ?? "user-1";
    const code = `code_${this.counter++}`;
    const nowSec = Math.floor(opts.now.getTime() / 1000);

    const mint = async (issuer: string, over: Record<string, unknown> = {}): Promise<string> => {
      const key = this.o.keys[issuer];
      if (!key) throw new Error(`no signing key for issuer ${issuer}`);
      return mintJwt(key, { iss: issuer, sub: subject, aud: clientId, iat: nowSec - 10, exp: nowSec + 600, nonce, ...over });
    };

    switch (scenario) {
      case "user_denied":
        return { callbackQuery: { error: "access_denied", state }, code: null };

      case "missing_code":
        await this.o.exchanger.register(code, { identityToken: await mint(this.o.primaryIssuer) });
        return { callbackQuery: { state }, code };

      case "duplicate_code":
        this.o.exchanger.register(code, { identityToken: await mint(this.o.primaryIssuer) });
        return { callbackQuery: { code: [code, code], state }, code };

      case "wrong_state":
        this.o.exchanger.register(code, { identityToken: await mint(this.o.primaryIssuer) });
        return { callbackQuery: { code, state: `${state}TAMPER` }, code };

      case "wrong_nonce":
        this.o.exchanger.register(code, { identityToken: await mint(this.o.primaryIssuer, { nonce: "__wrong_nonce__" }) });
        return { callbackQuery: { code, state }, code };

      case "wrong_issuer": {
        const alt = this.o.alternateIssuer;
        if (!alt) throw new Error("wrong_issuer scenario requires an alternateIssuer");
        this.o.exchanger.register(code, { identityToken: await mint(alt) });
        return { callbackQuery: { code, state }, code };
      }

      case "malformed_token":
        this.o.exchanger.register(code, { identityToken: "not-a-valid-jwt" });
        return { callbackQuery: { code, state }, code };

      case "exchanger_outage":
        this.o.exchanger.register(code, { forceFailure: "token_endpoint_unavailable" });
        return { callbackQuery: { code, state }, code };

      case "delayed_response":
        this.o.exchanger.register(code, { forceFailure: "timeout" });
        return { callbackQuery: { code, state }, code };

      case "code_reuse":
        this.o.exchanger.register(code, { forceFailure: "code_already_used" });
        return { callbackQuery: { code, state }, code };

      case "expired_transaction":
      case "success":
      default:
        this.o.exchanger.register(code, { identityToken: await mint(this.o.primaryIssuer) });
        return { callbackQuery: { code, state }, code };
    }
  }
}
