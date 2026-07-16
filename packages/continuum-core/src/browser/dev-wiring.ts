/**
 * Deterministic browser-auth wiring (DEV/TEST ONLY — production configuration
 * refuses the deterministic-local authorization server, so this is never reached in
 * production). It assembles the real S4B flow (in-memory transaction store + fixture
 * exchanger + real S4A verifier + S3 in-memory session manager) behind the browser
 * controller, plus the deterministic local authorization server, from a resolved
 * BrowserAuthConfig. The console uses this so it need not reach into non-exported
 * test-support to stand up the browser transport in development.
 */
import { randomBytes } from "node:crypto";
import {
  CachedVerificationKeyProvider,
  DEFAULT_JWKS_CACHE_POLICY,
  DEFAULT_JWT_LIMITS,
  DefaultAuthorizationCodeFlow,
  FixtureAuthorizationCodeExchanger,
  InMemoryAuthorizationEventSink,
  InMemoryAuthorizationTransactionStore,
  InMemoryJwksSource,
  JwtIdentityVerifier,
  StaticAuthorizationClientRegistry,
  TestProtectedSecretStore,
  type JwtIssuerPolicy,
  type PrincipalMapper,
  type VerifiedIdentity,
} from "../identity";
import { generateIssuerKey } from "../identity/jwt-test-support";
import type { SessionDigestKeys } from "../identity/session-digest";
import type { BrowserAuthConfig } from "./config";
import { BrowserAuthController } from "./controller";
import { InMemoryBrowserAuthEventSink } from "./events";
import { DeterministicLocalAuthorizationServer } from "./local-authz-server";
import { makeRouteClassifier } from "./middleware";
import { InMemorySessionManager } from "./session-memory";

export interface DeterministicBrowserAuthOptions {
  readonly config: BrowserAuthConfig;
  readonly clientId?: string;
  readonly scope?: string;
  readonly authorizationEndpoint?: string;
  readonly publicRoutes?: readonly string[];
  readonly mapper?: PrincipalMapper;
  readonly sessionDigestKeys?: SessionDigestKeys;
  readonly clock?: { now: Date };
}

export interface DeterministicBrowserAuth {
  readonly controller: BrowserAuthController;
  readonly local: DeterministicLocalAuthorizationServer;
  readonly sessions: InMemorySessionManager;
  readonly browserSink: InMemoryBrowserAuthEventSink;
}

/** Permissive dev mapper: every verified (issuer, subject) maps to an active dev
 *  principal. A completed login still carries NO tenant authority. */
const DEV_MAPPER: PrincipalMapper = {
  async resolve(identity: VerifiedIdentity) {
    return { mapped: true, principal: { principalId: `dev-${identity.subject}`, version: 1 }, mappingVersion: "dev" };
  },
};

export async function createDeterministicBrowserAuth(opts: DeterministicBrowserAuthOptions): Promise<DeterministicBrowserAuth> {
  const { config } = opts;
  if (config.production) throw new Error("deterministic browser-auth wiring is refused in production");

  const clientId = opts.clientId ?? "continuum-console";
  const authorizationEndpoint = opts.authorizationEndpoint ?? "https://authz.local/authorize";
  const redirectUri = `${config.origin.value}${config.callbackPath}`;
  const clock = opts.clock ?? { now: new Date() };
  const sessionDigestKeys = opts.sessionDigestKeys ?? { currentVersion: "dev", keys: { dev: randomBytes(32).toString("base64") } };

  const issuerKey = await generateIssuerKey("ES256", "dev-1");
  const source = new InMemoryJwksSource();
  source.setKeys(config.issuer, [issuerKey.publicJwk], "v1");

  const issuerPolicy: JwtIssuerPolicy = {
    issuer: config.issuer, audiences: [clientId], allowedAlgorithms: ["ES256"], keyProviderId: "kp", enabled: true,
    requireSubject: true, requireIssuedAt: true, requireExpiration: true, requireNonceWhenExpected: false,
    maximumCredentialAgeSeconds: 3600, maximumClockSkewSeconds: 60, replayPolicy: "none", policyVersion: "dev-idp",
  };
  const verifier = new JwtIdentityVerifier({
    policy: { issuers: [issuerPolicy], limits: DEFAULT_JWT_LIMITS },
    keyProvider: new CachedVerificationKeyProvider({ source, cachePolicy: DEFAULT_JWKS_CACHE_POLICY }),
  });

  const exchanger = new FixtureAuthorizationCodeExchanger();
  const sessions = new InMemorySessionManager({ keys: sessionDigestKeys, clock: () => clock.now });
  const browserSink = new InMemoryBrowserAuthEventSink();

  const flow = new DefaultAuthorizationCodeFlow({
    store: new InMemoryAuthorizationTransactionStore(),
    exchanger,
    verifier,
    mapper: opts.mapper ?? DEV_MAPPER,
    sessions,
    sink: new InMemoryAuthorizationEventSink(),
    secrets: new TestProtectedSecretStore({ currentVersion: "p1", keys: { p1: randomBytes(32).toString("base64") } }),
    clients: new StaticAuthorizationClientRegistry([
      { issuer: config.issuer, clientId, redirectUri, authorizationEndpoint, scope: opts.scope ?? "openid", policyVersion: "dev-authz", enabled: true },
    ]),
    digestKey: randomBytes(32).toString("base64"),
    transactionTtlSeconds: 300,
    sessionIdleTtlSeconds: 900,
    sessionAbsoluteTtlSeconds: 3600,
  });

  const controller = new BrowserAuthController({
    config,
    flow,
    sessions,
    sink: browserSink,
    routes: makeRouteClassifier(opts.publicRoutes ?? [config.loginPath, config.callbackPath, "/api/auth/session"]),
    evidenceDigestKey: randomBytes(32).toString("base64"),
  });

  const local = new DeterministicLocalAuthorizationServer({
    exchanger, keys: { [config.issuer]: issuerKey }, primaryIssuer: config.issuer,
  });

  return { controller, local, sessions, browserSink };
}
