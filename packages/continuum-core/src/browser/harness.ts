/**
 * S4C browser-transport TEST HARNESS (not exported from the package index). Wires
 * the real S4B flow (in-memory store + fixture exchanger + real S4A verifier + S3
 * in-memory session manager) behind the browser controller, plus the deterministic
 * local authorization server. Mirrors the S4B core-test topology so the browser
 * surface is exercised over the genuine authorization-code path — never a bypass.
 */
import { randomUUID } from "node:crypto";
import {
  BrowserAuthController,
  DeterministicLocalAuthorizationServer,
  InMemoryBrowserAuthEventSink,
  InMemorySessionManager,
  makeRouteClassifier,
  resolveBrowserAuthConfig,
  type BrowserAuthConfig,
  type BrowserRequest,
} from "./index";
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
  type JwtVerificationPolicy,
  type PrincipalMapper,
  type VerifiedIdentity,
} from "../identity";
import { generateIssuerKey, type TestIssuerKey } from "../identity/jwt-test-support";

export const NOW = new Date("2026-07-16T00:00:00.000Z");
export const HOST = "app.example";
export const ORIGIN = "https://app.example";
export const ISS = "https://issuer.test";
export const ISS2 = "https://other.test";
export const CLIENT = "client-web";
const DIGEST_KEY = Buffer.from("browser-digest-key-0123456789abc").toString("base64");
const CSRF_KEY = Buffer.from("browser-csrf-key-0123456789abcde").toString("base64");
const EVIDENCE_KEY = Buffer.from("browser-evidence-key-0123456789a").toString("base64");
const SESSION_DIGEST_KEYS = { currentVersion: "v1", keys: { v1: Buffer.from("session-digest-key-0123456789abc").toString("base64") } };
const SECRET_KEYS = { currentVersion: "p1", keys: { p1: Buffer.from("protected-secret-key-32byteslong").toString("base64") } };

let keyCache: Promise<{ k1: TestIssuerKey; k2: TestIssuerKey }> | null = null;
function keys(): Promise<{ k1: TestIssuerKey; k2: TestIssuerKey }> {
  if (!keyCache) {
    keyCache = (async () => ({ k1: await generateIssuerKey("ES256", "k1"), k2: await generateIssuerKey("ES256", "k2") }))();
  }
  return keyCache;
}

function jwtPolicy(): JwtVerificationPolicy {
  const mk = (issuer: string): JwtIssuerPolicy => ({
    issuer, audiences: [CLIENT], allowedAlgorithms: ["ES256"], keyProviderId: "kp", enabled: true,
    requireSubject: true, requireIssuedAt: true, requireExpiration: true, requireNonceWhenExpected: false,
    maximumCredentialAgeSeconds: 3600, maximumClockSkewSeconds: 60, replayPolicy: "none", policyVersion: "idp-v1",
  });
  return { issuers: [mk(ISS), mk(ISS2)], limits: DEFAULT_JWT_LIMITS };
}

const mapper: PrincipalMapper = {
  async resolve(identity: VerifiedIdentity) {
    if (identity.subject === "user-suspended") return { mapped: false, reason: "principal_suspended" };
    if (identity.subject === "user-unmapped") return { mapped: false, reason: "no_mapping" };
    return { mapped: true, principal: { principalId: `P-${identity.subject}`, version: 1 }, mappingVersion: "1" };
  },
};

export interface Harness {
  readonly config: BrowserAuthConfig;
  readonly controller: BrowserAuthController;
  readonly exchanger: FixtureAuthorizationCodeExchanger;
  readonly authzSink: InMemoryAuthorizationEventSink;
  readonly browserSink: InMemoryBrowserAuthEventSink;
  readonly sessions: InMemorySessionManager;
  readonly local: DeterministicLocalAuthorizationServer;
  readonly clock: { now: Date };
}

export interface HarnessOptions {
  readonly env?: Record<string, string | undefined>;
  readonly clock?: { now: Date };
}

export async function buildHarness(opts: HarnessOptions = {}): Promise<Harness> {
  const { k1, k2 } = await keys();
  const clock = opts.clock ?? { now: NOW };
  const config = resolveBrowserAuthConfig({
    NODE_ENV: "development",
    CONTINUUM_BROWSER_AUTH: "enabled",
    CONTINUUM_AUTH_SERVER: "deterministic-local",
    CONTINUUM_EXTERNAL_ORIGIN: ORIGIN,
    CONTINUUM_TRUST_PROXY: "false",
    CONTINUUM_AUTH_ISSUER: ISS,
    CONTINUUM_CSRF_KEY: CSRF_KEY,
    CONTINUUM_AUTH_RETURN_PATHS: "/,/app",
    ...opts.env,
  } as NodeJS.ProcessEnv);

  const store = new InMemoryAuthorizationTransactionStore();
  const exchanger = new FixtureAuthorizationCodeExchanger();
  const authzSink = new InMemoryAuthorizationEventSink();
  const browserSink = new InMemoryBrowserAuthEventSink();
  const source = new InMemoryJwksSource();
  source.setKeys(ISS, [k1.publicJwk], "v1");
  source.setKeys(ISS2, [k2.publicJwk], "v1");
  const verifier = new JwtIdentityVerifier({
    policy: jwtPolicy(), keyProvider: new CachedVerificationKeyProvider({ source, cachePolicy: DEFAULT_JWKS_CACHE_POLICY }),
  });
  const sessions = new InMemorySessionManager({ keys: SESSION_DIGEST_KEYS, clock: () => clock.now });

  const flow = new DefaultAuthorizationCodeFlow({
    store, exchanger, verifier, mapper, sessions, sink: authzSink,
    secrets: new TestProtectedSecretStore(SECRET_KEYS),
    clients: new StaticAuthorizationClientRegistry([
      { issuer: ISS, clientId: CLIENT, redirectUri: `${ORIGIN}${config.callbackPath}`, authorizationEndpoint: "https://authz.local/authorize", scope: "openid", policyVersion: "authz-v1", enabled: true },
    ]),
    digestKey: DIGEST_KEY, transactionTtlSeconds: 300, sessionIdleTtlSeconds: 900, sessionAbsoluteTtlSeconds: 3600,
  });

  const controller = new BrowserAuthController({
    config, flow, sessions, sink: browserSink,
    routes: makeRouteClassifier([config.loginPath, config.callbackPath, "/api/auth/session"]),
    evidenceDigestKey: EVIDENCE_KEY,
  });

  const local = new DeterministicLocalAuthorizationServer({
    exchanger, keys: { [ISS]: k1, [ISS2]: k2 }, primaryIssuer: ISS, alternateIssuer: ISS2,
  });

  return { config, controller, exchanger, authzSink, browserSink, sessions, local, clock };
}

export interface ReqOptions {
  readonly host?: string;
  readonly query?: Record<string, string | string[]>;
  readonly cookies?: Record<string, string>;
  readonly headers?: Record<string, string | string[]>;
  readonly at?: Date;
}

export function mkReq(method: string, path: string, o: ReqOptions = {}): BrowserRequest {
  const headers: Record<string, string | string[]> = { host: o.host ?? HOST, ...(o.headers ?? {}) };
  return { method, path, query: o.query ?? {}, headers, cookies: o.cookies ?? {}, requestId: `req-${randomUUID()}`, receivedAt: o.at ?? NOW };
}

/** Drive a full login → local authz → callback, returning the callback response. */
export async function login(h: Harness, scenario: Parameters<DeterministicLocalAuthorizationServer["authorize"]>[1]["scenario"] = "success", subject?: string) {
  const loginRes = await h.controller.login(mkReq("GET", h.config.loginPath));
  const loginCookie = loginRes.setCookies.find((c) => c.name === h.config.loginCookieName);
  const authz = await h.local.authorize(loginRes.location!, { scenario, now: h.clock.now, ...(subject ? { subject } : {}) });
  const cbRes = await h.controller.callback(
    mkReq("GET", h.config.callbackPath, { query: authz.callbackQuery, cookies: loginCookie ? { [h.config.loginCookieName]: loginCookie.value } : {} }),
  );
  return { loginRes, loginCookie, authz, cbRes };
}
