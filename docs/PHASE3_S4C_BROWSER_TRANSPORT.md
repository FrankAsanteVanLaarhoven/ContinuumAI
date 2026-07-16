# Phase 3 S4C — browser transport & session boundary

Exposes the already-tested S4B authorization-code state machine through a hardened,
framework-neutral browser transport, then binds the resulting S3 session to secure
cookies and CSRF-protected application requests — **without changing the underlying
identity, tenant, or authorization semantics**. A completed login carries no tenant
authority; the browser cookie is never a source of tenant authority. Tenant
resolution remains the S2B trusted database context, keyed on the principal the
middleware resolves — never on the cookie. S2B stays the sole tenant-authority
transition.

**Test-scope framing (do not overstate).** S4C drives the browser transport against a
**deterministic local authorization server** (never a real identity provider), the
S4B **fixture** exchanger, and the **test-protected** PKCE store. There is no real
IdP, provider SDK, provider credentials, refresh tokens, workload identity, or
break-glass. Production configuration is refused (fail-closed): the deterministic
authorization server, insecure cookies, a wildcard/missing origin, arbitrary proxy
trust, a missing CSRF key, and the S3/S4A/S4B test implementations all fail closed
with no silent fallback. S4C is a transport-and-session boundary, not secure
production browser login and not production-ready.

## Request flow

```
GET login initiation
  → validate host and configured return target
  → S4B begin()
  → set a short-lived, opaque login-correlation cookie
  → 302 redirect to the (deterministic local) authorization server

GET callback
  → validate host, callback shape and single code/state
  → S4B complete() (atomic consume → exchange → S4A verify → nonce/issuer bind → S3 map)
  → receive a NEW S3 session credential
  → issue a secure session cookie + a session-bound CSRF cookie
  → clear the temporary login cookie
  → 302 redirect to a fixed application destination

authenticated request
  → read session cookie
  → validate the S3 session (NO tenant returned)
  → resolve the trusted principal
  → derive tenant ONLY through S2B (downstream, keyed on the principal)
```

The session cookie is minted **only after** `complete()` fully succeeds. Every failure
path issues no session and clears the temporary login cookie.

## Routes (`@continuum/core/browser` controller + thin Next.js adapters)

```
GET  /api/auth/login      begin + redirect to the authorization server
GET  /api/auth/callback   consume + verify + issue the session cookie
POST /api/auth/logout     CSRF-protected, revokes server-side, idempotent
GET  /api/auth/session    authenticated principal status (reads only)
POST /api/auth/csrf       issue a session-bound CSRF token
```

The controller is framework-neutral (`BrowserRequest → BrowserResponse`); the console
adapters only translate native request/response and serialize cookies. Route names are
provider-neutral (no provider-specific callback names or SDK hooks).

## Session cookie

An opaque S3 credential (`${sessionId}.${secret}`) — **only** the credential, never a
tenant id, role, principal detail, authorization state, provider claim, or a
client-side expiry decision. Production attributes:

```
HttpOnly
Secure
SameSite=Lax
Path=/
Max-Age bounded by the absolute server-side session expiry
```

Host-only (no `Domain`) with the secure prefix `__Host-continuum_session` in production;
`serializeSetCookie` enforces the `__Host-` contract (Secure + Path=/ + no Domain).
Every authenticated request revalidates the server-side session; the cookie is never
trusted for expiry, identity, or authority on its own.

## Cookie lifecycle

- A NEW session (and cookie) after successful authentication (fixation-resistant — S4B
  always mints a new session; no pre-auth credential is upgraded).
- Rotation (new cookie) after reauthentication / privilege / tenant-context change,
  **preserving the absolute expiry** and immediately invalidating the old session
  (`rotated` — never both active).
- Logout revokes the server-side session **before** clearing the cookie.
- An invalid / expired / revoked / stale session clears the cookie; a genuinely missing
  cookie has nothing to clear; a session-store outage fails closed **without** clearing
  (it does not destroy a possibly-valid session).
- Cookie expiry never exceeds the absolute server-side session expiry.

Logout never relies on deleting the browser cookie alone.

## Login-transaction cookie

A short-lived, HttpOnly, opaque **correlation** reference (the S4B transaction id),
distinct from the authorization `state`. It carries no PKCE verifier, code, raw state,
raw nonce, issuer claim, or token material — S4B's protected server-side transaction
remains authoritative (`state` is the binding). It is cleared at the callback on both
success and failure.

## Origin & host validation

Redirect targets and post-login destinations are NEVER derived from arbitrary request
headers. Validated before constructing redirects or accepting state-changing requests:

- expected external origin (`CONTINUUM_EXTERNAL_ORIGIN`, exact, wildcards rejected);
- host against the configured origin;
- forwarded `X-Forwarded-Host`/`-Proto` honoured **only** in explicit trusted-proxy mode
  (`CONTINUUM_TRUST_PROXY=true`); ignored otherwise;
- conflicting/duplicate forwarded values rejected;
- exact callback URI; mismatched scheme rejected;
- a post-login `returnTo` restricted to an **allowlisted RELATIVE** path (absolute,
  protocol-relative `//host`, and backslash smuggling rejected). The callback itself
  redirects to a fixed application destination.

**Proxy-trust boundary (not deployment-grade).** `CONTINUUM_TRUST_PROXY` is an explicit
on/off flag that decides whether `X-Forwarded-Host`/`-Proto` are honoured at all; when
off they are ignored entirely. It does **not** implement immediate-peer / source-address
validation (i.e. it does not verify that the forwarded headers came from a specific
trusted proxy IP). Production-grade forwarded-header trust — pinning the trusted proxy
by source address / connection — is out of scope for this deterministic milestone and
must be added before relying on forwarded headers in a deployed environment. Do not read
this as deployment-grade reverse-proxy validation.

## Callback handling

Accepts exactly one `code` and one `state` (duplicates rejected), enforces S4B input
limits, never reflects raw query parameters into the body/error, atomically consumes
the transaction, mints the cookie only on full success, clears temporary cookies on
terminal failure, and returns generic error classes (`invalid_request` /
`authentication_failed` / `access_denied`). The raw callback URL is never logged (it
carries bearer secrets) and error bodies never echo caller inputs.

## CSRF model

A session-bound, keyed **double-submit** token: `nonce.HMAC(csrfKey, "csrf:"+sessionId+":"+nonce)`.
The non-HttpOnly CSRF cookie value is echoed by the client in the
`x-continuum-csrf` header; the server verifies (a) the double-submit cookie==header
equality, (b) the keyed, session-bound MAC (constant-time), and (c) the request origin.
Because the MAC is bound to the session id, a token cannot be forged without the key,
cannot be transplanted onto another session, and is invalidated by rotation (a new
session id yields a different MAC). Safe GET routes never mutate state; login CSRF is
prevented by S4B state/nonce/transaction binding — the OAuth `state` is never conflated
with application CSRF.

## Authenticated middleware

`authenticate()` returns one normalized result and **never returns tenant authority**:

```ts
type BrowserAuthenticationResult =
  | { authenticated: true; session: ValidatedSession; principalId: PrincipalId }
  | { authenticated: false; reason:
        "missing_cookie" | "malformed_cookie" | "session_unknown" | "session_expired"
      | "session_revoked" | "session_stale" | "session_store_unavailable" };
```

Route classification is **default-protected** over an exact-match public allowlist — a
newly added, unclassified route is protected, never accidentally public (no
prefix/wildcard rule). A missing cookie is unauthenticated; a malformed cookie denies
and clears; a store outage fails closed; the raw cookie is never logged.

## Logout

Validates host + origin, requires a valid session-bound CSRF token for the authenticated
POST, revokes the server-side session, records evidence, then clears the session and
CSRF cookies. A failed CSRF check never revokes. **If revocation storage is unavailable
the operation fails closed (503) and does NOT clear the cookie** — it never claims logout
while leaving the server-side credential active. Logout is idempotent: a repeat with no
active session (or an already-revoked one) still succeeds without restoring authority.

## Security headers

Auth responses carry `Content-Security-Policy` (with `frame-ancestors 'none'`),
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, a restrictive
`Permissions-Policy`, and `Cache-Control: no-store`. HSTS is emitted **only** where
HTTPS is guaranteed (production + https origin) — never for local http development.

## Deterministic local authorization server (test/dev only)

Stands in for the browser's redirect to a provider. Given the login redirect URL it
simulates: success, user denial, wrong state, missing/duplicate code, wrong issuer,
wrong nonce, expired transaction, code reuse, malformed token, exchanger outage, and a
delayed/timed-out token endpoint. It registers each code with the fixture exchanger and
mints a real `jose`-signed id token, so `complete()` runs the **genuine** S4A
verification + nonce/issuer binding + S3 mapping path — it never mints a session
directly or bypasses verification. Production configuration refuses it.

## Evidence (redacted)

Recorded: login initiated, callback accepted/denied, browser session issued, session
validation denied, CSRF denied, logout completed, invalid host/origin denied, session
rotated — as safe ids (principal/session) and keyed digests (of the login correlation
reference) only. Never recorded: raw cookies, raw state/code/nonce, PKCE verifier,
identity token, CSRF secret, session credential, or the full callback URL.

## Configuration (fail-closed)

```
CONTINUUM_BROWSER_AUTH=enabled
CONTINUUM_AUTH_SERVER=deterministic-local        # production refuses (final fail-closed)
CONTINUUM_EXTERNAL_ORIGIN=https://configured.example
CONTINUUM_TRUST_PROXY=false                        # explicit true|false only
CONTINUUM_SESSION_COOKIE_NAME=__Host-continuum_session
CONTINUUM_AUTH_ISSUER=<registered issuer>
CONTINUUM_AUTH_RETURN_PATHS=/,/app                 # allowlisted RELATIVE paths
CONTINUUM_CSRF_KEY=<base64>
```

Production refuses: the deterministic-local authorization server; an insecure (http)
origin; a session cookie without a secure prefix; a missing CSRF key; a wildcard/missing
origin; arbitrary proxy trust; and — via the composed S3/S4A/S4B guards — the
deterministic identity verifier, fixture exchanger, and test-protected PKCE store. No
silent fallback.

## Tests

Core (`@continuum/core/browser`, deterministic; real S4B/S4A/S3 path via the local
authorization server): config 12 · cookies 7 · csrf 6 · origin 17 · flow 17 · middleware
9 · session-flow 11 · hygiene 3 = **82**. Console (`apps/console`): browser-auth wiring 4
(adapter conversion, deterministic login→callback, fail-closed production).

## Frozen results (unchanged)

core **283** (201 + 82 S4C) · persistence **113** · console **11** (7 + 4 S4C) ·
concurrency 9 (pinned `0003`) · stage-a 6 · stage-b 7 · i1–i7 6/8/6/6/7/22/8 · comparative
44 · typecheck clean. S4C adds no migration and no dependency; it changes no S1/S2/S2B/
S3/S4A/S4B source or test.

## Supported vs unsupported claims

**Supported (bounded to the deterministic local environment):** a browser-facing
authentication transport with tested cookie, CSRF, origin, redirect, and session
controls — secure session cookies (HttpOnly/Secure/SameSite/`__Host-`/bounded/opaque, no
tenant embedded; incompatible secure-prefix configuration refused at startup); rotation
preserving absolute expiry with the old session invalidated; CSRF-protected,
origin-checked, idempotent logout revoking server-side and failing closed if revocation
storage is unavailable; session-bound keyed CSRF; default-protected exact-match route
classification; host/forwarded/return-target validation with no open redirect; a
completed login that carries no tenant authority (tenant still via S2B); redacted
evidence; and fail-closed production configuration. This is *not* evidence of secure
operation behind a real reverse proxy, CDN, load balancer, TLS terminator, or deployed
browser origin.

**Not supported (do not claim):** a real identity provider / token endpoint (the
authorization server is a deterministic local test double and the exchanger is a
fixture); interactive production browser login; refresh tokens; KMS/HSM-backed PKCE
custody; workload identity; break-glass; cross-region/cross-deployment session
consistency; resistance to a database-superuser or privileged session-role compromise;
production-scale latency; penetration-tested authentication; or production readiness.
