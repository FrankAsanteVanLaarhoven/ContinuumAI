# Phase 3 — Authentication & Trusted Tenant-Resolution: Specification

```
Status:   SPECIFICATION ONLY. No implementation. Held for review. No push, no tag.
Baseline: origin/main = 18af849 (Phase 2 async PostgreSQL runtime path, complete).
Scope:    Define the identity, tenant-resolution, session, delegation, workload,
          break-glass, database-context, fail-closed and audit BOUNDARIES.
Excluded: OIDC/session middleware code, provider SDKs, deployment/secrets config,
          credentials, a custom identity provider. Those follow only after review.
```

This document specifies boundaries. It does **not** implement authentication. It
builds on the Phase 2 async boundary already shipped: `RequestContext`,
`DerivedTenantContext.derivedFrom`, the trusted `ContinuumStore.resolveExecutionContext`,
transaction-local `app.current_tenant` + forced RLS, and the documented GAP-1
(a `SECURITY DEFINER` tenant-derivation function) in `POSTGRES_STORE_AUDIT.md`.

Today the console operator is a **fixed subject** with no authentication. Phase 3
replaces that with real identity → verified principal → active membership → derived
tenant, so tenant authority is never client-selected.

---

## Deliverable 1 — Authentication architecture

Delegated identity, never a home-grown credential store.

- **Humans** authenticate via an external **OIDC** provider (authorization-code +
  PKCE). Continuum verifies tokens; it does not issue passwords.
- **Services / agents / workloads** authenticate via **workload-identity federation**
  (mTLS / SPIFFE-SVID / OIDC workload tokens) with short-lived credentials.
- **Break-glass operators** authenticate via a separate high-assurance path
  (strong reauth + independent notification), never a standing backdoor.

Components (all server-side; none trust unsigned input):

```
External IdP(s) ──► Auth boundary ──► Session tier ──► Principal registry
    (OIDC/JWKS)     (verify tokens,     (server-side/    (verified subject
                     establish session)  crypto session)   → principal record)
                                              │
                                              ▼
                        Membership / delegation store ──► Tenant-resolution service
                        (principal → tenant memberships,      (derives the ONE active
                         scoped time-limited delegations)      tenant for this request)
                                              │
                                              ▼
                        Trusted DB-context function (SECURITY DEFINER)
                        sets transaction-local principal + tenant ──► RLS-protected op
```

The **auth boundary is the only place** that converts an external credential into an
internal `RequestContext`. Application/route code receives an already-derived context
and may never assemble one from request input.

---

## Deliverable 2 — Identity & tenant-resolution data flow

```
1. Caller presents a credential
   (browser: session cookie; service: mTLS/workload token; login: OIDC code)
2. Auth boundary VERIFIES it (signature, issuer, audience, algorithm, exp/nbf/iat,
   nonce/state/PKCE for browser flows). Unsigned or unverifiable ⇒ DENY.
3. Verified (issuer, subject) ⇒ look up the PRINCIPAL record. Missing/suspended/
   deleted ⇒ DENY.
4. Resolve ACTIVE membership/delegation for the principal. None ⇒ DENY.
   A caller-supplied tenant HINT may only SELECT among already-authorized
   memberships; it can never create authority. Ambiguous + no valid hint ⇒ DENY.
5. Derive the DerivedTenantContext (derivedFrom = authenticated_session |
   workload_identity | trusted_delegation) — never research_fixture in production.
6. Begin the transaction; a trusted DB function stamps transaction-local principal
   + tenant; RLS applies; the context disappears at COMMIT/ROLLBACK.
```

The authoritative tenant is **derived**, step 3→5, from verified identity. Steps
1–5 happen inside the auth boundary; steps 6+ inside the store transaction.

**Layer separation (identity validation ≠ database mapping).** Three distinct
layers, and the database **never verifies OIDC tokens**:

```
OIDC / session boundary   verify token or session cryptographically; validate
                          issuer, audience, algorithm, expiry, nonce and auth
                          state; derive a stable external subject.
Application identity svc   map (issuer, subject) → internal principal; resolve the
                          session and the requested membership (internal ids only).
Database                  independently REVALIDATE the internal principal, session
                          and active membership; establish transaction-local tenant
                          context; enforce RLS.
```

The database is passed **internal identifiers obtained after verified authentication**
— never raw browser-forwarded identity claims — and the trusted function confirms
their active relationships itself. The full untrusted token claim object is never
forwarded through the system; only the stable, normalized `VerifiedIdentity` crosses
the boundary.

---

## Deliverable 3 — Trust-boundary diagram

```
  UNTRUSTED                     │  TRUSTED (server)                    │  DATA PLANE
  ─────────                     │  ───────────────                    │  ──────────
  Browser / caller              │  Auth boundary                      │
   • cookie / bearer            │   • OIDC verify (JWKS, alg allowlist)│
   • mTLS / workload token ─────┼──►• session establish/rotate        │
   • tenant HINT (advisory) ────┼─► • principal lookup                │
                                │   • membership/delegation resolve    │
                                │   • tenant DERIVATION ───────────────┼─► SECURITY DEFINER
                                │        (never from request body)     │   set principal+tenant
                                │                                      │   (transaction-local)
                                │  RequestContext (derived)            │        │
                                │        │                             │        ▼
                                │        └── AsyncContinuumEngine ──────┼──► RLS-protected op
                                │                                      │   (app role, NOSUPERUSER,
                                │                                      │    SELECT/INSERT-only)
```

Everything left of the first boundary is untrusted, including any `tenantId` the
caller sends. Authority crosses the boundary only as a **derived** context.

---

## Deliverable 4 — Threat model & misuse cases

Each case names the control that must defeat it. All are required test cases
(Deliverable 13).

| # | Misuse case | Required control |
|---|-------------|------------------|
| T1 | Forged tenant header/body | Tenant is derived from verified identity; request `tenantId` is advisory-only and validated against memberships |
| T2 | Valid token for wrong audience | Audience verification in the OIDC boundary; deny on mismatch |
| T3 | Stale membership after role removal | Membership/delegation re-checked at resolution time; revocation status consulted; stale ⇒ deny |
| T4 | Tenant switch mid-request | Tenant is fixed for the life of the derived context/transaction; a switch requires a new request + session epoch |
| T5 | Session fixation | Session id rotated after authentication and after any privilege/tenant change |
| T6 | Stolen session cookie | Secure/HttpOnly/SameSite; idle+absolute expiry; server-side revocation; reauth for sensitive actions; binding to workload/UA where feasible |
| T7 | CSRF on approve/revoke | SameSite + origin check + per-request anti-CSRF token on all state-changing routes |
| T8 | Confused-deputy delegation | Delegations are explicit, scoped, non-transitive, and bounded by the delegator's authority; capability/PoP still required |
| T9 | Compromised service credential | Short-lived workload creds + audience binding + revocation; blast radius bounded to that workload's memberships |
| T10 | Replayed OIDC callback | state + nonce + PKCE + one-time code exchange; replay ⇒ deny |
| T11 | Malicious IdP claim | Only signed, allowlisted-issuer claims are trusted; roles/tenants are NOT taken from raw IdP claims but resolved from the internal membership store |
| T12 | Break-glass misuse | Reason + narrow duration + strong reauth + notification + immutable evidence + auto-expiry + post-event review |
| T13 | Connection-pool tenant leakage | Transaction-local context only; `SECURITY DEFINER` set; reset on release; proven by a pooled-reuse HTTP test |
| T14 | AuthZ checked before membership revocation | Revocation consulted at point of use; freshness re-check; deny if unresolved |
| T15 | Principal mapped to multiple tenants | Exactly one active tenant derived per request; explicit selection among authorized only; ambiguity ⇒ deny |
| T16 | Deleted/suspended principal | Principal state checked at resolution; not-active ⇒ deny |
| T17 | IdP outage / key-rotation failure | Fail-closed: cannot verify ⇒ deny (see Deliverable 10) |
| T18 | Alg-confusion / `none` alg | Exact algorithm allowlist; reject `none` and asymmetric→symmetric confusion |

---

## Deliverable 5 — Session & CSRF model

- **Session identifier:** server-side record, or a cryptographically signed **and**
  encrypted token; never a bare client-trusted claim.
- **Expiry:** idle timeout **and** absolute lifetime; both enforced server-side.
- **Rotation:** new session id after authentication, after privilege change, and
  after tenant switch (defeats fixation).
- **Cookies:** `Secure`, `HttpOnly`, `SameSite=Lax` (or `Strict` for admin surfaces);
  scoped path; no tenant/role data stored client-side.
- **CSRF:** `SameSite` + strict `Origin`/`Referer` check + a per-request anti-CSRF
  token required on every mutating route (approve, revoke, tenant-switch, break-glass).
- **Reauthentication:** required for sensitive actions (approvals, revocations,
  delegation grants, tenant switch, break-glass).
- **Revocation:** sessions revocable server-side; revocation is immediate.
- **Tenant switch:** re-derives the context and issues a new session epoch; never
  mutates an in-flight request's tenant.
- **Concurrent sessions:** bounded per principal; policy configurable; each session
  independently revocable and independently evidenced.

---

## Deliverable 6 — Role & delegation semantics

Authentication, role membership, and capability authorization are **separate layers**.
A role must **never** bypass intent, consent, capability, freshness, or proof checks.

```
identity      → membership / role → permitted ADMINISTRATIVE surface only
intent/capability                 → resource + purpose authority (deny-by-default)
PoP                               → holder / request / audience binding
freshness                         → point-of-use validity
```

Roles gate *which administrative operations a principal may attempt*; they do not
grant resource access, which always flows through intent → policy → capability → PoP.

**Delegations** must be:

- **explicit** (no implicit inheritance),
- **scoped** (operations/resources/purpose enumerated),
- **time-limited** (bounded validity),
- **revocable** (immediate),
- **non-transitive by default** (no re-delegation unless separately granted),
- **evidenced** (hash-chained grant + revoke events),
- **bounded** — a delegation can never exceed the delegator's own authority.

---

## Deliverable 7 — Workload-identity model

For service and agent workloads (the procurement/billing agents today):

- **mTLS** or **workload-identity federation** (SPIFFE-SVID / federated OIDC),
- **short-lived** credentials (minutes-to-hours, auto-rotated),
- **audience binding** (a credential is valid only for its intended service),
- carries **workload name + deployment identity** and, where available, a **build/image
  digest** (ties to the existing attested `build_hash` allowlist),
- **separated** from human sessions (distinct verification path, distinct evidence),
- **no long-lived shared API keys** in the target architecture.

---

## Deliverable 8 — Break-glass policy

Break-glass is governed emergency access, not a silent bypass. It requires:

- an explicit **reason**,
- a **narrow duration** with **automatic expiry**,
- **strong reauthentication**,
- **independent notification** to a second party,
- **immutable, hash-chained evidence** of open + actions + close,
- mandatory **post-event review**,
- **no bypass of database tenant isolation** unless a *separately governed* recovery
  procedure explicitly requires it,
- **denial of destructive/irreversible actions** unless explicitly permitted for that
  incident.

---

## Deliverable 9 — Database-context establishment contract

The exact trust transition (extends the Phase 2 `withTenant` boundary with GAP-1):

```
validated identity/session
  → resolved principal (active, not suspended/deleted)
  → resolved ACTIVE tenant membership (exactly one, derived — NOT app-supplied)
  → BEGIN transaction
  → trusted SECURITY DEFINER function DERIVES and sets transaction-local context
      (the app role CANNOT set a tenant itself — closes app-cooperative RLS)
  → RLS-protected operation(s)
  → COMMIT / ROLLBACK ⇒ transaction-local context DISAPPEARS
```

**The function is a narrow trusted boundary — not a general privilege.** Its input is
limited to trusted identity/session references; it does **not** accept an authoritative
tenant identifier from the application:

```sql
continuum_begin_authenticated_context(
  p_principal_id            uuid,
  p_session_id              uuid,
  p_request_id              uuid,
  p_requested_membership_id uuid default null   -- SELECTS among the principal's
)                                               -- active memberships; never GRANTS one
```

Internally it MUST:

1. resolve the authenticated principal;
2. validate the principal is active (not suspended/deleted);
3. validate the session is active and belongs to that principal;
4. resolve an active principal→tenant membership;
5. reject ambiguous membership when no explicit authorized selection is supplied;
6. set transaction-local principal, tenant, membership, session, request context;
7. return only non-sensitive derived context metadata.

Hardening (prevents `SECURITY DEFINER` becoming an escalation surface):

- Owned by a **dedicated non-login role** (not the app role, not a superuser).
- Fixed, schema-qualified `search_path`; all tables/functions inside are schema-qualified:
  ```sql
  ALTER FUNCTION continuum_begin_authenticated_context(...)
    SECURITY DEFINER
    SET search_path = pg_catalog, continuum;
  ```
- Default public execution revoked; only the app role may execute it:
  ```sql
  REVOKE ALL ON FUNCTION continuum_begin_authenticated_context(...) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION continuum_begin_authenticated_context(...) TO continuum_app;
  ```
- The application role (`continuum_app`) has **only `EXECUTE`** on this function and
  MUST NOT have: `BYPASSRLS`, `SUPERUSER`, `CREATE` on trusted schemas, direct `UPDATE`
  on memberships, the ability to call `set_config` for trusted authority, or ownership
  of the context function.

Requirements:

- The function is the **only** way to establish request context in production, and it
  **derives** the tenant from the (principal, session, membership) it independently
  revalidates — it never trusts an app-supplied tenant.
- Context is **transaction-local** (`set_config(..., is_local => true)`), never
  session-level:
  `app.current_principal`, `app.current_tenant`, `app.current_membership`,
  `app.current_session`, `app.current_request`.
- **Pooled connections never retain identity/tenant state** — proven today for
  `app.current_tenant` by the pooled-reuse test; Phase 3 extends the same guarantee
  to the principal, membership and session identity.

---

## Deliverable 10 — Fail-closed matrix

| Failure condition | Behaviour |
|-------------------|-----------|
| Identity provider unavailable | New authentication DENIED. Existing valid sessions may continue read-only within their unexpired lifetime; any security-sensitive action DENIED |
| Signing keys cannot be refreshed (JWKS) | Tokens that require the missing key DENIED; no downgrade to a weaker/again-cached-past-TTL key |
| Session storage unavailable | Session validation DENIED (no "assume valid") |
| Tenant membership cannot be resolved | Request DENIED (no default tenant) |
| Database context establishment fails | Transaction aborts; operation DENIED |
| Role/membership data stale | Treat as unresolved ⇒ security-sensitive action DENIED |
| Revocation status unavailable | DENIED (cannot prove not-revoked) |

Read-only bounded behaviour, where allowed, must be **explicit** and must never expose
another tenant's data or perform a write.

---

## Deliverable 11 — Audit / evidence event catalogue

New CIP-007 hash-chained event types (identifiers only — never tokens/secrets/PII;
digests where a value must be bound):

```
authn.succeeded         authn.failed            authn.denied_failclosed
session.established      session.rotated         session.revoked
tenant.resolved          tenant.selection.denied
membership.changed       delegation.granted      delegation.revoked
workload.authenticated   workload.denied
breakglass.opened        breakglass.action       breakglass.closed
dbcontext.established     dbcontext.failed
```

Each event records the derived principal + tenant (identifiers), the derivation
provenance (`derivedFrom`), decision/reason, and timing — and chains onto the existing
evidence ledger (same append-only + independent re-verification guarantees).

---

## Deliverable 12 — Migration sequence

Each step is separately reviewed and held; no step trusts client-supplied tenant.

```
S1  principal + membership + delegation schema (reviewed migration; RLS; least-privilege)
S2  OIDC verify-only boundary (JWKS, allowlists) — no session issuance yet
S3  session tier (server-side/crypto sessions, CSRF, cookies, rotation)
S4  tenant-resolution service + SECURITY DEFINER DB-context function (GAP-1)
S5  replace the fixed console operator subject with the derived context
S6  workload-identity federation for service/agent principals
S7  break-glass governance path
S8  remove any interim shims; full fail-closed matrix enforced
```

---

## Deliverable 13 — Test plan

- **Unit:** token-validation vectors (valid, expired, nbf-future, bad-audience,
  wrong-issuer, `none`/alg-confusion, tampered signature, missing kid); PKCE/nonce/
  state; delegation-bound checks.
- **Integration (HTTP):** RLS through the real route path with a stubbed IdP;
  foreign-tenant denial; pooled-connection reuse; tenant-switch epoch; session
  rotation.
- **Threat cases:** all of T1–T18.
- **Fail-closed:** each Deliverable-10 condition returns a denial, not a fallback.
- **HTTP SIF-Bench v0.2** (see the separate note): governance behaviour over the real
  `/api/runtime` surface, distinguishing transport errors from governance denials.

---

## Deliverable 14 — Supported vs unsupported claims (after Phase 3)

**Supported (post-implementation):**
- Tenant authority is derived from verified identity; the caller cannot select
  authority.
- OIDC tokens are verified (issuer/audience/alg/expiry/PKCE) before any context.
- Sessions are server-controlled, rotated, revocable, and CSRF-protected.
- Delegations are explicit, scoped, bounded, and evidenced.
- Fail-closed on IdP/keys/session/membership/revocation failure.

**Still unsupported (do NOT claim):**
- production readiness; enterprise RBAC completeness; end-to-end canonical SCT
  signature re-verification at disclosure; exactly-once external action execution;
  KMS/HSM-backed custody; physical disaster recovery; complete runtime observability;
  deployment hardening; penetration-tested security; arbitrary-scale multi-tenant
  operation; zero leakage or impossibility of compromise.

---

## Deliverable 15 — HTTP SIF-Bench v0.2 migration

Tracked separately in **`docs/HTTP_SIFBENCH_MIGRATION.md`** — the legacy Python live
harness targets the retired `/api/state` + `/api/rerun` slice endpoints and must be
migrated to `/api/runtime` before it is evidence for the async runtime. The historical
result stays frozen as **HTTP SIF-Bench v0.1**; the replacement is **v0.2**.

---

## Non-goals for the first Phase 3 commit

This specification introduces **no** authentication implementation, provider SDK,
deployment/secrets configuration, or credentials. It is held for review before any
implementation begins.
