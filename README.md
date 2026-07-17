# Continuum — Sovereign Intent and Agency Infrastructure

Continuum is an **owner-controlled identity, intent, memory, authorization, and
provenance control plane** that governs how heterogeneous AI agents, models,
services, devices, and robots obtain private context and exercise agency.

> **Claim boundary.** Continuum minimises disclosure, cryptographically
> constrains authorization, records every release and action, supports
> confidential execution, and provides measurable leakage-resistance guarantees
> **within an explicitly defined threat model**. It does **not** claim that
> leakage is mathematically impossible. See [`docs/CLAIMS.md`](docs/CLAIMS.md).

## The primary invariant

```
Permit = IdentityValid ∧ PurposeAllowed ∧ ScopeAllowed ∧ PolicySatisfied
         ∧ RiskWithinLimit ∧ ConsentCurrent ∧ EvidenceSufficient
```

with **tenant isolation** as a hard gate. The default result is deny. No agent
receives context or authority merely because it can connect.

## What is in the repository

A **runnable, tested control plane** — the blueprint's First Implementation
Milestone — hardened over three phases: (1) the vertical slice + operations
console, (2) a durable, async PostgreSQL runtime, and (3) a layered,
provider-neutral identity and authorization boundary.

| Layer | Where | Status |
|-------|-------|--------|
| Control-plane core (policy, capability, broker, model gateway, evidence, action) | `packages/continuum-core` | strict TS |
| Durable data plane (PostgreSQL + row-level-security isolation) | `packages/continuum-persistence` | real embedded Postgres |
| Async runtime (request-scoped store, trusted tenant context) | `packages/continuum-core/src/async` + `PostgresStore` | live over PG |
| Identity, session & authorization boundary (Phase 3, S1–S4D-0) | `packages/continuum-core/src/identity`, `.../browser` | see below |
| Operations console (Foundry-style aesthetic) | `apps/console` | Next.js 15, live |
| Benchmark & intervention harnesses | `research/sif-bench`, `packages/sif-*` | stdlib + vitest |
| Research paper (stable components) | `research/paper` | problem, hypotheses, RQs, protocol, claim-evidence matrix |
| Protocol schemas (CIP-002/004/007 + index) | `protocol/` | JSON Schema |
| Security-critical Rust TCB | `security-core/` | reserved (v0.6+) |

### Gates, reported by suite

Each suite is a distinct gate with its own scope. They are **not** summed into a
single headline number — a passing browser-boundary gate does not stand in for a
passing database-isolation gate, and vice versa.

| Suite | Command | Passing |
|-------|---------|---------|
| Core control plane + identity/browser boundary | `npm run verify` | 285 |
| Persistence — isolation, durability, restore, trusted context, sessions, replay | `npm run test:persistence` | 113 |
| Console operational + browser-auth wiring | `npm run test -w @continuum/console` | 11 |
| SIF-Bench **Stage A** — deterministic control-plane adversarial | `npm run sif-bench:stage-a` | 6 |
| SIF-Bench **Stage B** — corpus-driven adversarial (honest before-defence baseline) | `npm run sif-bench:stage-b` | 7 |
| Concurrency / TOCTOU | `npm run sif-bench:concurrency` | 9 |
| Interventions I1–I7 (measured defences vs. the frozen baselines) | `npm run intervention:i1 … :i7` | 6 / 8 / 6 / 6 / 7 / 22 / 8 |
| Comparative (deterministic B0–B3 matched-arm) | `npm run comparative:validate` | 44 |

**Stage A** attacks the control plane's own guarantees with no model and no
corpus: capability misuse (bearer replay, forged proof-of-possession, expiry,
revocation, scope/tenant tamper, audience confusion), cross-tenant access,
evidence-chain tamper (content, link, re-sign, splice), and human-gate bypass
(agent self-approval, impostor and cross-tenant approvers). Every attack must be
blocked *and* fail for the expected reason; positive controls confirm the
legitimate paths still succeed, so a pass cannot be reached by over-blocking.

Tenant isolation is enforced by **PostgreSQL Row-Level Security** (not application
filtering) bound to a trusted, database-derived context: absent context exposes
nothing, a forged `tenant_id` GUC yields no tenant, the evidence stream is
append-only, and the persisted hash chain re-verifies after a fresh connection.

## Phase 3 — identity, session, and authorization boundary

Phase 3 builds a **layered, provider-neutral** boundary. Each layer is separately
tested; **no layer accepts a caller-supplied tenant**:

```
external credential → S4C browser transport → S4B one-time authorization-code
transaction → S4A JWT/JWS verification → S3 identity mapping + session
→ S2B trusted database tenant derivation
```

- **S1/S2/S2B** — identity data model and a `SECURITY DEFINER` trusted-context
  boundary. Tenant authority is derived only from an active `(principal, session,
  membership)` triple; a raw `app.current_tenant` GUC yields nothing. **S2B is the
  sole tenant-authority transition.**
- **S3** — vendor-neutral identity-verification and session interfaces; verified
  externals are keyed by `(issuer, subject)`; sessions are opaque, digest-stored,
  revocable, rotatable, and carry **no** self-authorizing tenant.
- **S4A** — real JWT/JWS verification using standards-based JOSE processing
  (`jose`, pinned) **within an explicitly supported algorithm / key-type /
  issuer-policy / claim-validation profile**; SSRF-constrained JWKS; restart-safe
  **single-database** replay detection.
- **S4B** — a browser-independent authorization-code **state machine** (persisted
  single-use transaction, encrypted-at-rest PKCE) exercised against a **fixture**
  exchanger — not a real provider.
- **S4C** — a hardened browser transport and secure-cookie / CSRF session boundary,
  exercised against a **deterministic local authorization server** that runs the
  genuine S4B/S4A/S3 path — not a real provider.
- **S4D / S4D-0** — a reviewed, fail-closed **specification** for onboarding and
  qualifying one real IdP, plus a private registration-manifest structure and a
  static completion gate.

> **Auth claim boundary.** These layers are implemented and tested against
> deterministic, fixture, and local servers. **No real identity provider has been
> contacted, no credentials created, no callback registered, and no qualification
> run; both kill switches are engaged and there are zero real users.** Continuum
> does not claim end-to-end real-provider login, universal standards compliance,
> global/cross-deployment replay prevention, complete SSRF elimination, or
> production readiness. See the `docs/PHASE3_*` documents and
> [`docs/threat-model.md`](docs/threat-model.md).

**Persistence boundary — read precisely.** Durability is verified over a fresh
connection and a **logical** restore only; a full physical cluster stop/start and
a `pg_dump`/`pg_restore` cycle are **not** yet exercised. The platform signing key
is generated **in-process** (no HSM/KMS custody), so a database **superuser
bypasses RLS**; the isolation guarantee holds for the least-privilege application
roles, not against a superuser. See [`docs/CLAIMS.md`](docs/CLAIMS.md).

### The slice, end to end (over the async runtime)

owner + agent authenticate → agent submits a CIP-002 intent → the deny-by-default
PDP permits **2 of 10** memory objects (the other 8 deny for distinct, legible
reasons) → the broker releases the minimum set and **redacts `bank_iban`** →
a holder-bound Ed25519 capability (90 s TTL, proof-of-possession) is issued →
the agent proves possession and the model gateway releases only permitted context
→ the **model gateway** allows a screened, budgeted, schema-validated call and
**blocks a prompt-injection attempt** → the agent proposes an external action →
it is **blocked at the human gate** → the owner approves → the tool gateway
executes (simulated) → every step appends a **signed, hash-chained** evidence
envelope → the capability is **revoked** and reuse is denied → a **cross-tenant**
probe is blocked by isolation.

## Language strategy

TypeScript for the control plane and console; Python for the research/benchmark
plane; Rust deferred to a later, narrow security-critical TCB. Start monolingual;
become polyglot only where measurement proves it improves assurance.

## Run it

```bash
npm install
npm run verify                       # typecheck (strict) + core + identity/browser boundary (285)
npm run test:persistence             # real embedded Postgres: isolation, durability, trusted context, sessions, replay (113)
npm run test -w @continuum/console   # console operational + browser-auth wiring (11)
npm run sif-bench:stage-a            # deterministic control-plane adversarial (6)
npm run sif-bench:stage-b            # corpus-driven before-defence baseline (7)
npm run sif-bench:concurrency        # concurrency / TOCTOU (9)
npm run comparative:validate         # deterministic B0–B3 matched-arm (44)
npm run dev                          # console + async runtime at http://localhost:4311
```

Each command is a separate gate; run all of them for full coverage. `npm run
verify` alone exercises the core control plane and the identity/browser boundary,
not the database or the console.

API (console): `POST /api/runtime` (async control-plane snapshot / rerun) and the
`/api/auth/{login,callback,logout,session,csrf}` boundary. The earlier synchronous
`/api/state` + `/api/rerun` slice endpoints have been **retired** in favour of the
async runtime; the legacy `research/sif-bench/sif_bench.py` HTTP harness targeted
`/api/state` and is not a current gate.

## Documentation

- [`docs/CLAIMS.md`](docs/CLAIMS.md) — the claim boundary (normative).
- [`docs/architecture.md`](docs/architecture.md) — the five planes and layout.
- [`docs/threat-model.md`](docs/threat-model.md) — adversaries, controls, residual risk.
- `docs/PHASE3_*` — the identity and authorization boundary (S1–S4D-0), per milestone.
- [`protocol/README.md`](protocol/README.md) — the CIP family and versioning.

## License

Apache-2.0.
