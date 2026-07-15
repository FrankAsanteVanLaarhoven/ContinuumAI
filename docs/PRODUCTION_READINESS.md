# Production-Readiness Plan

```
Status:   PRE-PRODUCTION reference control plane — NOT general-availability.
          This document does not claim production readiness. Held for review.
Baseline: HEAD 0fd91b4 (== origin/main)
Pairs with: docs/PERSISTENCE_WIRING_AUDIT.md (the evidence this plan acts on)
```

## Current maturity

Two maturity layers coexist (measured, not asserted — see the audit for file evidence):

- **Control-plane + data plane (validated):** deny-by-default authorization, capability
  tokens, disclosure broker, human gate, revocation, I1–I3/I7 interventions, Ed25519
  hash-chained evidence — **68/68 core tests**. Durable PostgreSQL data plane with
  row-level-security isolation, least-privilege role, append-only evidence, independent
  chain re-verification — **14 persistence tests**. Stage-A adversarial suite is a
  build-failing CI gate.
- **Client-facing runtime (incomplete):** the console SSR and `/api/state` + `/api/rerun`
  run an **in-memory** engine with a **hardcoded tenant** and **no authentication**; the
  model is **simulated**; there is no deployment, secrets, or session tier.

Continuum provides **measurable leakage-resistance within an explicitly defined threat
model** (see `docs/CLAIMS.md`), not a proof of impossibility. That boundary must be
stated to any client.

## Documented limitations (already recorded in-repo — production blockers)

Cited from `README.md:68–73` and `docs/threat-model.md:41,47–52`:

- Platform signing key is generated **in-process** — no HSM/KMS custody.
- A database **superuser bypasses RLS**; isolation holds for `continuum_app`, not superuser.
- Object-storage **at-rest encryption** is not implemented.
- Restore testing is **logical** only — no physical cluster stop/start or
  `pg_dump`/`pg_restore` cycle yet.

## Phased sequence

### Phase 1 — Audit & plan (THIS MILESTONE)
Evidence-only. Deliverables: `PERSISTENCE_WIRING_AUDIT.md` (runtime matrix + gap report)
and this plan. Committed separately from implementation; **held for review**. No storage
code, no auth, no deploy, no push, no tag, no production claim.

### Phase 2 — `PostgresStore` adapter (only the missing wiring)
Trigger: the audit confirms the console bypasses PostgreSQL — it does.
Build the **smallest** adapter that connects the **existing** persistence package to the
live path. It **must**:

- Implement the existing core `Store` interface (reconciling the synchronous, `Map`-based
  contract with async Postgres — load tenant-scoped state per request, or evolve the
  interface to async; decide in review).
- Reuse existing migrations, RLS policies, least-privilege role, append-only evidence.
- Use database-bound tenant identity; preserve I1–I7 invariants and chain semantics.
- Be selected by explicit config and **fail closed** in production:

  ```
  CONTINUUM_STORE=memory     # deterministic tests / research only
  CONTINUUM_STORE=postgres   # development / staging / production
  ```
  ```ts
  if (environment === "production" && storeMode !== "postgres") {
    throw new Error("Production requires the PostgreSQL store");
  }
  ```

It **must not**: duplicate schemas, add a second persistence model, weaken RLS, silently
fall back to memory, or take an authentication shortcut.
Gate: existing persistence + core suites stay green; the console path reads/writes Postgres
under RLS; restart-safety demonstrated on the live path.

### Phase 3 — Authentication & tenant boundary
OIDC authentication; secure session handling; **tenant derived from authenticated
identity** (eliminate client-selected tenant authority); RBAC/ABAC middleware on every
console and API route; CSRF protection where cookies are used; rate limiting; security
headers; administrator + auditor roles; break-glass audit semantics. No custom password
system.

### Phase 4 — Deployment & operational hardening
Docker images; local Compose; Kubernetes / managed containers; migration job; secrets +
**KMS/HSM** key custody; object-storage at-rest encryption; TLS + private networking;
health/readiness endpoints; backup + **physical** restore testing; disaster recovery;
OpenTelemetry; alerting; SLOs; progressive delivery; signed images, SBOMs, provenance.

### Phase 5 — Client-facing readiness pack
Current maturity; demonstrated controls; unsupported claims; threat model; data-flow
diagram; deployment topology; security-responsibility split; pilot limits; roadmap;
evidence/test summary; incident & support model; pilot acceptance criteria.

## Pre-client checklist (beyond the phases above)

Authenticated console/API access · runtime persistence wiring · secrets custody ·
production tenancy lifecycle · data deletion & export · operational monitoring · incident
response · capacity & load evidence · browser/session security · dependency & container
supply-chain controls · independent penetration testing.

## Decision

Proceed **Phase 1 → review → Phase 2 (adapter only, if approved)**. Do not build a new
persistence subsystem. Connect the proven persistence and governance semantics to the
real client-facing runtime.
