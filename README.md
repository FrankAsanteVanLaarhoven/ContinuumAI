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

## What is in this v0.1

A **runnable, tested vertical slice** — the blueprint's First Implementation
Milestone — plus a Foundry-style operations console over it.

| Layer | Where | Status |
|-------|-------|--------|
| Control-plane core (policy, capability, broker, model gateway, evidence, action) | `packages/continuum-core` | strict TS |
| Durable data plane (PostgreSQL + row-level-security isolation) | `packages/continuum-persistence` | real embedded Postgres |
| Operations console (Palantir/Foundry aesthetic) | `apps/console` | Next.js 15, live |
| Benchmark harness | `research/sif-bench` | stdlib-only |
| Research paper (stable components) | `research/paper` | problem, hypotheses, RQs, protocol, claim-evidence matrix |
| Protocol schemas (CIP-002/004/007 + index) | `protocol/` | JSON Schema |
| Security-critical Rust TCB | `security-core/` | reserved (v0.6+) |

### Gates, reported by suite

Each suite is a distinct gate with its own scope. They are **not** summed into a
single headline number — a passing HTTP gate does not stand in for a passing
database-isolation gate, and vice versa.

| Suite | Command | Passing |
|-------|---------|---------|
| Core invariant tests (primitives, slice, gateway) | `npm run test` | 27 |
| SIF-Bench **Stage A** — deterministic control-plane adversarial | `npm run sif-bench:stage-a` | 6 tests · 18 attacks blocked · 4 controls |
| Persistence — isolation | `npm run test:persistence` | 7 |
| Persistence — durability (incl. idempotent migration) | `npm run test:persistence` | 6 |
| Persistence — logical restore | `npm run test:persistence` | 1 |
| SIF-Bench HTTP harness (over the live console) | `npm run sif-bench` | 11/11 gates |
| Console operational gates | in `apps/console` | 11/11 gates |

**Stage A** attacks the control plane's own guarantees with no model and no
corpus: capability misuse (bearer replay, forged proof-of-possession, expiry,
revocation, scope/tenant tamper, audience confusion), cross-tenant access,
evidence-chain tamper (content, link, re-sign, splice), and human-gate bypass
(agent self-approval, impostor and cross-tenant approvers). Every attack must be
blocked *and* fail for the expected reason; positive controls confirm the
legitimate paths still succeed, so a pass cannot be reached by over-blocking. The
frozen v0.2 baseline is `research/sif-bench/STAGE_A_BASELINE.md`.

Tenant isolation is enforced by **PostgreSQL Row-Level Security** (not application
filtering): absent tenant context exposes nothing, a forged `tenant_id` is
rejected by `WITH CHECK`, the evidence stream is append-only, and the persisted
hash chain re-verifies after a fresh connection.

**Persistence boundary — read precisely.** Durability is verified over a fresh
connection and a **logical** restore only; a full physical cluster stop/start and
a `pg_dump`/`pg_restore` cycle are **not** yet exercised. The platform signing key
is generated **in-process** (no HSM/KMS custody), so a database **superuser
bypasses RLS**; the isolation guarantee holds for the least-privilege
`continuum_app` role, not against a superuser. At-rest encryption for object
storage is not implemented. See [`docs/CLAIMS.md`](docs/CLAIMS.md) and
[`docs/threat-model.md`](docs/threat-model.md).

### The slice, end to end

owner + agent authenticate → agent submits a CIP-002 intent → the deny-by-default
PDP permits **2 of 10** memory objects (the other 8 deny for distinct, legible
reasons) → the broker releases the minimum set and **redacts `bank_iban`** →
a holder-bound Ed25519 capability (90 s TTL, proof-of-possession) is issued →
the agent proves possession and the model gateway releases only permitted context
→ the **model gateway** allows a screened, budgeted, schema-validated call and
**blocks a prompt-injection attempt** → the agent proposes an external action →
it is **blocked at the human gate** →
the owner approves → the tool gateway executes (simulated) → every step appends a
**signed, hash-chained** evidence envelope → the capability is **revoked** and
reuse is denied → a **cross-tenant** probe is blocked by isolation.

## Language strategy

TypeScript for the control plane and console; Python for the research/benchmark
plane; Rust deferred to a later, narrow security-critical TCB. Start monolingual;
become polyglot only where measurement proves it improves assurance.

## Run it

```bash
npm install
npm run verify                 # typecheck (strict) + core control-plane tests
npm run test:persistence       # real embedded Postgres: isolation + durability + restore
npm run dev                    # console + control plane at http://localhost:4311
# in another shell, with the server up:
npm run sif-bench              # SIF-Bench HTTP gates over the live console
```

Each command is a separate gate; run all of them for full coverage. `npm run
verify` alone exercises only the core control plane, not the database or the
HTTP benchmark.

API: `GET /api/state` (full control-plane snapshot), `POST /api/rerun`.

## Documentation

- [`docs/CLAIMS.md`](docs/CLAIMS.md) — the claim boundary (normative).
- [`docs/architecture.md`](docs/architecture.md) — the five planes and layout.
- [`docs/threat-model.md`](docs/threat-model.md) — adversaries, controls, residual risk.
- [`protocol/README.md`](protocol/README.md) — the CIP family and versioning.

## License

Apache-2.0.
