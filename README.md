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
| Control-plane core (policy, capability, broker, evidence, action) | `packages/continuum-core` | 19 tests green, strict TS |
| Operations console (Palantir/Foundry aesthetic) | `apps/console` | Next.js 15, live |
| Benchmark harness | `research/sif-bench` | 10/10 gates, stdlib-only |
| Protocol schemas (CIP-002/004/007 + index) | `protocol/` | JSON Schema |
| Security-critical Rust TCB | `security-core/` | reserved (v0.6+) |

### The slice, end to end

owner + agent authenticate → agent submits a CIP-002 intent → the deny-by-default
PDP permits **2 of 10** memory objects (the other 8 deny for distinct, legible
reasons) → the broker releases the minimum set and **redacts `bank_iban`** →
a holder-bound Ed25519 capability (90 s TTL, proof-of-possession) is issued →
the agent proves possession and the model gateway releases only permitted context
→ the agent proposes an external action → it is **blocked at the human gate** →
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
npm run verify                 # typecheck (strict) + core tests
npm run dev                    # console + control plane at http://localhost:4311
# in another shell, with the server up:
python3 research/sif-bench/sif_bench.py --iterations 30
```

API: `GET /api/state` (full control-plane snapshot), `POST /api/rerun`.

## Documentation

- [`docs/CLAIMS.md`](docs/CLAIMS.md) — the claim boundary (normative).
- [`docs/architecture.md`](docs/architecture.md) — the five planes and layout.
- [`docs/threat-model.md`](docs/threat-model.md) — adversaries, controls, residual risk.
- [`protocol/README.md`](protocol/README.md) — the CIP family and versioning.

## License

Apache-2.0.
