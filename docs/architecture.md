# Continuum — Architecture (v0.1)

## Language strategy

TypeScript is the primary language for the control plane and console. Python is
reserved for the research/benchmark plane (SIF-Bench). Rust is deliberately
deferred to a later, narrow security-critical trusted computing base
(`security-core/`, v0.6+) — introduced only where measurement proves it improves
assurance, not before. This keeps the initial trusted computing base small and
the build system simple. See `security-core/README.md`.

## The five planes

| Plane | Responsibility | v0.1 module(s) |
|-------|----------------|----------------|
| A · Identity & Trust | principals, tenancy, attestation, holder keys | `types.ts`, `store.ts` |
| B · Intent, Policy & Authority | intent envelopes, deny-by-default PDP, capability tokens, revocation | `protocol.ts`, `policy.ts`, `capability.ts` |
| C · Sovereign Memory & Knowledge | memory objects + provenance, minimum-disclosure broker | `types.ts`, `store.ts`, `broker.ts` |
| D · Agent, Model & Tool Execution | model gateway (allowlist, injection screening, egress canary, budget, output-schema), action state machine, human gate | `gateway.ts`, `action.ts` |
| E · Evidence, Observability & Governance | hash-chained signed ledger, metrics | `evidence.ts`, `engine.ts` |

The `ContinuumEngine` (`engine.ts`) is the orchestration facade; every operation
threads a single evidence ledger. `slice.ts` drives the 15-step first-milestone
flow with built-in assertions.

## The primary invariant

```
Permit = IdentityValid ∧ PurposeAllowed ∧ ScopeAllowed ∧ PolicySatisfied
         ∧ RiskWithinLimit ∧ ConsentCurrent ∧ EvidenceSufficient
```

with **tenant isolation** as a hard gate above it. The default result is deny;
`permit` becomes true only when every mandatory check passes. Every allow and
every deny carries its full check list.

## Repository layout

```
continuum/
├── packages/continuum-core/   # TS control-plane core (framework-free, tested)
├── apps/console/              # Next.js operations console (Foundry-style)
├── research/sif-bench/        # Python benchmark harness
├── protocol/                  # CIP schemas + versioning rules
├── security-core/             # reserved Rust TCB (deferred, v0.6+)
└── docs/                      # claims, threat model, architecture
```

## Data flow (vertical slice)

```
owner + agent authenticate
  → agent submits CIP-002 intent (Zod-validated, fail-closed)
  → PDP evaluates 10 candidate objects → permits 2
  → broker computes minimum disclosure, redacts bank_iban, emits digest
  → holder-bound CIP-004 capability issued (Ed25519, 90s TTL, PoP)
  → agent proves possession → model gateway releases only permitted context
  → model gateway allows a screened/budgeted/schema-validated call
    and blocks a prompt-injection attempt (direct + indirect + egress canary)
  → agent proposes external action → blocked at human gate
  → owner approves → tool gateway executes (simulated) → SUCCEEDED
  → every step appends a signed, hash-chained CIP-007 evidence envelope
  → capability revoked → reuse denied
  → cross-tenant probe denied by isolation
```

## Not yet in v0.1 (roadmap)

PostgreSQL + object storage + append-only event store; SPIFFE/SPIRE workload
identity; customer-managed keys / HSM; Temporal workflows; graph memory;
confidential-compute attestation; the Rust security-core extraction.
