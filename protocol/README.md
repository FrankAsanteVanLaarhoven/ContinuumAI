# Continuum Open Protocol (CIP)

The protocol is specified independently of the reference implementation. Vendor
and infrastructure choices (Next.js, Node, a particular cloud) are replaceable
implementation details and are **not** part of the protocol.

## CIP family

| CIP | Title | v0.1 status |
|-----|-------|-------------|
| CIP-001 | Sovereign Principal Identity | modelled (`types.ts` `Principal`) |
| CIP-002 | Intent Envelope | **schema + implemented** (`schemas/cip-002-intent.schema.json`) |
| CIP-003 | Context Disclosure Request | implemented (`protocol.ts` `discloseInputSchema`) |
| CIP-004 | Sovereign Capability Token | **schema + implemented** (`schemas/cip-004-capability.schema.json`) |
| CIP-005 | Memory Mutation | modelled (`MemoryObject` provenance) |
| CIP-006 | Action Proposal | implemented (`protocol.ts` `actionProposalInputSchema`) |
| CIP-007 | Evidence Envelope | **schema + implemented** (`schemas/cip-007-evidence.schema.json`) |
| CIP-008 | Continuous Revocation Signal | implemented (`engine.revoke`) |
| CIP-009 | Portable Continuum Archive | roadmap |
| CIP-010 | Confidential Execution Attestation | roadmap |

## Versioning

```
CIP major.minor.patch
```

- **major** — breaking semantic change.
- **minor** — backward-compatible capability addition.
- **patch** — clarification or defect correction.
- Every request advertises supported versions.
- **Unknown mandatory fields MUST fail closed.** (v0.1 enforces this via Zod
  `.strict()` parsing at the boundary — unknown keys are rejected.)
- Unknown optional fields MAY be ignored only when explicitly marked optional.
- Protocol conformance MUST be independently testable.

## Normative language

Specifications use MUST, MUST NOT, SHOULD, SHOULD NOT, MAY per RFC 2119.
