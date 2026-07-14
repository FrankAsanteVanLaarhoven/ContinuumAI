# security-core (reserved — Rust, deferred to v0.6+)

This directory is intentionally empty of implementation. It reserves the place
for a **narrow, audited Rust trusted computing base**, to be introduced only
where measurement proves it improves assurance over the TypeScript control
plane.

## Why deferred

"Polyglot" is an eventual architecture property, not a starting objective.
Beginning in Rust would trade real velocity and CI simplicity for assurance the
v0.1 control plane does not yet need. Node's OpenSSL-backed Ed25519 and SHA-256
are high-assurance enough for v0.1 capability and evidence signing, so **no
current requirement forces Rust**.

## What will move here (v0.6+)

Extracted only after the interfaces stabilise and measurement justifies it:

- `capability-engine/` — capability-token signing and verification.
- `evidence-signer/` — tamper-evident ledger hashing and signing.
- `attestation-verifier/` — confidential-compute attestation verification.

The contract these must preserve already exists as the interface in
`packages/continuum-core/src/crypto.ts`. Keeping this TCB small is the point.

_(The Rust toolchain is already available in this environment for that work.)_
