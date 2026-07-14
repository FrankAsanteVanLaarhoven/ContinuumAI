# I6 digest and evidence design

Two digests with different jobs. They are **never merged into one field**.

| Digest | Column | Purpose | Construction |
|--------|--------|---------|--------------|
| **Idempotency-key digest** | `i6_evidence.idempotency_key_digest` | safely identify *repeated use of the same client key* in immutable evidence | `kd1:` + `sha256(tenant ∥ 0x1f ∥ raw_key ∥ secret)` |
| **Request digest** | `i6_action.request_digest`, `i6_evidence.request_digest` | decide whether a repeat is *semantically identical* (replay) or *materially different* (conflict) | `sha256(canonicalJson(request))`, alg `sha256/continuum-canonical-v1` |

Regression tests: `src/canonicalization.test.ts`.

## Idempotency-key digest

- **Construction** — `keyDigest(tenant, key) = "kd1:" + sha256Hex(tenant + "\x1f" + key + secret)`.
- **Where the secret is held** — a demonstration literal in `harness.ts` for the
  benchmark. **Production** holds it in a KMS / secret store; it is an
  evidence-correlation key, not a signing key.
- **Cross-tenant unlinkability** — the tenant is in the preimage, so the **same raw
  key in two tenants yields different digests** (tested). Within a tenant, repeated
  use of the same key is linkable (its purpose).
- **Rotation policy & replay** — rotating the secret changes only the
  **evidence-correlation** value. It does **not** break replay lookup, because
  replay/conflict resolution keys on the **raw `idempotency_key` column in
  `i6_action`** (the operational store), never on the evidence digest. So rotation is
  safe for correctness; it only re-bases correlation going forward.
- **Version & migration** — the `kd1:` prefix versions the construction. A migration
  to `kd2` writes new evidence under `kd2:` while old rows keep `kd1:`; correlation
  queries filter by prefix. No rewrite of immutable evidence is required.
- **Raw key never in immutable evidence** — `i6_evidence` stores only the digest
  (tested: the digest never contains the raw key). The raw `idempotency_key` lives
  only in the operational `i6_action` row, which the UNIQUE lookup needs.

## Request digest — canonicalisation

Built from the security-relevant, normalized request
`{tenant, principal, intent, operation, resource, arguments, purpose, capability,
policy_version, approval_requirement}` via the control plane's `canonicalJson`
(recursively sorted keys, `JSON.stringify` scalars). No volatile timestamps are
included.

**Guarantees (pinned by tests):**

- Stable across calls; independent of top-level and nested key insertion order.
- `1` ≡ `1.0` (same IEEE-754 number); a number is **distinct** from its string
  encoding (`1000` ≠ `"1000"`).
- Array order is semantic (`["a","b"]` ≠ `["b","a"]`).
- A present-null field ≠ an omitted field (empty ≠ omitted).
- Floats serialise deterministically (IEEE-754); use integer minor units for money
  in production to avoid representational surprise.

**Documented caller-normalisation boundaries (pinned by tests):**

- **No Unicode NFC/NFD normalisation** — `"café"` (precomposed) ≠ `"café"`
  (decomposed). The caller MUST normalise text fields (e.g. NFC) before submitting,
  or the two are treated as materially different requests (a CONFLICT under I6-C).
- **Case-sensitive** — `"Place_Order"` ≠ `"place_order"`. Identifier case
  normalisation is the caller's responsibility where case is insignificant.

Duplicate JSON keys are not representable (the request is a JS object; last-wins at
parse). These boundaries are deliberate: normalising inside the digest would hide a
materially different request; normalising at the edge keeps the digest a faithful
function of the submitted bytes.

## Production field-coverage note

Before treating I6-C as production-ready, the canonical request should also bind
`agent`, `entitlement_version`, and `tool_identity` (in addition to the fields
above), and the caller-side normalisation (Unicode NFC, identifier case, numeric
minor units) should be enforced at the API boundary with its own tests. This
workspace binds the core security-relevant set and documents the remainder as the
production hardening path.
