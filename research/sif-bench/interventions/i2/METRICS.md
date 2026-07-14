# I2 metric definitions and opaque-handle properties

Normative definitions for the figures reported in `I2_RESULTS.md`, so the numbers
are reproducible and not challengeable as arbitrary.

## Excess-metadata ratio

$$\mathrm{ExcessMetadataRatio} = \frac{\mathrm{ReturnedFields} - \mathrm{RequiredFields}}{\mathrm{ReturnedFields}}$$

- **Denominator is `ReturnedFields`** (the fields the projection actually emits per
  object), *not* the total fields available in the store. A ratio of 0 means the
  response carries only what the task requires; values approach 1 as the response
  carries more surplus.
- **`RequiredFields` = 3** — the minimum a pure *listing* task needs:

  | Field | Why the listing task requires it |
  |-------|----------------------------------|
  | `handle` | a stable, non-reversible reference to fetch or act on the object in a follow-up **authorized** call — without it the listing is inert |
  | `memory_class` | the object type, so the caller can select relevant objects without reading content |
  | `classification` | the permitted sensitivity label, so the caller respects the ceiling without fetching content |

  These three are the `minimal` projection (`PROJECTION_FIELDS.minimal`), and
  `MINIMAL_NECESSARY_FIELDS = 3` is the single source of truth in
  `packages/continuum-core/src/interventions/metadata.ts`.

### Field-counting rules

- **One top-level key = one field**, regardless of nested depth. `purpose_constraints`
  (an array) and `content_hash` (a scalar) each count as **1**. Nested objects and
  arrays are **not** flattened or expanded.
- The `full` projection is `Omit<MemoryObject, "content">` = **23** top-level keys
  (24 fields on `MemoryObject` minus `content`). Hence for the full arms:
  $(23 - 3) / 23 = 0.8696 \approx 0.87$. The minimal arm returns exactly the 3
  required fields: $(3 - 3) / 3 = 0$.
- **Sensitive and non-sensitive fields are weighted equally** in v0.1. This is a
  deliberate simplification: a field that leaks (`source_reference`, `sensitive_fields`,
  `creator_principal`) counts the same as a benign one (`created_at`). A
  sensitivity-weighted variant — penalising leaky fields more — is a documented future
  refinement, not the current metric.

The metric measures **response surface**, not information content or leak severity; it
should be read alongside the qualitative field list, not as a standalone risk score.

## Opaque handles — what they are and are not

The minimal/standard projections replace the raw storage id with
`opaqueHandle(capabilityId, memoryId) = "obj_" + sha256Hex(capabilityId + ":" + memoryId).slice(0, 16)`.

**Properties the current implementation has (honest):**

- **Capability-scoped** — the capability id is in the preimage, so the same object
  under a different capability yields a different handle.
- **Tenant-scoped (transitively)** — a capability is tenant-bound, so handles do not
  cross tenants.
- **Not caller-reversible** — SHA-256 preimage resistance; the caller does not hold
  the `memoryId` needed to recompute it.
- **Randomness-inheriting** — `capabilityId` is `sct_${randomUUID()}` (CSPRNG) plus a
  per-token `nonce`, so handles are unpredictable without the token.
- **Never co-logged with the raw id** — the evidence chain records handles in
  `disclosed_objects` and field *names* in `scope`; the raw `memory_id` never enters an
  immutable record.

**Properties NOT yet provided (deferred, must not be claimed):**

- **Determinism, not fresh randomness** — the handle is a deterministic pseudonym
  (chosen for reproducible tests), not a freshly random token. It is stable for the
  life of the capability.
- **No independent revocation / expiry** — the handle is not stored server-side and is
  not independently revocable; it lives and dies with its capability only because it is
  recomputed, not tracked.
- **Not collision-tested** — the 16-hex-char (64-bit) truncation has a birthday bound
  that is comfortable for per-listing sets (~10 objects) but is **not** formally
  collision-tested; widening or testing it is future work.
- **No dereference path** — there is currently **no** handle→object read implemented;
  the handle is a display pseudonym only.

**Critical invariant for any future dereference:** an opaque handle is **not**
authorization. If a `resolve(handle)` path is built, every dereference MUST repeat the
full capability + policy checks (holder proof, tenant derivation, scope, purpose,
expiry, revocation) exactly as `listMemoryMetaBound` does — the handle must never be a
bearer key.
