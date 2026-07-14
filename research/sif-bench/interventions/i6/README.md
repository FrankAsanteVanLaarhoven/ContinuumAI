# SIF-Bench intervention I6 — idempotent action identity (GAP-6)

Matched-arm evaluation over a real embedded PostgreSQL that the action-creation
path must not accept a caller-controlled `action_id` (silent overwrite) and must
not re-execute on retry.

```bash
npm run intervention:i6      # boots embedded PostgreSQL on port 55448
```

- **I6-A** — caller-chosen `action_id`, `ON CONFLICT DO UPDATE` (silent overwrite),
  execute-every-time. Reproduces GAP-6. Preserved only as the frozen benchmark arm.
- **I6-B** — server-issued `action_id`, required idempotency key, same-request
  replay. Prevents duplicate creation and duplicate execution.
- **I6-C** — I6-B **+** canonical request-digest conflict rejection **+**
  execution-level idempotency.

Idempotency domain: `UNIQUE (tenant_id, principal_id, operation, idempotency_key)`,
enforced by `INSERT ... ON CONFLICT DO NOTHING` + read (**never** `DO UPDATE`).
`intent`, `capability` and `policy_version` are bound into the request digest but not
the uniqueness domain, so a differing one with the same key/operation is a CONFLICT
under I6-C rather than a silent second action.

Result document: [`I6_RESULTS.md`](./I6_RESULTS.md) · case catalog:
[`cases/CATALOG.md`](./cases/CATALOG.md) · digest & evidence design:
[`DIGEST.md`](./DIGEST.md). The generated `report.json` is gitignored; regenerate
with the command above.

Files:

```
sql/i6_schema.sql   baseline + bound schemes, roles, UNIQUE constraint
src/harness.ts      pools, canonical request digest, keyed key-digest, reset
src/idempotency.ts  baselineCreate (overwrite) + boundCreate (create-or-read)
src/i6.ts           arms I6-A/B/C, 24-case battery, metrics
src/i6.test.ts      assertions + report writer
src/global-setup.ts embedded PostgreSQL boot on port 55448
```
