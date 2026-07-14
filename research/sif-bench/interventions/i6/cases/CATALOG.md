# I6 case catalog (GAP-6 — action idempotency)

Idempotency domain: `UNIQUE (tenant_id, principal_id, operation, idempotency_key)`.
Digest binds `{tenant, principal, intent, operation, resource, arguments, purpose,
capability, policy_version, approval_requirement}`.

| # | Case | Expected (bound) | Probe |
|---|------|------------------|-------|
| 1 | New key, new request | CREATED, executed once | B1 |
| 2 | Same key, same request, sequential retry | REPLAYED, no re-execute | B2 |
| 3 | Same key, same request, concurrent retry | one CREATED / one REPLAYED, exec once | B10 |
| 4 | Same key, different arguments | C: CONFLICT · B: REPLAYED (undetected) | B3 |
| 5 | Same key, different operation | distinct domain → CREATED | B7 |
| 6 | Same key, different intent | C: CONFLICT (digest) | B4 |
| 7 | Same key, different capability | C: CONFLICT (digest) | B5 |
| 8 | Same key, different tenant | distinct domain → CREATED | B7 |
| 9 | Same key, different principal | distinct domain → CREATED | B7 |
| 10 | Missing key (consequential) | IDEMPOTENCY_REQUIRED | B8 |
| 11 | Caller chooses existing action_id | rejected: server-issued id | B9 / A |
| 12 | Two workers, same request | one action, exec once | B10 |
| 13 | Two workers, same key/different request | one authoritative record | B11 |
| 14 | Retry after successful execution | REPLAYED (no re-exec) | B2 |
| 15 | Retry after denied action | idempotent re-deny (CONFLICT/missing-key) | B3/B8 |
| 16–18 | Retry after failed/compensated/revoked | REPLAYED returns stored terminal outcome | B2 (terminal replay) |
| 19 | Retry after policy-version change | C: CONFLICT (digest) | B6 |
| 20 | DB rollback during creation | no orphan; retry clean | B12 |
| 21 | Evidence append fails after create | whole create rolls back; retry clean | B12 |
| 22 | Tool adapter duplicate execution | exactly one execution row | B10/B2 (i6_execution PK) |
| 23 | Key reused outside its domain | distinct domain → separate action | B7 |
| 24 | Benign distinct keys | distinct actions, each exec once | B14 |

Controls: valid sequential (B1) and valid concurrent (B10 winner) new-action
creation must succeed under every arm (no false deny).

Baseline (I6-A) reproductions: A1 silent overwrite · A2 duplicate execution · A3
caller-selected action_id.
