# S4D-0 completion validation — two-checker model

The S4D-0 registration manifest has two distinct static checkers. Both are documentation
linters (no provider traffic, no network, no credentials); neither authorizes contact or
enables qualification.

## 1. Freeze checker — `docs/validate_s4d0.mjs`

Asserts the **S4D-0 frozen posture** as pushed to `origin/main`:

```
registrationValid = false   (all facts UNPINNED)
all gates          = false
providerContactAllowed = false
qualificationEnabled   = false
both kill switches ENGAGED
```

This is the checker that gates the committed public S4D-0 artifacts and the all-UNPINNED
private template. It intentionally hard-asserts `registrationValid = false` and
"all gates false", so it exits 1 on a *completed* manifest — **by design**.

## 2. Completed-state checker — `docs/validate_s4d0_complete.mjs`

Validates a manifest that the operator has completed **outside Git** (private operator
completion). It requires the **completed-registration posture**:

```
registrationValid      = true    (every required fact pinned)
providerContactAllowed = false   (held false by the ENGAGED contact kill switch)
qualificationEnabled   = false   (Q0–Q5 not enabled)
```

It requires ALL of: every mandatory operator field pinned (⇒ `registrationValid = true`);
`privacy_review_complete` gate true; budget ceilings pinned and `budget_pinned` gate true;
`evidence_controls_verified` gate true; rollback readiness complete (owner + procedure
pinned, and `credential_revocation_ready` / `callback_removal_ready` /
`synthetic_user_disablement_ready` / `session_revocation_ready` all true);
**`reviewer_signoff = true`** (registration sign-off present); `real_users = 0`;
`contact_kill_switch = ENGAGED`; `qualification_kill_switch = ENGAGED`.

It preserves every hard fail-closed invariant the freeze checker also enforces:
no `offline_access`/refresh scope; no `none` algorithm; PKCE `S256`; `response_type = code`;
no wildcard redirect; all synthetic identities `NOT_CREATED`; `secret_present_in_manifest =
false`; no secret-looking value anywhere; HTTPS endpoints; `qualification_enabled` gate
false; `synthetic_identities_ready` gate false (accounts are created during qualification,
never at registration completion).

Governing implication — `registrationValid = true` is **not** authority to contact the
provider or enable qualification. With sign-off + gates + `registrationValid` all true,
`providerContactAllowed` reduces to *(contact kill switch disengaged)*, so **disengaging
either kill switch fails this checker**. `registrationValid = true ≠ providerContactAllowed
= true ≠ qualificationEnabled = true`.

Run (pass the manifest path explicitly — the checker does not silently search
home/working directories):

```
node docs/validate_s4d0_complete.mjs operator.s4d.local.json   # explicit path
node docs/validate_s4d0_complete.mjs /path/to/operator.s4d.local.json
```

**Privacy of output.** The completed checker never prints a pinned confidential value
(issuer, client_id, tenant/directory id, secret_reference, endpoints). It emits only
derived booleans, field names, and invariant pass/fail. The manifest it reads is the
gitignored private file; this checker's committed source contains no facts and no secrets.

## Why two checkers, not one flag

The freeze checker is a frozen, pushed artifact whose whole purpose is to prove the
S4D-0 fail-closed posture. Completing registration legitimately inverts two of its
assertions. Keeping the completed-state gate as a separate committed checker preserves the
frozen freeze checker unchanged and gives private operator completion its own reviewable
gate, without ever needing to relax the S4D-0 freeze assertions.

## What neither checker does

Neither checker selects or contacts a provider, retrieves discovery metadata or JWKS,
registers a callback, creates or reads a credential secret, creates a synthetic account,
or enables qualification. `providerContactAllowed = true` and any Q0–Q5 activity require
separate, explicit authorization beyond both checkers.
