# Phase 3 S4D — qualification checklist (RUNBOOK)

> **Status: NOT EXECUTED.** This runbook is inert until a reviewer authorizes S4D
> execution as a separate milestone. Every case below begins `NOT_EXECUTED`. No provider
> is contacted, no credential exists, and no box is checked by this specification
> milestone. Fill this runbook only during an authorized qualification, from redacted
> evidence (see spec §10).

Companion to `PHASE3_S4D_PROVIDER_QUALIFICATION_SPEC.md`. Result categories: `PASS`,
`PASS_WITH_DOCUMENTED_LIMITATIONS`, `FAIL_CLOSED`, `INCONCLUSIVE_INFRASTRUCTURE`,
`NOT_EXECUTED`.

---

## A. Kill-switch preconditions (all must be TRUE before any provider traffic)

```
[ ] provider_config_pinned
[ ] issuer_verified
[ ] audience_verified
[ ] redirect_registered
[ ] credential_reference_valid
[ ] synthetic_identities_ready
[ ] evidence_redaction_verified
[ ] budget_pinned
[ ] reviewer_signoff
[ ] qualification_enabled
```

Unmet-condition list (record any FALSE): ______________________________

---

## B. Budget counters (halt + re-engage kill switch on any breach)

| limit | ceiling | observed | within? |
|-------|---------|----------|---------|
| synthetic users | 7 | | |
| successful logins | 10 | | |
| negative protocol cases | 20 | | |
| total token exchanges | 40 | | |
| metadata/JWKS requests | 30 | | |
| infrastructure retries | 5 | | |
| failed attempts (hard stop) | 25 | | |
| wall-clock qualification | 4 hours | | |
| maximum provider cost | (pinned before start) | | |
| maximum evidence volume | (pinned before start) | | |
| real users | 0 | | |

---

## C. Synthetic identity readiness

```
[ ] active_standard_user        defined, mapped, one owned active membership
[ ] active_multi_tenant_user    defined, mapped, two owned active memberships
[ ] suspended_user              defined, principal suspended
[ ] disabled_mapping_user       defined, mapping disabled/absent
[ ] mfa_user                    defined, MFA enrolled
[ ] wrong_tenant_user           defined, no owned active membership
[ ] deleted_user                defined, deleted/disabled at provider
```

No real person's identity is used.

---

## D. Stage Q0 — static configuration validation (no provider traffic)

```
[ ] issuer pinned          [ ] endpoints pinned      [ ] algorithms pinned
[ ] audience pinned        [ ] redirect URI exact    [ ] scopes minimal
[ ] credential reference present (value not read)    [ ] provider environment isolated
[ ] synthetic identities defined                     [ ] evidence directory protected
[ ] kill switch engaged
```

Expected: `configurationValid=true`, `providerContacted=false`, `qualificationComplete=false`, `realUsers=0`.

Result: `NOT_EXECUTED`

---

## E. Per-case ledger

Each case: expected outcome / observed outcome / evidence reference / failure class /
retry count / claim implication. All begin `NOT_EXECUTED`.

### Q1 — metadata & JWKS

| case | expected | observed | evidence | failure class | retries | claim implication |
|------|----------|----------|----------|---------------|---------|-------------------|
| S4D-Q1-01 issuer_match | iss equals pinned | | | | | |
| S4D-Q1-02 endpoint_origins | expected HTTPS origins | | | | | |
| S4D-Q1-03 jwks_transport | SSRF constraints hold | | | | | |
| S4D-Q1-04 alg_allowlist | only allowed algs | | | | | |
| S4D-Q1-05 cache_rotation | cache + rotation work | | | | | |
| S4D-Q1-06 no_credential_to_jwks | no secret sent | | | | | |
| S4D-Q1-07 keyset_digest_recorded | digest recorded | | | | | |

### Q2 — single successful synthetic login

| case | expected | observed | evidence | failure class | retries | claim implication |
|------|----------|----------|----------|---------------|---------|-------------------|
| S4D-Q2-01 successful_login_active_standard_user | full chain success; no refresh token | | | | | |

### Q3 — negative protocol cases (no session on any failure)

| case | expected | observed | evidence | failure class | retries | claim implication |
|------|----------|----------|----------|---------------|---------|-------------------|
| S4D-Q3-01 wrong_state | deny, no session | | | | | |
| S4D-Q3-02 state_replay | deny, no session | | | | | |
| S4D-Q3-03 expired_transaction | deny, no session | | | | | |
| S4D-Q3-04 wrong_nonce | deny, no session | | | | | |
| S4D-Q3-05 wrong_audience | deny, no session | | | | | |
| S4D-Q3-06 issuer_mismatch | deny, no session | | | | | |
| S4D-Q3-07 unknown_signing_key | deny, no session | | | | | |
| S4D-Q3-08 disabled_user | deny, no session | | | | | |
| S4D-Q3-09 suspended_principal | deny, no session | | | | | |
| S4D-Q3-10 disabled_mapping | deny, no session | | | | | |
| S4D-Q3-11 redirect_mismatch | deny, no session | | | | | |
| S4D-Q3-12 code_reuse | deny, no session | | | | | |
| S4D-Q3-13 token_endpoint_outage | fail closed (infra) | | | | | |
| S4D-Q3-14 jwks_outage | fail closed (infra) | | | | | |
| S4D-Q3-15 revoked_client_credential | deny, no session | | | | | |
| S4D-Q3-16 provider_denial | deny, no session | | | | | |
| S4D-Q3-17 malformed_token_response | deny, no session | | | | | |

### Q4 — rotation & lifecycle

| case | expected | observed | evidence | failure class | retries | claim implication |
|------|----------|----------|----------|---------------|---------|-------------------|
| S4D-Q4-01 signing_key_rotation | new key accepted | | | | | |
| S4D-Q4-02 old_key_overlap | overlap honoured | | | | | |
| S4D-Q4-03 new_key_refresh | refresh picks up new key | | | | | |
| S4D-Q4-04 removed_key_rejection | removed key rejected | | | | | |
| S4D-Q4-05 user_disablement | next login denied | | | | | |
| S4D-Q4-06 membership_revocation | tenant no longer derived | | | | | |
| S4D-Q4-07 session_revocation | session invalid next request | | | | | |
| S4D-Q4-08 client_credential_rotation | old credential rejected | | | | | |
| S4D-Q4-09 logout_behaviour | server-side revoke + clear | | | | | |

---

## F. Q5 — bounded interoperability result

Produced ONLY after Q0–Q4 pass. Overall category: `NOT_EXECUTED`.

This is an interoperability qualification result, **not** production certification.

---

## G. Rollback (execute on completion / abort / ceiling breach)

```
[ ] 1. re-engage authentication kill switch
[ ] 2. disable real-provider configuration (revert to deterministic local path)
[ ] 3. revoke or rotate client credentials
[ ] 4. remove registered callback URIs where required
[ ] 5. revoke synthetic-user sessions
[ ] 6. disable synthetic identities
[ ] 7. preserve redacted qualification evidence
[ ] 8. delete transient provider tokens and local temporary files
[ ] 9. confirm deterministic test path remains separate and intact
[ ] 10. produce rollback report
```

Rollback must not delete historical evidence required to explain the outcome.

---

## H. Reviewer sign-off

```
Provider selected (criteria-approved):  ____________________   date: __________
Q0 authorized by reviewer:              ____________________   date: __________
Q1 authorized by reviewer:              ____________________   date: __________
Q2 authorized by reviewer:              ____________________   date: __________
Q3 authorized by reviewer:              ____________________   date: __________
Q4 authorized by reviewer:              ____________________   date: __________
Q5 result reviewed:                     ____________________   date: __________
Rollback confirmed:                     ____________________   date: __________
```
