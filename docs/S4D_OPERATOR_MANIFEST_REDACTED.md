# S4D-0 — operator provider-registration manifest (PUBLIC REDACTED RECORD)

> **Status: REGISTRATION ONLY — NOTHING PINNED, NO PROVIDER TRAFFIC.** This is the
> committed, redacted public status of the private S4D operator manifest
> (`operator.s4d.local.json`, gitignored, never committed). No provider is selected,
> contacted, or configured; no credential, callback registration, tenant, application
> registration, synthetic account, or qualification evidence exists. Both kill switches
> are engaged. Execution (Q0–Q5) is NOT authorized by this milestone.

This record exposes only non-sensitive status, categories, digests, counts, ceilings, and
gate/fail-closed states. It never exposes secrets, client IDs (where private),
tenant/directory IDs, account IDs, private administrative URLs, personal contact details,
or exact secret-manager paths. Confidential facts live only in the gitignored private
manifest and are pinned there, under review, in a later step.

Schema: `docs/S4D_OPERATOR_MANIFEST_SCHEMA.json`. Static validator:
`docs/validate_s4d0.mjs` (registration linter — no provider traffic).

---

## Reportable fail-closed states

```
registrationValid       = false
providerContactAllowed  = false
qualificationEnabled    = false
providerContacted       = false
qualificationStarted    = false
realUsers               = 0
```

`providerContactAllowed` stays false until the private manifest is complete AND reviewed.
`qualificationEnabled` stays false even after static registration becomes valid, until a
separate explicit execution authorization.

## Kill switches (both ENGAGED)

```
contact_kill_switch        = ENGAGED
qualification_kill_switch  = ENGAGED
```

## Manifest status

| field | public value |
|-------|--------------|
| manifest_version | `s4d0-v1` |
| selected-provider status | `UNPINNED` |
| provider category | `UNPINNED` (standards-compatible OIDC, to be selected on §1 criteria) |
| isolated-environment status | `isolated_test` (declared; not provisioned) |
| issuer digest | not available (UNPINNED) |
| authorization_endpoint digest | not available (UNPINNED) |
| token_endpoint digest | not available (UNPINNED) |
| jwks_uri digest | not available (UNPINNED) |
| algorithm set | `[]` (asymmetric allowlist to be pinned; `none` forbidden) |
| scope set | `["openid"]` (offline-access / refresh forbidden) |
| PKCE / response_type / response_mode | `S256` / `code` / `query` |
| redirect-registration status | not registered (UNPINNED) |
| region category | `UNPINNED` |

## Privacy review

```
privacy_review_complete         = false
processing_region               = UNPINNED
authentication_log_retention    = UNPINNED
administrative_log_retention    = UNPINNED
training_use_policy             = UNPINNED
subprocessor_review_status      = UNPINNED
deletion_procedure_reference    = UNPINNED
```

## Credential custody

```
credentials_available        = false
credential_type              = UNPINNED
credential-custody class     = UNPINNED (secret-manager / env reference abstraction; no plaintext in repo)
secret_reference             = UNPINNED (identifies WHERE the secret is held)
secret_present_in_manifest   = false    (the private manifest never stores the secret)
rotation_policy              = UNPINNED
emergency_revocation         = UNPINNED
```

No credential exists. The private manifest identifies only WHERE a secret would be held
(`secret_reference`) and never stores it (`secret_present_in_manifest = false`); it is not
an alternative plaintext secret store. No secret, client secret, or secret-manager path is
disclosed here.

## Synthetic identity inventory

```
defined:  7   (SYN-01 … SYN-07)
created:  0   (all creation_status = NOT_CREATED)
```

| id | label | expected auth result | expected tenant resolution |
|----|-------|----------------------|----------------------------|
| SYN-01 | active_standard_user | success | tenant derived |
| SYN-02 | active_multi_tenant_user | success | tenant derived from selected owned membership |
| SYN-03 | suspended_provider_user | deny (principal_inactive) | none |
| SYN-04 | disabled_identity_mapping | deny (identity_mapping_denied) | none |
| SYN-05 | mfa_user | success (MFA) | tenant derived |
| SYN-06 | wrong_tenant_membership | success auth, deny tenant | none |
| SYN-07 | deleted_or_disabled_user | deny | none |

No real names, emails, or phone numbers appear in Git.

## Budget ceilings

```
maximum_successful_logins        = 10
maximum_negative_cases           = 20
maximum_token_exchanges          = 40
maximum_metadata_jwks_requests   = 30
maximum_infrastructure_retries   = 5
maximum_failed_attempts          = 20
maximum_wall_clock_minutes       = 240
maximum_cost                     = UNPINNED
maximum_evidence_bytes           = UNPINNED
real_users                       = 0
```

## Evidence controls

```
evidence_controls_verified   = false
location_reference           = UNPINNED
access_policy                = UNPINNED
retention_period             = UNPINNED
redaction_validation_complete = false
```

## Rollback readiness

```
owner                             = UNPINNED
credential_revocation_ready       = false
callback_removal_ready            = false
synthetic_user_disablement_ready  = false
session_revocation_ready          = false
procedure_reference               = UNPINNED
```

## Gate states (all false)

```
configuration_valid          = false
privacy_review_complete      = false
credentials_available        = false
redirect_registered          = false
synthetic_identities_ready   = false
budget_pinned                = false
evidence_controls_verified   = false
reviewer_signoff             = false
qualification_enabled        = false
```

## Supported vs unsupported claims

**Supported after this milestone:**

> Continuum defines a private operator-registration structure and fail-closed validation
> gate for future real-provider qualification.

**NOT supported (must not be stated):**

- a provider has been selected (unless privately pinned AND appropriately publicly disclosed);
- configuration has been validated against a provider;
- credentials exist;
- callback registration exists;
- provider contact is authorized;
- qualification has begun;
- interoperability works.
