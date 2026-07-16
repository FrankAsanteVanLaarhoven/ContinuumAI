# Phase 3 S4D — real-provider onboarding & interoperability qualification (SPECIFICATION)

> **Status: SPECIFICATION ONLY — UNIMPLEMENTED.** No provider is selected, configured,
> contacted, or integrated. No credentials exist. No runtime code, dependency, browser
> registration, or deployment configuration is changed by this milestone. This document
> defines exactly how ONE standards-compatible identity provider will be configured,
> qualified, evidenced, and rolled back **before** any real external authentication
> traffic is permitted. Qualification remains blocked (see §12 kill switch) until every
> precondition is met and a reviewer authorizes execution as a separate milestone.

Vendor-neutral in structure. Although the first qualification ultimately selects one
provider, nothing here is written to favour a particular vendor, and no provider is
chosen because it is expected to produce a favourable result.

S4D qualifies **initial authentication and session establishment only**, against the
already-pushed S4C browser transport, S4B one-time transaction boundary, S4A
cryptographic verification, S3 identity mapping/session, and S2B tenant derivation. It
does not change any of them; it exercises them against a real provider under strict
controls.

---

## 1. Provider selection criteria

A provider is eligible for the first qualification only if it objectively satisfies ALL
of the following, verified from the provider's own current documentation at selection
time (not from marketing):

- Standards-compatible OpenID Connect **authorization-code** flow.
- **PKCE S256** support.
- **Stable issuer** identifier (`iss`) that does not vary per request.
- **Exact audience** (`aud`) configuration for the registered client.
- **JWKS endpoint** with documented key **rotation** behaviour.
- Configurable **redirect URI allowlist** with exact-match registration.
- A **test tenant / isolated development environment** separate from any production
  directory.
- Ability to create **synthetic test identities**.
- **Administrative audit logs** for authentications and admin actions.
- **MFA support** available for later qualification (not required in Q2).
- Documented **token lifetime** and **signing algorithms** (asymmetric; e.g. RS256 /
  ES256), no symmetric id-token signing.
- **Regional processing** information (where authentication is processed).
- Documented **data-retention** and **training-use** terms for authentication data.
- Ability to **revoke** users, sessions, applications, and credentials.
- **No requirement** for a provider-specific SDK.
- **Compatibility with generic JOSE/OIDC libraries** (the repository's already-pinned
  `jose`; no new dependency is added by S4D).
- **Feasible test cost** and account controls (spend cap / free test tier).

**Selection rule.** The provider must be selected on these criteria alone. It must not
be selected because it is expected to pass qualification more easily, and the criteria
must be recorded and reviewer-approved before a provider is named.

---

## 2. Trust-boundary definition

The complete external-authentication transition and the component that OWNS each
decision:

```
browser
  → configured authorization endpoint        [owner: S4C login route + trusted client registry]
  → provider authentication                   [owner: external provider]
  → configured callback                       [owner: S4C callback route + host/origin validation]
  → S4B one-time transaction consumption      [owner: S4B store (atomic single-use)]
  → provider token endpoint                   [owner: real code exchanger (replaces the S4B fixture)]
  → S4A signature and claims verification      [owner: S4A JWT/JWS verifier + JWKS provider]
  → S3 external identity mapping               [owner: S3 PrincipalMapper (issuer, subject)]
  → S3 session creation                        [owner: S3 SessionManager (digest-only)]
  → S2B trusted tenant derivation              [owner: S2B trusted DB context]
```

**The provider establishes an external identity ASSERTION only.** It does NOT establish
any of the following — each remains owned entirely inside Continuum:

- Continuum **tenant authority** (S2B, derived from an owned active membership);
- Continuum **roles**;
- **intent** authority;
- **capability** scope;
- **consent**;
- **memory** access;
- **action** permission.

A validly-authenticated external identity that has no active Continuum principal
mapping, or no owned active membership, yields **no tenant and no authority**. S2B
remains the sole tenant-authority transition; a real provider does not change that.

---

## 3. Exact provider configuration fields (pinned before contact)

Every field below MUST be pinned in trusted configuration and reviewer-approved before
any provider contact. Assertion-controlled values MUST NOT be used to discover or
override any of them at runtime.

```
provider_registration_id        # opaque internal id for this registration
issuer                          # exact expected iss; compared byte-for-byte
authorization_endpoint          # expected HTTPS origin, pinned
token_endpoint                  # expected HTTPS origin, pinned
jwks_uri                        # expected HTTPS origin, pinned; SSRF-constrained (S4A)
userinfo_endpoint               # optional; only if used, pinned
client_id
client_authentication_method    # none (public+PKCE) | private_key_jwt | client_secret_*
allowed_redirect_uris           # exact-match list (no wildcard/prefix)
post_logout_redirect_uris       # exact-match list
allowed_scopes                  # minimal: openid (+ profile/email only if required)
expected_audiences              # exact aud pin(s)
allowed_signing_algorithms      # asymmetric allowlist (e.g. RS256, ES256)
required_claims                 # iss, sub, aud, exp, iat, nonce (+ auth_time if used)
maximum_token_age               # bound in seconds
clock_skew                      # bound in seconds
PKCE_method                     # S256 only
response_type                   # code
response_mode                   # query (or form_post if pinned)
tenant_or_directory_identifier  # provider test tenant / directory id
endpoint_region                 # documented processing region
provider_environment            # isolated test/dev environment marker
```

**Discovery rule.** If OIDC discovery metadata is used, it MUST be fetched from the
**preregistered issuer**'s well-known document over the pinned HTTPS origin, and every
discovered value MUST be validated to **equal** the pinned expectation. A discovered
value that disagrees with a pinned value fails closed; discovery never widens the
allowlist and never introduces a new endpoint origin.

---

## 4. Credential custody

The specification requires, before any credential exists:

- **Storage location.** A secret-manager reference or an environment reference
  abstraction only — never a checked-in file. (No fabricated KMS/HSM claim is made
  before one exists; the abstraction is a reference, not an asserted hardware custody.)
- **Access.** A named, least-privilege set of operators; retrieval is auditable.
- **Rotation frequency.** A defined maximum age with scheduled rotation.
- **Emergency revocation.** A documented immediate-revocation procedure.
- **Versioning / key identifiers.** Each credential carries a version identifier;
  rotation retains the identifier lineage.
- **Retrieval audit trail.** Every retrieval is recorded (who, when, purpose) without
  recording the secret value.
- **Dev vs production separation.** Qualification credentials are distinct from any
  future production credential and from the deterministic local development path.
- **Never** in Git, shell history, evidence, logs, browser code, or test snapshots.
- **No plaintext local credential file** unless explicitly marked temporary, kept
  **outside the repository**, and deleted by the rollback plan (§14).

**Public-client case.** If the provider client is public (no client secret), the spec
records **why no client secret exists** (public clients cannot keep one confidential)
and states that PKCE S256 and exact redirect registration therefore carry more of the
security burden: the authorization code is protected in transit by PKCE, and the
redirect allowlist prevents code delivery to an attacker-controlled endpoint.

---

## 5. Redirect registration

Redirect URIs are pinned exactly. The registration REJECTS:

- wildcard redirect URIs;
- prefix matching;
- arbitrary ports in formal qualification;
- user-controlled return URLs;
- plaintext HTTP except an explicitly isolated local-development entry;
- multiple loosely scoped callbacks.

Three **separate** registrations are maintained, never shared:

```
local deterministic development   http://localhost:<pinned>/api/auth/callback   (isolated dev only)
formal qualification environment  https://<qualification-host>/api/auth/callback
future production environment      https://<production-host>/api/auth/callback   (NOT used by S4D)
```

The S4D qualification MUST NOT reuse the production redirect registration. The
qualification host is a dedicated non-production host.

---

## 6. Data handling and privacy

At execution time (a later milestone), the following MUST be reviewed and recorded from
the provider's **verified current terms**, not assumed here:

- region of authentication processing;
- authentication log retention;
- administrative log retention;
- whether authentication data is used for provider training;
- subprocessors;
- account telemetry collected;
- IP-address handling;
- user-profile fields returned;
- token/assertion retention **by Continuum** (see evidence §10 — digests only);
- provider-side data-deletion procedure;
- test-identity deletion procedure.

**Only synthetic identities are used.** No real client, employee, health, financial,
research-participant, or asylum-case information is transmitted to or through the
provider during qualification. If the provider's training-use terms cannot be confirmed
to exclude authentication data, qualification does not proceed with any data beyond the
synthetic set, and the limitation is recorded.

---

## 7. Synthetic identity set

Predefined synthetic accounts (no real person's identity is used). Concrete
subjects/emails are assigned at execution time as `synthetic+<label>@<qualification-domain>`.

| label | provider status | expected issuer | expected subject | Continuum mapping | membership state | expected auth result | expected tenant resolution |
|-------|-----------------|-----------------|------------------|-------------------|------------------|----------------------|----------------------------|
| active_standard_user | active | pinned `iss` | stable `sub` A | active principal | one owned active membership | success | tenant derived from that membership |
| active_multi_tenant_user | active | pinned `iss` | stable `sub` B | active principal | two owned active memberships | success | tenant derived from the selected owned membership (hint disambiguates; never caller-named) |
| suspended_user | active at provider | pinned `iss` | stable `sub` C | principal suspended | n/a | deny (principal_inactive) | none |
| disabled_mapping_user | active at provider | pinned `iss` | stable `sub` D | mapping disabled / absent | n/a | deny (identity_mapping_denied) | none |
| mfa_user | active + MFA | pinned `iss` | stable `sub` E | active principal | one owned active membership | success (MFA) | tenant derived |
| wrong_tenant_user | active | pinned `iss` | stable `sub` F | active principal | membership only in a tenant it does not own / not active | success auth, deny tenant | no tenant (no owned active membership) |
| deleted_user | deleted/disabled at provider | pinned `iss` | stable `sub` G | mapping absent | n/a | deny (provider denies or mapping absent) | none |

A provider-authenticated identity NEVER implies a tenant; the tenant column is always
derived by S2B from an owned active membership, or is absent.

---

## 8. Qualification stages (Q0–Q5)

Staged; each stage gates the next. No stage runs until the kill switch (§12) reports all
preconditions met and a reviewer authorizes the specific stage.

### Q0 — Static configuration validation (NO provider traffic)

Verify: issuer pinned; endpoints pinned; algorithms pinned; audience pinned; redirect
URI exact; scopes minimal; credential reference present (value not read); provider
environment isolated; synthetic identities defined; evidence directory protected; kill
switch engaged.

Expected state:

```
configurationValid = true
providerContacted  = false
qualificationComplete = false
realUsers = 0
```

### Q1 — Metadata & JWKS qualification (retrieval only)

Allow ONLY discovery-metadata / JWKS retrieval. Verify: `iss` matches exactly;
endpoints use the expected HTTPS origins; JWKS transport restrictions hold (S4A SSRF
constraints); key types and algorithms are in the allowlist; cache and rotation logic
works; no unexpected redirect; no credential is sent to the JWKS endpoint; the key-set
digest is recorded. No user login yet.

Case IDs: `S4D-Q1-01 issuer_match`, `S4D-Q1-02 endpoint_origins`, `S4D-Q1-03 jwks_transport`,
`S4D-Q1-04 alg_allowlist`, `S4D-Q1-05 cache_rotation`, `S4D-Q1-06 no_credential_to_jwks`,
`S4D-Q1-07 keyset_digest_recorded`.

### Q2 — Single successful synthetic login

Use `active_standard_user` only. Verify the full chain: S4C browser route → S4B
state/nonce/PKCE → **real** code exchange → S4A cryptographic verification → S3 mapping →
S3 digest-only session → S2B membership-derived tenant → secure cookie handling →
redacted evidence → **no refresh token requested or stored**. Output is
**non-production evidence**.

Case IDs: `S4D-Q2-01 successful_login_active_standard_user`.

### Q3 — Negative protocol cases (no session on any failure)

Each case MUST fail closed and mint no session:

```
S4D-Q3-01 wrong_state
S4D-Q3-02 state_replay
S4D-Q3-03 expired_transaction
S4D-Q3-04 wrong_nonce
S4D-Q3-05 wrong_audience
S4D-Q3-06 issuer_mismatch
S4D-Q3-07 unknown_signing_key
S4D-Q3-08 disabled_user
S4D-Q3-09 suspended_principal
S4D-Q3-10 disabled_mapping
S4D-Q3-11 redirect_mismatch
S4D-Q3-12 code_reuse
S4D-Q3-13 token_endpoint_outage
S4D-Q3-14 jwks_outage
S4D-Q3-15 revoked_client_credential
S4D-Q3-16 provider_denial
S4D-Q3-17 malformed_token_response
```

### Q4 — Rotation and lifecycle

```
S4D-Q4-01 signing_key_rotation
S4D-Q4-02 old_key_overlap            # where the provider permits an overlap window
S4D-Q4-03 new_key_refresh
S4D-Q4-04 removed_key_rejection
S4D-Q4-05 user_disablement
S4D-Q4-06 membership_revocation
S4D-Q4-07 session_revocation
S4D-Q4-08 client_credential_rotation
S4D-Q4-09 logout_behaviour
```

### Q5 — Bounded interoperability result

Produced only after Q0–Q4 pass. It is an **interoperability qualification result**, NOT
production certification (see §15, §16).

---

## 9. Failure handling

Predeclared classes:

```
provider_unavailable
authorization_endpoint_error
token_endpoint_timeout
token_endpoint_5xx
rate_limit
invalid_client
invalid_grant
redirect_mismatch
jwks_unavailable
jwks_changed_unexpectedly
issuer_mismatch
audience_mismatch
signature_invalid
nonce_mismatch
state_replay
user_denied
mapping_missing
principal_suspended
session_store_unavailable
evidence_write_failed
```

Rules:

- **Fail closed** on every class.
- **Never** silently fall back to deterministic authentication (the deterministic local
  server and fixture exchanger remain separately configured and are never selected as a
  fallback for a failed real exchange).
- **Do not retry** semantic authentication failures (`invalid_grant`, `signature_invalid`,
  `issuer_mismatch`, `audience_mismatch`, `nonce_mismatch`, `state_replay`,
  `redirect_mismatch`, `user_denied`, `mapping_missing`, `principal_suspended`).
- **Infrastructure retries** (`provider_unavailable`, `token_endpoint_timeout`,
  `token_endpoint_5xx`, `jwks_unavailable`, `rate_limit`) are **bounded** (§13) and every
  retry is recorded.
- A **consumed S4B transaction is never reopened** — a failed real exchange does not make
  the transaction reusable; a fresh login creates a new transaction.
- **No session is minted** until the entire chain succeeds.

---

## 10. Evidence requirements

Record (redacted; safe ids + digests + metadata only):

- provider registration identifier;
- issuer;
- endpoint-origin digests or safe identifiers;
- key-set digest;
- signing algorithm;
- safe key identifier (`kid`);
- qualification case id;
- result classification (§15);
- token timing metadata (iat/exp/auth_time as durations/instants, not the token);
- mapping outcome;
- session id after success;
- tenant-resolution outcome;
- request and trace ids.

Never record:

- client secret;
- authorization code;
- raw access token;
- raw identity token;
- raw refresh token;
- raw state;
- raw nonce;
- PKCE verifier;
- session credential;
- full claim set;
- complete callback URL.

Evidence redaction reuses the S3/S4A/S4B/S4C discipline (keyed digests, safe ids) and is
verified before Q1 (a kill-switch precondition).

---

## 11. No refresh tokens

The first qualification requests **no offline access** and stores **no refresh token**.

> S4D qualifies initial authentication and session establishment only. Long-lived
> provider refresh credentials require a separate threat model, custody design,
> revocation model, rotation policy, and implementation milestone.

The requested scope set is minimal (`openid`, plus `profile`/`email` only if a
qualification case requires a returned attribute); no long-lived-access scope is
requested.

---

## 12. Kill switch

Qualification remains **blocked** unless EVERY condition is true:

```
provider_config_pinned
issuer_verified
audience_verified
redirect_registered
credential_reference_valid
synthetic_identities_ready
evidence_redaction_verified
budget_pinned
reviewer_signoff
qualification_enabled
```

Any mismatch returns an explicit **unmet-condition list** and no provider traffic occurs.
The kill switch remains available (can be re-engaged to halt) **throughout** qualification,
not only at the start.

---

## 13. Budget and limits

Predeclared ceilings (ceilings, NOT targets). Exceeding any ceiling halts qualification
and re-engages the kill switch:

```
synthetic users:             7
successful logins:          10
negative protocol cases:    20
total token exchanges:      40
metadata/JWKS requests:     30
infrastructure retries:      5
failed attempts (hard stop): 25
wall-clock qualification:    4 hours
maximum provider cost:       pinned free-tier / spend-cap (recorded before start)
maximum evidence volume:     pinned (recorded before start)
real users:                  0
```

---

## 14. Rollback plan

Defined **before** qualification; executed on completion, on abort, or on any ceiling
breach:

1. Re-engage the authentication kill switch.
2. Disable the real-provider configuration (revert to deterministic local path).
3. Revoke or rotate client credentials.
4. Remove registered callback URIs where required.
5. Revoke synthetic-user sessions.
6. Disable synthetic identities.
7. Preserve redacted qualification evidence.
8. Delete transient provider tokens and local temporary files.
9. Confirm the deterministic test path remains separate and intact.
10. Produce a rollback report.

Rollback MUST NOT delete historical evidence required to explain the qualification
outcome (step 7 preserves it; step 8 deletes only transient tokens/temp files).

---

## 15. Qualification result categories

```
PASS
PASS_WITH_DOCUMENTED_LIMITATIONS
FAIL_CLOSED
INCONCLUSIVE_INFRASTRUCTURE
NOT_EXECUTED
```

No single "working" flag is used. Each qualification case records:

```
expected outcome
observed outcome
evidence reference
failure class
retry count
claim implication
```

Before execution every case is `NOT_EXECUTED`.

---

## 16. Supported vs unsupported claims

**Supported after this specification only:**

> Continuum defines a reviewed real-provider onboarding and interoperability qualification
> protocol.

**Explicitly NOT supported (must not be stated) before/at spec time:**

- a provider has been integrated;
- interoperability has been demonstrated;
- real login works;
- provider key rotation has been validated;
- browser authentication is production-ready.

---

## 17. Required specification-validation checks

This milestone is documentation-only; the following are validated by `docs/validate_s4d.mjs`
(a documentation linter, not a product/runtime test):

- both S4D documents present and non-empty;
- all required sections (§1–§17) present;
- no credential placeholders resembling secrets (no private-key blocks, AWS-key patterns,
  or assigned confidential-client values);
- no wildcard redirect URI;
- no refresh-token / offline-access scope requested (the exact scope string never appears);
- no production-user language (real users pinned to 0);
- qualification case identifiers unique;
- kill-switch conditions complete (all 10);
- rollback steps present (all 10);
- supported AND unsupported claims present;
- no provider-contact shell command included (no network-fetch commands or POST-to-endpoint examples);
- no provider-specific SDK dependency added (no package-manager install of an SDK).

See `PHASE3_S4D_QUALIFICATION_CHECKLIST.md` for the operational runbook (all cases begin
`NOT_EXECUTED`).
