#!/usr/bin/env node
/**
 * S4D-0 COMPLETED-registration validator (STATIC ONLY — no provider traffic, no
 * network, no credentials). Companion to docs/validate_s4d0.mjs.
 *
 * docs/validate_s4d0.mjs is the S4D-0 FREEZE checker: it hard-asserts the fail-closed
 * frozen posture (registrationValid=false, all gates false). Completing the private
 * registration INTENTIONALLY inverts those two assertions, so the freeze checker exits 1
 * on a completed manifest — by design, not a regression.
 *
 * This validator is the COMPLETED-state gate. It requires the operator-completed private
 * manifest to satisfy ALL of:
 *     - every mandatory operator field pinned  (=> registrationValid = true)
 *     - privacy review complete gate           (privacy_review_complete = true)
 *     - budget ceilings pinned + gate          (maximum_cost/evidence_bytes pinned, budget_pinned = true)
 *     - evidence controls verified gate        (evidence_controls_verified = true)
 *     - rollback readiness complete            (owner+procedure pinned, all *_ready = true)
 *     - reviewer sign-off for registration     (reviewer_signoff = true)
 *     - real_users = 0
 *     - contact kill switch = ENGAGED          (EXPLICIT fail if disengaged)
 *     - qualification kill switch = ENGAGED    (EXPLICIT fail if disengaged)
 * and preserving every hard fail-closed invariant (no offline_access/refresh, no 'none'
 * alg, PKCE S256, response_type=code, no wildcard redirect, all synthetic identities
 * NOT_CREATED, secret_present_in_manifest=false, no secret-looking value anywhere, HTTPS
 * endpoints).
 *
 * Governing implication enforced here — registrationValid=true is NOT authority to
 * contact the provider or enable qualification:
 *     registrationValid      = true
 *     providerContactAllowed = false   (held false by the ENGAGED contact kill switch)
 *     qualificationEnabled   = false
 * With sign-off + gates + registrationValid all true, providerContactAllowed reduces to
 * (contact kill switch disengaged); so disengaging either kill switch fails this checker.
 *
 * It NEVER prints a pinned confidential value (issuer, client_id, tenant/directory id,
 * secret_reference, endpoints): only derived booleans, field/category names, and
 * invariant pass/fail. It never contacts a provider, retrieves metadata/JWKS, registers
 * a callback, or creates a credential. Exit 0 = completed-state invariants hold; exit 1 =
 * a violation.
 *
 *   node docs/validate_s4d0_complete.mjs <path-to-manifest>   # e.g. operator.s4d.local.json
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const arg = process.argv[2];
// Require an explicit manifest path; do not silently search home/cwd. Fall back only to
// the repo-root private manifest when no path is given (documented convenience).
const root = join(here, "..");
const PRIVATE = arg ? (isAbsolute(arg) ? arg : join(process.cwd(), arg)) : join(root, "operator.s4d.local.json");
const SCHEMA = join(here, "S4D_OPERATOR_MANIFEST_SCHEMA.json");
const REDACTED = join(here, "S4D_OPERATOR_MANIFEST_REDACTED.md");

const invariants = []; // hard checks; any failure => exit 1
const rejections = []; // reasons registrationValid would still be false (must be empty here)
const inv = (name, pass, detail = "") => invariants.push({ name, pass: !!pass, detail });

const readJson = (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : null);
const readText = (p) => (existsSync(p) ? readFileSync(p, "utf8") : "");

const schema = readJson(SCHEMA);
const redacted = readText(REDACTED);
const m = readJson(PRIVATE);

const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /AKIA[0-9A-Z]{16}/,
  /(client_secret|password|api[_-]?key|bearer|access[_-]?token|refresh[_-]?token)\s*[:=]\s*["']?[A-Za-z0-9/+_-]{12,}/i,
];

const UNPINNED = "UNPINNED";
const isPinned = (v) => v !== undefined && v !== null && v !== UNPINNED && v !== "";

// --- public artifacts must exist and carry no secrets (defensive, same as the freeze checker) ---
inv("public schema present", !!schema);
inv("public redacted record present", redacted.length > 500);
const publicText = redacted + "\n" + (schema ? JSON.stringify(schema) : "");
const publicLeak = SECRET_PATTERNS.map((r) => r.exec(publicText)).find(Boolean);
inv("no secret-looking values in the public record/schema", !publicLeak, publicLeak ? `matched: ${publicLeak[0].slice(0, 20)}...` : "");

// A COMPLETED registration requires the private manifest to be present.
if (!m) {
  inv("completed private manifest present", false, `${PRIVATE} not found — a completed registration cannot be validated`);
  report({ registrationValid: false, providerContactAllowed: false, qualificationEnabled: false });
} else {
  // --- structural required keys ---
  for (const k of ["manifest_version", "provider", "oidc", "privacy", "credential_custody", "synthetic_identities", "budgets", "evidence", "rollback", "gates"]) {
    inv(`manifest has '${k}'`, k in m);
  }
  inv("manifest_version is s4d0-v1", m.manifest_version === "s4d0-v1");

  const o = m.oidc ?? {};
  const b = m.budgets ?? {};
  const g = m.gates ?? {};
  const ks = m.kill_switches ?? {};
  const cc = m.credential_custody ?? {};
  const rb = m.rollback ?? {};

  // --- HARD fail-closed invariants that MUST persist through completion ---
  inv("real_users == 0", b.real_users === 0, `real_users=${b.real_users}`);
  inv("no offline_access / refresh scope", Array.isArray(o.scopes) && !o.scopes.some((s) => /offline_access|refresh/i.test(s)));
  inv("no 'none' signing algorithm", Array.isArray(o.allowed_signing_algorithms) && !o.allowed_signing_algorithms.map((a) => String(a).toLowerCase()).includes("none"));
  inv("PKCE method is S256", o.pkce_method === "S256");
  inv("response_type is code", o.response_type === "code");
  inv("no wildcard redirect URI", !/\*/.test(String(o.redirect_uri ?? "")) && !/\*/.test(String(o.post_logout_redirect_uri ?? "")));
  inv("all synthetic identities NOT_CREATED", Array.isArray(m.synthetic_identities) && m.synthetic_identities.every((s) => s.creation_status === "NOT_CREATED"));

  // The manifest identifies WHERE the secret is held; it must never store the secret.
  inv("secret_present_in_manifest is false (manifest is not a secret store)", cc.secret_present_in_manifest === false);
  const ccLeak = SECRET_PATTERNS.map((r) => r.exec(JSON.stringify(cc))).find(Boolean);
  inv("no secret-looking value inside credential_custody", !ccLeak, ccLeak ? `matched: ${ccLeak[0].slice(0, 20)}...` : "");
  const anyLeak = SECRET_PATTERNS.map((r) => r.exec(JSON.stringify(m))).find(Boolean);
  inv("no secret-looking value anywhere in the manifest", !anyLeak, anyLeak ? `matched: ${anyLeak[0].slice(0, 20)}...` : "");

  // Formal endpoints must be HTTPS.
  for (const [name, val] of [["authorization_endpoint", o.authorization_endpoint], ["token_endpoint", o.token_endpoint], ["jwks_uri", o.jwks_uri], ["issuer", o.issuer]]) {
    inv(`${name} is HTTPS`, /^https:\/\//.test(String(val)));
  }

  // --- registration completeness: every required fact MUST now be pinned ---
  const requirePinned = (path, val) => { if (!isPinned(val)) rejections.push(`${path} is UNPINNED`); };
  requirePinned("provider.provider_name", m.provider?.provider_name);
  requirePinned("provider.registration_id", m.provider?.registration_id);
  requirePinned("provider.tenant_or_directory_id", m.provider?.tenant_or_directory_id);
  requirePinned("provider.region", m.provider?.region);
  requirePinned("oidc.issuer", o.issuer);
  requirePinned("oidc.authorization_endpoint", o.authorization_endpoint);
  requirePinned("oidc.token_endpoint", o.token_endpoint);
  requirePinned("oidc.jwks_uri", o.jwks_uri);
  requirePinned("oidc.client_id", o.client_id);
  requirePinned("oidc.client_authentication_method", o.client_authentication_method);
  requirePinned("oidc.redirect_uri", o.redirect_uri);
  if (!Array.isArray(o.audiences) || o.audiences.length === 0) rejections.push("oidc.audiences missing exact audience");
  if (!Array.isArray(o.allowed_signing_algorithms) || o.allowed_signing_algorithms.length === 0) rejections.push("oidc.allowed_signing_algorithms empty");
  if (m.privacy?.terms_reviewed_at === null || !isPinned(m.privacy?.training_use_policy)) rejections.push("privacy review incomplete");
  requirePinned("credential_custody.secret_reference", cc.secret_reference);
  requirePinned("credential_custody.rotation_policy", cc.rotation_policy);
  requirePinned("rollback.owner", rb.owner);
  requirePinned("rollback.procedure_reference", rb.procedure_reference);
  requirePinned("evidence.retention_period", m.evidence?.retention_period);
  if (!isPinned(b.maximum_cost)) rejections.push("budgets.maximum_cost UNPINNED");
  if (!isPinned(b.maximum_evidence_bytes)) rejections.push("budgets.maximum_evidence_bytes UNPINNED");

  const registrationValid = rejections.length === 0;

  // --- derived reportable states (SAME reviewer logic as the freeze checker) ---
  const contactKillDisengaged = ks.contact_kill_switch !== "ENGAGED";
  const qualKillDisengaged = ks.qualification_kill_switch !== "ENGAGED";
  const providerContactAllowed =
    registrationValid && g.privacy_review_complete === true && g.budget_pinned === true &&
    g.evidence_controls_verified === true && g.reviewer_signoff === true && contactKillDisengaged;
  const qualificationEnabled =
    providerContactAllowed && g.credentials_available === true && g.redirect_registered === true &&
    g.synthetic_identities_ready === true && qualKillDisengaged;

  // --- COMPLETED-state requirements (all must hold) ---
  inv("registrationValid is TRUE (registration complete)", registrationValid === true, rejections.length ? `${rejections.length} still unpinned` : "");
  inv("privacy review complete gate", g.privacy_review_complete === true);
  inv("budget ceilings pinned + budget_pinned gate", isPinned(b.maximum_cost) && isPinned(b.maximum_evidence_bytes) && g.budget_pinned === true);
  inv("evidence controls verified gate", g.evidence_controls_verified === true);
  inv("rollback readiness complete", rb.credential_revocation_ready === true && rb.callback_removal_ready === true && rb.synthetic_user_disablement_ready === true && rb.session_revocation_ready === true);
  inv("reviewer sign-off for registration present", g.reviewer_signoff === true);
  // Kill switches are the barrier to contact/qualification at THIS milestone: fail if disengaged.
  inv("contact kill switch ENGAGED (fail if disengaged)", ks.contact_kill_switch === "ENGAGED");
  inv("qualification kill switch ENGAGED (fail if disengaged)", ks.qualification_kill_switch === "ENGAGED");
  inv("qualification_enabled gate is false", g.qualification_enabled === false);
  // Synthetic accounts are created during qualification, never at registration completion.
  inv("synthetic_identities_ready gate is false (accounts not created)", g.synthetic_identities_ready === false);
  // Governing implication: registrationValid=true does NOT authorize contact/qualification.
  inv("providerContactAllowed is false (registration ≠ contact authority)", providerContactAllowed === false);
  inv("qualificationEnabled is false (registration ≠ qualification authority)", qualificationEnabled === false);

  report({ registrationValid, providerContactAllowed, qualificationEnabled });
}

function report(states) {
  process.stdout.write("=== S4D-0 COMPLETED-state validation (no confidential values printed) ===\n");
  process.stdout.write(`registrationValid      = ${states.registrationValid}   (target: true)\n`);
  process.stdout.write(`providerContactAllowed = ${states.providerContactAllowed}   (target: false)\n`);
  process.stdout.write(`qualificationEnabled   = ${states.qualificationEnabled}   (target: false)\n`);
  process.stdout.write(`providerContacted      = false\nqualificationStarted   = false\nrealUsers              = 0\n\n`);

  if (rejections.length) {
    process.stdout.write(`=== registration NOT complete — ${rejections.length} field(s) still unpinned ===\n`);
    for (const r of rejections) process.stdout.write(`  - ${r}\n`); // field names only, never values
    process.stdout.write("\n");
  }

  let failed = 0;
  process.stdout.write("=== invariant checks ===\n");
  for (const c of invariants) {
    if (!c.pass) failed++;
    process.stdout.write(`${c.pass ? "PASS" : "FAIL"}  ${c.name}${c.detail ? `  (${c.detail})` : ""}\n`);
  }
  process.stdout.write(`\nS4D-0 completed-state validation: ${invariants.length - failed}/${invariants.length} invariants hold\n`);
  process.exit(failed === 0 ? 0 : 1);
}
