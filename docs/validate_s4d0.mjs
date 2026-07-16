#!/usr/bin/env node
/**
 * S4D-0 registration validator (STATIC ONLY — no provider traffic, no credentials,
 * no network). It statically evaluates the S4D provider-registration manifest and the
 * committed public artifacts, enforces the fail-closed rejection rules, computes the
 * three reportable states (registrationValid / providerContactAllowed /
 * qualificationEnabled), and confirms no secret leaks into the public record.
 *
 * It never contacts a provider, retrieves metadata/JWKS, registers a callback, or
 * creates a credential. Exit 0 = fail-closed invariants hold; exit 1 = a violation.
 *
 *   node docs/validate_s4d0.mjs
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const PRIVATE = join(root, "operator.s4d.local.json");
const SCHEMA = join(here, "S4D_OPERATOR_MANIFEST_SCHEMA.json");
const REDACTED = join(here, "S4D_OPERATOR_MANIFEST_REDACTED.md");

const invariants = []; // hard checks; any failure => exit 1
const rejections = []; // reasons registrationValid is false (EXPECTED at S4D-0)
const inv = (name, pass, detail = "") => invariants.push({ name, pass: !!pass, detail });

const readJson = (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : null);
const readText = (p) => (existsSync(p) ? readFileSync(p, "utf8") : "");

const schema = readJson(SCHEMA);
const redacted = readText(REDACTED);
const m = readJson(PRIVATE); // gitignored; may be absent in a fresh clone

// --- public artifacts must exist and carry no secrets ---
inv("public schema present", !!schema);
inv("public redacted record present", redacted.length > 500);

const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /AKIA[0-9A-Z]{16}/,
  /(client_secret|password|api[_-]?key|bearer|access[_-]?token|refresh[_-]?token)\s*[:=]\s*["']?[A-Za-z0-9/+_-]{12,}/i,
];
const publicText = redacted + "\n" + (schema ? JSON.stringify(schema) : "");
const leak = SECRET_PATTERNS.map((r) => r.exec(publicText)).find(Boolean);
inv("no secret-looking values in the public record/schema", !leak, leak ? `matched: ${leak[0].slice(0, 20)}...` : "");

const UNPINNED = "UNPINNED";
const isPinned = (v) => v !== undefined && v !== null && v !== UNPINNED && v !== "";

if (!m) {
  // No private manifest (fresh clone). Evaluate public artifacts only; fail closed.
  inv("private manifest absent → registration cannot be valid (fail closed)", true, "operator.s4d.local.json not present");
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

  // --- HARD fail-closed invariants (never acceptable, regardless of pinning) ---
  inv("real_users == 0", b.real_users === 0, `real_users=${b.real_users}`);
  inv("no offline_access / refresh scope", Array.isArray(o.scopes) && !o.scopes.some((s) => /offline_access|refresh/i.test(s)));
  inv("no 'none' signing algorithm", Array.isArray(o.allowed_signing_algorithms) && !o.allowed_signing_algorithms.map((a) => String(a).toLowerCase()).includes("none"));
  inv("PKCE method is S256", o.pkce_method === "S256");
  inv("response_type is code", o.response_type === "code");
  inv("no wildcard redirect URI", !/\*/.test(String(o.redirect_uri ?? "")) && !/\*/.test(String(o.post_logout_redirect_uri ?? "")));
  inv("all synthetic identities NOT_CREATED", Array.isArray(m.synthetic_identities) && m.synthetic_identities.every((s) => s.creation_status === "NOT_CREATED"));
  inv("both kill switches ENGAGED", ks.contact_kill_switch === "ENGAGED" && ks.qualification_kill_switch === "ENGAGED");
  inv("qualification_enabled gate is false without reviewer_signoff", !(g.qualification_enabled === true && g.reviewer_signoff !== true));

  // The manifest identifies WHERE the secret is held; it must never store the secret.
  const cc = m.credential_custody ?? {};
  inv("secret_present_in_manifest is false (manifest is not a secret store)", cc.secret_present_in_manifest === false);
  const ccLeak = SECRET_PATTERNS.map((r) => r.exec(JSON.stringify(cc))).find(Boolean);
  inv("no secret-looking value inside credential_custody", !ccLeak, ccLeak ? `matched: ${ccLeak[0].slice(0, 20)}...` : "");

  // Formal endpoints, when pinned, must be HTTPS (localhost dev redirect is the only http exception).
  for (const [name, val] of [["authorization_endpoint", o.authorization_endpoint], ["token_endpoint", o.token_endpoint], ["jwks_uri", o.jwks_uri]]) {
    if (isPinned(val)) inv(`${name} is HTTPS`, /^https:\/\//.test(String(val)), String(val).slice(0, 24));
  }

  // --- registration completeness (rejections => registrationValid=false; EXPECTED here) ---
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
  requirePinned("credential_custody.secret_reference", m.credential_custody?.secret_reference);
  requirePinned("credential_custody.rotation_policy", m.credential_custody?.rotation_policy);
  requirePinned("rollback.owner", m.rollback?.owner);
  requirePinned("rollback.procedure_reference", m.rollback?.procedure_reference);
  requirePinned("evidence.retention_period", m.evidence?.retention_period);
  if (!isPinned(b.maximum_cost)) rejections.push("budgets.maximum_cost UNPINNED");
  if (!isPinned(b.maximum_evidence_bytes)) rejections.push("budgets.maximum_evidence_bytes UNPINNED");

  const registrationValid = rejections.length === 0;

  // --- derived reportable states (reviewer logic) ---
  const contactKillDisengaged = ks.contact_kill_switch !== "ENGAGED";
  const qualKillDisengaged = ks.qualification_kill_switch !== "ENGAGED";
  const providerContactAllowed =
    registrationValid && g.privacy_review_complete === true && g.budget_pinned === true &&
    g.evidence_controls_verified === true && g.reviewer_signoff === true && contactKillDisengaged;
  const qualificationEnabled =
    providerContactAllowed && g.credentials_available === true && g.redirect_registered === true &&
    g.synthetic_identities_ready === true && qualKillDisengaged;

  // At S4D-0 these MUST be false (fail closed).
  inv("registrationValid is false at S4D-0 (UNPINNED)", registrationValid === false);
  inv("providerContactAllowed is false", providerContactAllowed === false);
  inv("qualificationEnabled is false", qualificationEnabled === false);
  inv("all gates are false", Object.values(g).every((v) => v === false));

  report({ registrationValid, providerContactAllowed, qualificationEnabled });
}

function report(states) {
  process.stdout.write("=== S4D-0 fail-closed states ===\n");
  process.stdout.write(`registrationValid      = ${states.registrationValid}\n`);
  process.stdout.write(`providerContactAllowed = ${states.providerContactAllowed}\n`);
  process.stdout.write(`qualificationEnabled   = ${states.qualificationEnabled}\n`);
  process.stdout.write(`providerContacted      = false\nqualificationStarted   = false\nrealUsers              = 0\n\n`);

  if (rejections.length) {
    process.stdout.write(`=== registration incomplete — ${rejections.length} unmet condition(s) (EXPECTED at S4D-0) ===\n`);
    for (const r of rejections) process.stdout.write(`  - ${r}\n`);
    process.stdout.write("\n");
  }

  let failed = 0;
  process.stdout.write("=== invariant checks ===\n");
  for (const c of invariants) {
    if (!c.pass) failed++;
    process.stdout.write(`${c.pass ? "PASS" : "FAIL"}  ${c.name}${c.detail ? `  (${c.detail})` : ""}\n`);
  }
  process.stdout.write(`\nS4D-0 validation: ${invariants.length - failed}/${invariants.length} invariants hold\n`);
  process.exit(failed === 0 ? 0 : 1);
}
