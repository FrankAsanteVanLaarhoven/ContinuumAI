#!/usr/bin/env node
/**
 * S4D specification-validation linter (documentation-only; NOT a product/runtime test).
 *
 * Verifies the S4D specification and checklist satisfy the reviewer's required
 * document-validation checks (spec §17). It reads only the docs — it never contacts a
 * provider, adds a dependency, or changes runtime code. Exit 0 = all checks pass;
 * exit 1 = one or more failed.
 *
 *   node docs/validate_s4d.mjs
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const SPEC = join(here, "PHASE3_S4D_PROVIDER_QUALIFICATION_SPEC.md");
const CHECK = join(here, "PHASE3_S4D_QUALIFICATION_CHECKLIST.md");
const THREAT = join(here, "threat-model.md");

const results = [];
const ok = (name, cond, detail = "") => results.push({ name, pass: !!cond, detail });

function read(p) {
  try { return readFileSync(p, "utf8"); } catch { return null; }
}

const spec = read(SPEC);
const check = read(CHECK);
const threat = read(THREAT);

// 1) both documents present and non-empty
ok("both S4D documents present and non-empty", spec && spec.length > 500 && check && check.length > 500);

if (spec) {
  // 2) all required sections (1..17) present
  const missing = [];
  for (let n = 1; n <= 17; n++) if (!new RegExp(`^## ${n}\\.`, "m").test(spec)) missing.push(n);
  ok("all required sections (1-17) present", missing.length === 0, missing.length ? `missing: ${missing}` : "");

  // 3) no credential placeholders resembling secrets
  const secretPatterns = [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    /AKIA[0-9A-Z]{16}/,
    /(client_secret|password|api[_-]?key|access[_-]?token|bearer)\s*[:=]\s*["']?[A-Za-z0-9/+_-]{12,}/i,
  ];
  const secretHit = secretPatterns.map((r) => r.exec(spec)).find(Boolean);
  ok("no credential placeholders resembling secrets", !secretHit, secretHit ? `matched: ${secretHit[0].slice(0, 24)}...` : "");

  // 4) no wildcard redirect URI (asterisk in a URL or a wildcard domain)
  const wildcard = /https?:\/\/\S*\*/.test(spec) || /\*\.[a-z]/i.test(spec);
  ok("no wildcard redirect URI", !wildcard);

  // 5) no refresh-token / offline_access scope requested + a No-refresh section exists
  ok("no refresh-token / offline_access scope requested", !/offline_access/.test(spec) && /##\s*11\.\s*No refresh tokens/i.test(spec));

  // 6) no production-user language; real users pinned to 0
  const prodUser = /\bproduction users?\b/i.test(spec);
  const realUsersZero = /realUsers\s*=\s*0/.test(spec) && /real users:\s*0/.test(spec);
  ok("no production-user language; real users pinned to 0", !prodUser && realUsersZero);

  // 7) qualification case identifiers unique (within the spec)
  const specIds = spec.match(/S4D-Q\d+-\d+/g) ?? [];
  const specDupes = specIds.filter((id, i) => specIds.indexOf(id) !== i);
  ok("qualification case identifiers unique (spec)", specIds.length > 0 && specDupes.length === 0, specDupes.length ? `dupes: ${[...new Set(specDupes)]}` : `${specIds.length} ids`);

  // 8) kill-switch conditions complete (all 10)
  const killConds = [
    "provider_config_pinned", "issuer_verified", "audience_verified", "redirect_registered",
    "credential_reference_valid", "synthetic_identities_ready", "evidence_redaction_verified",
    "budget_pinned", "reviewer_signoff", "qualification_enabled",
  ];
  const killMissing = killConds.filter((c) => !spec.includes(c));
  ok("kill-switch conditions complete (10)", killMissing.length === 0, killMissing.length ? `missing: ${killMissing}` : "");

  // 9) rollback steps present (>= 10 numbered steps in section 14)
  const rb = spec.slice(spec.indexOf("## 14."), spec.indexOf("## 15."));
  const rbSteps = (rb.match(/^\s*\d+\.\s/gm) ?? []).length;
  ok("rollback steps present (>=10)", rbSteps >= 10, `${rbSteps} steps`);

  // 10) supported AND unsupported claims present
  ok("supported and unsupported claims present", /Supported after this specification only/i.test(spec) && /NOT supported/i.test(spec));

  // 11) no provider-contact command included
  const contact = /\b(curl|wget)\b/.test(spec) || /POST\s+https?:\/\//.test(spec);
  ok("no provider-contact command included", !contact);

  // 12) no provider-specific SDK dependency / install command
  const sdk = /\b(npm|pnpm|yarn)\s+(install|add)\b/.test(spec) || /(next-auth|passport|openid-client|@okta\/|@auth0\/|msal)/i.test(spec);
  ok("no provider-specific SDK dependency added", !sdk);
}

if (check) {
  const checkIds = check.match(/S4D-Q\d+-\d+/g) ?? [];
  const checkDupes = checkIds.filter((id, i) => checkIds.indexOf(id) !== i);
  ok("qualification case identifiers unique (checklist)", checkIds.length > 0 && checkDupes.length === 0, checkDupes.length ? `dupes: ${[...new Set(checkDupes)]}` : `${checkIds.length} ids`);
  ok("checklist begins NOT_EXECUTED", /NOT[_ ]EXECUTED/.test(check));
}

// threat-model planned + unimplemented marker
ok("threat-model marks S4D planned/unimplemented", threat && /Phase 3 S4D/.test(threat) && /UNIMPLEMENTED/.test(threat));

// --- report ---
let failed = 0;
for (const r of results) {
  if (!r.pass) failed++;
  process.stdout.write(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}\n`);
}
process.stdout.write(`\nS4D doc-validation: ${results.length - failed}/${results.length} passed\n`);
process.exit(failed === 0 ? 0 : 1);
