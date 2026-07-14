/**
 * Model Gateway (Plane D).
 *
 * The boundary every model call must pass through. It enforces, fail-closed:
 * provider/version allowlisting, region and data-classification limits,
 * zero-retention verification, prompt-injection screening (direct AND indirect
 * — the retrieved context is part of the attack surface), egress canary
 * detection, a token/cost budget (denial-of-wallet), and output-schema
 * validation. The model itself is simulated in v0.1; the *gateway* logic is
 * real and independently tested.
 */
import { z } from "zod";
import { classRank, type Classification } from "./types";
import type { DisclosedObject } from "./broker";
import type { SovereignCapabilityToken } from "./capability";
import { canonicalJson } from "./crypto";

export interface ModelProvider {
  provider: string;
  model_id: string;
  version: string;
  region: string;
  zero_retention: boolean;
  external: boolean;
  max_classification: Classification;
}

export interface ModelGatewayConfig {
  providers: ModelProvider[];
  /** Source strings compiled to case-insensitive RegExp. */
  injection_patterns: string[];
  /** Known canary secrets that must never appear in an egress payload. */
  canaries: string[];
  per_request_token_budget: number;
  gbp_per_1k_tokens: number;
}

export const DEFAULT_INJECTION_PATTERNS: string[] = [
  "ignore (all |your |the )?previous instructions",
  "disregard (the |your |all )?(above|system|prior|previous)",
  "reveal (your |the )?(system )?(prompt|instructions)",
  "print (your |the )?(system )?(prompt|instructions)",
  "you are now (a|an|dan|in)",
  "exfiltrat",
  "override (the |your )?(policy|guardrails|safety|rules)",
  "send (it |the data |them )?to https?://",
];

export interface GatewayCheck {
  name: string;
  satisfied: boolean;
  detail: string;
}

export interface ModelCallResult {
  allowed: boolean;
  requested_model: string;
  checks: GatewayCheck[];
  denied_reason: string | null;
  model: { provider: string; model_id: string; version: string } | null;
  tokens_charged: number;
  cost_gbp: number;
  output: unknown | null;
  output_valid: boolean;
  quarantined: boolean;
}

export interface ModelCallRequest {
  token: SovereignCapabilityToken;
  requested_model_id: string;
  disclosed: DisclosedObject[];
  agent_prompt: string;
  allowed_regions: string[];
  max_cost_gbp: number;
  estimated_tokens: number;
}

const recommendationSchema = z.object({
  recommended_supplier: z.string().min(1),
  unit_price_gbp: z.number().positive(),
  rationale: z.string().min(1),
  considered: z.array(z.string()).min(1),
});

/** Deterministic stand-in for a real model: recommends the lowest compliant quote. */
function simulateModel(disclosed: DisclosedObject[]): unknown {
  const quotes = disclosed
    .map((o) => ({
      supplier: String(o.content["supplier"] ?? "unknown"),
      price: Number(o.content["unit_price_gbp"] ?? Number.POSITIVE_INFINITY),
    }))
    .filter((q) => Number.isFinite(q.price));
  if (quotes.length === 0) return { note: "no comparable quotes" }; // fails schema → quarantine
  const best = quotes.reduce((a, b) => (b.price < a.price ? b : a));
  return {
    recommended_supplier: best.supplier,
    unit_price_gbp: best.price,
    rationale: `lowest compliant unit price £${best.price} across ${quotes.length} disclosed quote(s)`,
    considered: quotes.map((q) => q.supplier),
  };
}

export function evaluateModelCall(
  req: ModelCallRequest,
  cfg: ModelGatewayConfig,
): ModelCallResult {
  const checks: GatewayCheck[] = [];
  const provider =
    cfg.providers.find((p) => p.model_id === req.requested_model_id) ?? null;

  checks.push({
    name: "provider_allowlisted",
    satisfied: provider !== null,
    detail: provider
      ? `${provider.provider}/${provider.model_id}@${provider.version}`
      : `model '${req.requested_model_id}' not on allowlist`,
  });

  const regionOk = provider
    ? req.allowed_regions.includes(provider.region)
    : false;
  checks.push({
    name: "region_permitted",
    satisfied: regionOk,
    detail: provider
      ? regionOk
        ? `region ${provider.region} permitted`
        : `region ${provider.region} outside ${req.allowed_regions.join(",")}`
      : "no provider",
  });

  const classOk = provider
    ? classRank(req.token.data_classification) <=
        classRank(provider.max_classification) &&
      !(provider.external && req.token.data_classification === "restricted")
    : false;
  checks.push({
    name: "classification_permitted",
    satisfied: classOk,
    detail: provider
      ? classOk
        ? `${req.token.data_classification} ≤ provider max ${provider.max_classification}`
        : `${req.token.data_classification} exceeds provider max ${provider.max_classification}${provider.external ? " (external)" : ""}`
      : "no provider",
  });

  checks.push({
    name: "zero_retention_verified",
    satisfied: provider?.zero_retention ?? false,
    detail: provider
      ? provider.zero_retention
        ? "provider asserts zero retention"
        : "provider retention not zero"
      : "no provider",
  });

  // Prompt injection: the agent prompt AND the retrieved context (indirect).
  const haystack = `${req.agent_prompt} ${canonicalJson(req.disclosed)}`.toLowerCase();
  const injection =
    cfg.injection_patterns.find((p) => new RegExp(p, "i").test(haystack)) ??
    null;
  checks.push({
    name: "no_prompt_injection",
    satisfied: injection === null,
    detail:
      injection === null
        ? "no injection indicators"
        : `injection indicator matched: /${injection}/`,
  });

  const tokens = req.estimated_tokens;
  const cost = (tokens / 1000) * cfg.gbp_per_1k_tokens;
  const budgetOk =
    tokens <= cfg.per_request_token_budget && cost <= req.max_cost_gbp;
  checks.push({
    name: "budget_within_limit",
    satisfied: budgetOk,
    detail: `${tokens} tok · £${cost.toFixed(4)} (limit ${cfg.per_request_token_budget} tok / £${req.max_cost_gbp.toFixed(2)})`,
  });

  const egress = canonicalJson({ prompt: req.agent_prompt, context: req.disclosed });
  const canary = cfg.canaries.find((c) => egress.includes(c)) ?? null;
  checks.push({
    name: "egress_no_canary",
    satisfied: canary === null,
    detail:
      canary === null
        ? "no canary in egress payload"
        : `canary present in egress: ${canary.slice(0, 8)}…`,
  });

  const preOk = checks.every((c) => c.satisfied);
  let output: unknown = null;
  let outputValid = false;
  let quarantined = false;

  if (preOk && provider) {
    output = simulateModel(req.disclosed);
    outputValid = recommendationSchema.safeParse(output).success;
    quarantined = !outputValid;
    checks.push({
      name: "output_schema_valid",
      satisfied: outputValid,
      detail: outputValid
        ? "structured output conforms to schema"
        : "output failed schema — quarantined",
    });
  } else {
    checks.push({
      name: "output_schema_valid",
      satisfied: false,
      detail: "not evaluated (call denied upstream)",
    });
  }

  const allowed = checks.every((c) => c.satisfied);
  const failed = checks.find((c) => !c.satisfied) ?? null;
  return {
    allowed,
    requested_model: req.requested_model_id,
    checks,
    denied_reason: allowed ? null : failed ? `${failed.name}: ${failed.detail}` : "denied",
    model: provider
      ? { provider: provider.provider, model_id: provider.model_id, version: provider.version }
      : null,
    tokens_charged: allowed ? tokens : 0,
    cost_gbp: allowed ? cost : 0,
    output: allowed ? output : null,
    output_valid: outputValid,
    quarantined,
  };
}
