/**
 * Context Broker (Plane C).
 *
 * Given an authorization decision, releases the *minimum necessary* context:
 * only permitted objects, with their sensitive fields redacted, plus a
 * disclosure digest that fixes exactly what left the boundary. It also reports
 * how much a naive retrieval layer would have leaked, which is the basis for
 * the disclosure-minimization KPI.
 */
import type { MemoryObject } from "./types";
import type { AuthorizationDecision } from "./policy";
import { digestOf } from "./crypto";

export interface DisclosedObject {
  memory_id: string;
  memory_class: string;
  classification: string;
  content: Record<string, unknown>;
  redacted_fields: string[];
}

export interface Redaction {
  memory_id: string;
  field: string;
}

export interface DisclosurePackage {
  cip: "CIP-003";
  intent_id: string;
  disclosed: DisclosedObject[];
  redactions: Redaction[];
  disclosure_digest: string;
  minimum_required: number;
  disclosed_count: number;
  naive_baseline_count: number;
  excess_disclosure_ratio: number;
  reduction_vs_naive: number;
}

/** Redact a single dot-path within a cloned content object. Returns whether it applied. */
function redactField(root: Record<string, unknown>, path: string): boolean {
  const segs = path.split(".");
  let cur: Record<string, unknown> = root;
  for (let i = 0; i < segs.length - 1; i++) {
    const s = segs[i]!;
    const next = cur[s];
    if (next === null || typeof next !== "object" || Array.isArray(next)) {
      return false;
    }
    cur = next as Record<string, unknown>;
  }
  const last = segs[segs.length - 1]!;
  if (!(last in cur)) return false;
  cur[last] = "[REDACTED]";
  return true;
}

/**
 * Compute the disclosure package. Only objects the PDP permitted are eligible;
 * for each, sensitive fields are stripped before the content ever leaves the
 * broker. The digest binds the released set and its redactions.
 */
export function computeDisclosure(
  decision: AuthorizationDecision,
  objectsById: Map<string, MemoryObject>,
): DisclosurePackage {
  const disclosed: DisclosedObject[] = [];
  const redactions: Redaction[] = [];

  for (const id of decision.permitted_ids) {
    const obj = objectsById.get(id);
    if (obj === undefined) continue;
    const content = structuredClone(obj.content);
    const redactedFields: string[] = [];
    for (const field of obj.sensitive_fields) {
      if (redactField(content, field)) {
        redactedFields.push(field);
        redactions.push({ memory_id: id, field });
      }
    }
    disclosed.push({
      memory_id: id,
      memory_class: obj.memory_class,
      classification: obj.classification,
      content,
      redacted_fields: redactedFields,
    });
  }

  const minimumRequired = disclosed.length;
  const disclosedCount = disclosed.length;
  const naiveBaseline = decision.candidate_count;
  const excess =
    minimumRequired === 0
      ? 0
      : (disclosedCount - minimumRequired) / minimumRequired;
  const reductionVsNaive =
    naiveBaseline === 0 ? 0 : (naiveBaseline - disclosedCount) / naiveBaseline;

  const digest = digestOf({
    intent_id: decision.intent_id,
    ids: disclosed.map((d) => d.memory_id),
    redactions,
  });

  return {
    cip: "CIP-003",
    intent_id: decision.intent_id,
    disclosed,
    redactions,
    disclosure_digest: digest,
    minimum_required: minimumRequired,
    disclosed_count: disclosedCount,
    naive_baseline_count: naiveBaseline,
    excess_disclosure_ratio: excess,
    reduction_vs_naive: reductionVsNaive,
  };
}
