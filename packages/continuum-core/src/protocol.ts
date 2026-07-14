/**
 * Continuum Open Protocol (CIP) envelope schemas.
 *
 * These Zod schemas are the fail-closed boundary: every intent, disclosure
 * request, and action proposal that enters the control plane is parsed here
 * before any logic runs. TypeScript types evaporate at runtime — these do not.
 * Unknown mandatory fields fail closed; unknown extras are stripped.
 *
 * Wire spec: CIP-002 (Intent), CIP-003 (Context Disclosure Request),
 * CIP-006 (Action Proposal). CIP-004 (capability) and CIP-007 (evidence) are
 * issued by the platform and typed in their own modules.
 */
import { z } from "zod";
import { CLASSIFICATION_ORDER } from "./types";

export const classificationSchema = z.enum(CLASSIFICATION_ORDER);

// --- CIP-002: Intent Envelope ---------------------------------------------

export const intentConstraintsSchema = z
  .object({
    maximum_data_classification: classificationSchema,
    geographic_boundary: z.array(z.string()).min(1),
    valid_until: z.string(),
    maximum_cost_gbp: z.number().nonnegative(),
  })
  .strict();

export const intentInputSchema = z
  .object({
    intent_id: z.string().optional(),
    owner_id: z.string().min(1),
    actor_id: z.string().min(1),
    tenant_id: z.string().min(1),
    purpose: z.string().min(1),
    requested_operations: z.array(z.string()).default([]),
    prohibited_operations: z.array(z.string()).default([]),
    constraints: intentConstraintsSchema,
    required_evidence: z.array(z.string()).default([]),
    human_gate: z
      .object({ required_for: z.array(z.string()).default([]) })
      .default({ required_for: [] }),
    actor_geo: z.string().default("GB"),
    model_id: z.string().nullable().default(null),
    agent_build: z.string().nullable().default(null),
    risk_score: z.number().min(0).max(1).default(0.1),
  })
  .strict();

export type IntentInput = z.infer<typeof intentInputSchema>;

/** Fully-resolved intent (intent_id always present) used inside the engine. */
export interface Intent extends Omit<IntentInput, "intent_id"> {
  intent_id: string;
  cip: "CIP-002";
}

// --- CIP-003: Context Disclosure Request ----------------------------------

export const discloseInputSchema = z
  .object({
    token_id: z.string().min(1),
    /** Fresh challenge the holder must sign to prove possession of the key. */
    pop_challenge: z.string().default("continuum-pop-challenge"),
  })
  .strict();

export type DiscloseInput = z.infer<typeof discloseInputSchema>;

// --- CIP-006: Action Proposal ---------------------------------------------

export const actionProposalInputSchema = z
  .object({
    action_id: z.string().optional(),
    intent_id: z.string().min(1),
    actor: z.string().min(1),
    operation: z.string().min(1),
    /** Consequence class, e.g. "draft", "external_commitment", "financial_execution". */
    action_class: z.string().min(1),
    expected_effect: z.string().default(""),
    risk: z.number().min(0).max(1).default(0.3),
    reversible: z.boolean().default(true),
    cost_gbp: z.number().nonnegative().default(0),
    resources: z.array(z.string()).default([]),
  })
  .strict();

export type ActionProposalInput = z.infer<typeof actionProposalInputSchema>;

export interface ActionProposal extends Omit<ActionProposalInput, "action_id"> {
  action_id: string;
  cip: "CIP-006";
}
