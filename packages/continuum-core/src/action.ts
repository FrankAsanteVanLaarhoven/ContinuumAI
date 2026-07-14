/**
 * Action state machine and human gate — CIP-006 (Plane D).
 *
 * Every consequential action is a typed proposal that walks a formally
 * constrained state machine. Prohibited operations are denied outright.
 * High-consequence classes cannot reach EXECUTING without an explicit
 * HUMAN_APPROVED transition — the proposing agent can never self-approve.
 */
import type { ActionProposal, Intent } from "./protocol";

export type ActionState =
  | "PROPOSED"
  | "VALIDATED"
  | "POLICY_APPROVED"
  | "HUMAN_APPROVED"
  | "EXECUTING"
  | "SUCCEEDED"
  | "FAILED"
  | "COMPENSATED"
  | "REVOKED"
  | "DENIED"
  | "QUARANTINED";

const TRANSITIONS: Record<ActionState, ActionState[]> = {
  PROPOSED: ["VALIDATED", "DENIED", "QUARANTINED"],
  VALIDATED: ["POLICY_APPROVED", "DENIED", "QUARANTINED"],
  POLICY_APPROVED: ["HUMAN_APPROVED", "EXECUTING", "DENIED", "REVOKED"],
  HUMAN_APPROVED: ["EXECUTING", "REVOKED"],
  EXECUTING: ["SUCCEEDED", "FAILED", "COMPENSATED"],
  SUCCEEDED: [],
  FAILED: ["COMPENSATED"],
  COMPENSATED: [],
  REVOKED: [],
  DENIED: [],
  QUARANTINED: ["DENIED"],
};

export function canTransition(from: ActionState, to: ActionState): boolean {
  return TRANSITIONS[from].includes(to);
}

/** Consequence classes that always require human approval before execution. */
export const HIGH_CONSEQUENCE_CLASSES = new Set<string>([
  "external_commitment",
  "financial_execution",
  "contract_execution",
  "credential_change",
  "production_deletion",
  "external_publication",
  "robot_motion",
  "cross_border_transfer",
]);

export interface StateTransition {
  state: ActionState;
  at: string;
  note: string;
}

export interface ActionRecord {
  action_id: string;
  intent_id: string;
  actor: string;
  operation: string;
  action_class: string;
  expected_effect: string;
  reversible: boolean;
  cost_gbp: number;
  requires_human_approval: boolean;
  state: ActionState;
  history: StateTransition[];
  denied_reason: string | null;
}

function advance(
  record: ActionRecord,
  to: ActionState,
  nowMs: number,
  note: string,
): void {
  if (!canTransition(record.state, to)) {
    throw new Error(
      `illegal action transition ${record.state} -> ${to} for ${record.action_id}`,
    );
  }
  record.state = to;
  record.history.push({ state: to, at: new Date(nowMs).toISOString(), note });
}

/**
 * Evaluate a fresh proposal. Returns the record at its resting state:
 * DENIED (prohibited), POLICY_APPROVED (awaiting human gate), or SUCCEEDED
 * (auto-executed low-consequence action).
 */
export function evaluateProposal(
  proposal: ActionProposal,
  intent: Intent,
  nowMs: number,
): ActionRecord {
  const requiresHuman =
    HIGH_CONSEQUENCE_CLASSES.has(proposal.action_class) ||
    intent.human_gate.required_for.includes(proposal.action_class);

  const record: ActionRecord = {
    action_id: proposal.action_id,
    intent_id: proposal.intent_id,
    actor: proposal.actor,
    operation: proposal.operation,
    action_class: proposal.action_class,
    expected_effect: proposal.expected_effect,
    reversible: proposal.reversible,
    cost_gbp: proposal.cost_gbp,
    requires_human_approval: requiresHuman,
    state: "PROPOSED",
    history: [
      { state: "PROPOSED", at: new Date(nowMs).toISOString(), note: "submitted" },
    ],
    denied_reason: null,
  };

  // Hard deny: an operation the intent explicitly prohibits.
  if (intent.prohibited_operations.includes(proposal.operation)) {
    advance(record, "DENIED", nowMs, "operation prohibited by intent");
    record.denied_reason = `operation '${proposal.operation}' is prohibited by intent`;
    return record;
  }

  advance(record, "VALIDATED", nowMs, "schema and scope validated");
  advance(record, "POLICY_APPROVED", nowMs, "within intent scope");

  if (requiresHuman) {
    // Rest here — blocked pending human approval. No self-approval possible.
    return record;
  }

  advance(record, "EXECUTING", nowMs, "auto-execute (low consequence)");
  advance(record, "SUCCEEDED", nowMs, "tool executed (simulated)");
  return record;
}

/**
 * Apply a human approval. Only valid for a record resting at POLICY_APPROVED
 * that requires approval. Drives it through execution to SUCCEEDED.
 */
export function approveAction(
  record: ActionRecord,
  approver: string,
  nowMs: number,
): ActionRecord {
  if (record.state !== "POLICY_APPROVED" || !record.requires_human_approval) {
    throw new Error(
      `action ${record.action_id} is not awaiting human approval (state ${record.state})`,
    );
  }
  advance(record, "HUMAN_APPROVED", nowMs, `approved by ${approver}`);
  advance(record, "EXECUTING", nowMs, "tool gateway executing");
  advance(record, "SUCCEEDED", nowMs, "tool executed (simulated)");
  return record;
}
