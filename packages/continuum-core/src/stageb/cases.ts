/**
 * SIF-Bench Stage B — corpus case model, loader, and structural validator.
 *
 * Cases live as JSONL under research/sif-bench/stage_b/corpora and are validated
 * against schemas/case.schema.json. The loader is dependency-free; the validator
 * mirrors the schema's required fields and enums so a malformed corpus fails the
 * framework gate rather than silently skewing a metric.
 */
export type Track =
  | "prompt_injection"
  | "canary_exfiltration"
  | "memory_poisoning"
  | "extraction";

export type SecurityOutcome = "BLOCK" | "ALLOW" | "SURFACE_ABSENT";
export type TaskOutcome = "CONTINUE_SAFELY" | "DENY" | "NOT_APPLICABLE";
export type Severity = "low" | "medium" | "high" | "critical";

export interface Case {
  case_id: string;
  track: Track;
  attack_family: string;
  input: Record<string, unknown>;
  expected_security_outcome: SecurityOutcome;
  expected_task_outcome: TaskOutcome;
  required_controls: string[];
  severity: Severity;
  source_type: "synthetic";
  notes?: string;
}

const TRACKS = new Set<Track>([
  "prompt_injection",
  "canary_exfiltration",
  "memory_poisoning",
  "extraction",
]);
const SEC = new Set<SecurityOutcome>(["BLOCK", "ALLOW", "SURFACE_ABSENT"]);
const TASK = new Set<TaskOutcome>(["CONTINUE_SAFELY", "DENY", "NOT_APPLICABLE"]);
const SEV = new Set<Severity>(["low", "medium", "high", "critical"]);
const ID_RE = /^[A-Z0-9]+-[A-Z0-9]+-[0-9]{3}$/;

/** Parse a JSONL corpus. Blank lines are skipped; a bad line throws with context. */
export function loadCorpus(text: string): Case[] {
  const out: Case[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (line === "") continue;
    try {
      out.push(JSON.parse(line) as Case);
    } catch (e) {
      throw new Error(`corpus line ${i + 1}: ${(e as Error).message}`);
    }
  }
  return out;
}

/** Return a list of structural violations for a case (empty ⇒ valid). */
export function validateCase(c: Case): string[] {
  const v: string[] = [];
  if (typeof c.case_id !== "string" || !ID_RE.test(c.case_id)) v.push("case_id");
  if (!TRACKS.has(c.track)) v.push("track");
  if (typeof c.attack_family !== "string" || c.attack_family.length === 0) v.push("attack_family");
  if (c.input === null || typeof c.input !== "object") v.push("input");
  if (!SEC.has(c.expected_security_outcome)) v.push("expected_security_outcome");
  if (!TASK.has(c.expected_task_outcome)) v.push("expected_task_outcome");
  if (!Array.isArray(c.required_controls)) v.push("required_controls");
  if (!SEV.has(c.severity)) v.push("severity");
  if (c.source_type !== "synthetic") v.push("source_type");
  return v;
}
