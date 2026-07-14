/**
 * SIF-Bench Stage B / I7-C — bounded decode + normalize preprocessor.
 *
 * Turns an obfuscated payload into a screening surface WITHOUT executing anything
 * and WITHOUT unbounded work. Every transform is resource-bounded and evidenced;
 * a bound breach fails CLOSED (the input is marked suspicious, never passed through
 * raw), so this cannot become a decompression-bomb / denial-of-service amplifier.
 *
 * It is NOT an LLM, moderation service, or translator: it performs deterministic
 * Unicode/homoglyph/whitespace normalization, HTML-comment extraction, and a single
 * bounded pass of permitted base64 decoding. Non-English instructions are therefore
 * deliberately NOT resolved (that would require the excluded model-dependent layer).
 */

export interface NormalizeBounds {
  maxRecursionDepth: number; // nested base64 decode passes
  maxDecodedBytes: number; // cap on any single decoded fragment
  maxExpansionRatio: number; // total extracted bytes / input bytes
  maxTransforms: number; // transforms applied to one input
  maxOps: number; // deterministic work budget (a stand-in for a wall-clock timeout)
}

export const DEFAULT_BOUNDS: NormalizeBounds = {
  maxRecursionDepth: 2,
  maxDecodedBytes: 4096,
  maxExpansionRatio: 4,
  maxTransforms: 8,
  maxOps: 50_000,
};

export interface NormalizeResult {
  /** Primary normalized form (NFKC + homoglyph fold), safe for benign content. */
  normalized: string;
  /** Extra fragments recovered (base64-decoded, HTML comments, de-spaced variants). */
  extracted: string[];
  /** The full screening surface: normalized + extracted, lowercased. */
  surface: string;
  transformations: string[]; // evidence: which transforms fired
  flags: string[]; // bound breaches / fail-closed reasons
  fail_closed: boolean; // true → caller must treat the input as suspicious (block)
  input_length: number;
  output_length: number;
  expansion_ratio: number;
  ops: number; // work consumed (latency surrogate)
}

// A compact confusables table: Unicode look-alikes → ASCII. NFKC does NOT fold these
// (they are distinct letters), so homoglyph attacks need an explicit map.
const CONFUSABLES: Record<string, string> = {
  "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
  "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
  "Х": "X", "а": "a", "в": "b", "е": "e", "к": "k",
  "м": "m", "н": "h", "о": "o", "р": "p", "с": "c",
  "т": "t", "у": "y", "х": "x", "і": "i", "І": "I",
  "ѕ": "s", "Ѕ": "S", "ԁ": "d", "ɡ": "g", "һ": "h",
  "Ι": "I", "Ο": "O", "Ρ": "P", "Τ": "T", "Β": "B",
  "Ε": "E", "Κ": "K", "Μ": "M", "Ν": "N", "ο": "o",
  "α": "a", "ι": "i", "ｉ": "i", "ⅼ": "l",
};

function foldConfusables(s: string): { out: string; changed: boolean } {
  let changed = false;
  let out = "";
  for (const ch of s) {
    const rep = CONFUSABLES[ch];
    if (rep !== undefined) {
      out += rep;
      changed = true;
    } else {
      out += ch;
    }
  }
  return { out, changed };
}

/** Collapse letter-spaced text ("i g n o r e   a l l") into words, benign-safe. */
function despace(s: string): { out: string; changed: boolean } {
  const toks = s.trim().split(/\s+/).filter(Boolean);
  const singles = toks.filter((t) => t.length === 1).length;
  // Only fire when the input is DOMINATED by single characters (letter-spacing);
  // ordinary prose (multi-char tokens) is left untouched, so benign text is safe.
  if (toks.length < 4 || singles / toks.length < 0.6) return { out: s, changed: false };
  // Keep 2+ spaces as real word boundaries; remove the single inter-letter spaces.
  const SEP = "";
  const out = s.replace(/\s{2,}/g, SEP).replace(/ /g, "").split(SEP).join(" ");
  return { out, changed: out !== s };
}

const BASE64_RE = /[A-Za-z0-9+/]{16,}={0,2}/g;

function tryBase64(s: string): string | null {
  try {
    const buf = Buffer.from(s, "base64");
    if (buf.length === 0) return null;
    const text = buf.toString("utf8");
    // Accept only mostly-printable ASCII (an actual decoded instruction), not noise.
    const printable = [...text].filter((c) => c >= " " && c.charCodeAt(0) < 127).length;
    if (text.length === 0 || printable / text.length < 0.85) return null;
    return text;
  } catch {
    return null;
  }
}

/** Bounded, evidenced decode + normalize. Fails closed on any resource-limit breach. */
export function decodeNormalize(input: string, bounds: NormalizeBounds = DEFAULT_BOUNDS): NormalizeResult {
  const transformations: string[] = [];
  const flags: string[] = [];
  const extracted: string[] = [];
  let ops = 0;
  let failClosed = false;
  const inputLen = input.length;

  const spend = (n: number): boolean => {
    ops += n;
    if (ops > bounds.maxOps) {
      if (!flags.includes("op_budget_exceeded")) flags.push("op_budget_exceeded");
      failClosed = true;
      return false;
    }
    return true;
  };

  // 1 — Unicode NFKC (folds compatibility forms, e.g. full-width, ligatures).
  spend(input.length);
  const nfkc = input.normalize("NFKC");
  if (nfkc !== input) transformations.push("nfkc");
  let normalized = nfkc;

  // 2 — homoglyph fold.
  if (spend(normalized.length)) {
    const f = foldConfusables(normalized);
    if (f.changed) {
      transformations.push("homoglyph_fold");
      normalized = f.out;
    }
  }

  // 3 — de-spacing variant (added to the surface, never replaces benign text).
  if (spend(normalized.length)) {
    const d = despace(normalized);
    if (d.changed) {
      transformations.push("despace");
      extracted.push(d.out);
    }
  }

  // 4 — HTML-comment extraction.
  if (spend(normalized.length)) {
    const comments = normalized.match(/<!--([\s\S]*?)-->/g);
    if (comments && comments.length) {
      transformations.push("html_comment_extract");
      for (const c of comments) extracted.push(c.replace(/^<!--|-->$/g, ""));
    }
  }

  // 5 — permitted base64 decode, bounded and non-recursive-past-depth.
  let depthSource = normalized;
  for (let depth = 0; depth < bounds.maxRecursionDepth && !failClosed; depth++) {
    if (transformations.filter((t) => t === "base64_decode").length + 1 > bounds.maxTransforms) {
      flags.push("transform_budget_exceeded");
      failClosed = true;
      break;
    }
    const matches = depthSource.match(BASE64_RE);
    if (!matches) break;
    let decodedAny = "";
    let firedThisDepth = false;
    for (const m of matches) {
      if (!spend(m.length)) break;
      const decoded = tryBase64(m);
      if (decoded === null) continue;
      if (decoded.length > bounds.maxDecodedBytes) {
        flags.push("decoded_size_exceeded");
        failClosed = true;
        break;
      }
      transformations.push("base64_decode");
      extracted.push(decoded);
      decodedAny += " " + decoded;
      firedThisDepth = true;
    }
    if (!firedThisDepth) break;
    depthSource = decodedAny; // only recurse into freshly-decoded material
  }

  // Expansion ratio (extracted amplification vs input) — fail closed if too large.
  const extractedBytes = extracted.reduce((s, e) => s + e.length, 0);
  const expansion = inputLen === 0 ? 0 : +((normalized.length + extractedBytes) / inputLen).toFixed(3);
  if (expansion > bounds.maxExpansionRatio) {
    flags.push("expansion_ratio_exceeded");
    failClosed = true;
  }

  const surface = [normalized, ...extracted].join(" ␟ ").toLowerCase();
  return {
    normalized,
    extracted,
    surface,
    transformations,
    flags,
    fail_closed: failClosed,
    input_length: inputLen,
    output_length: normalized.length + extractedBytes,
    expansion_ratio: expansion,
    ops,
  };
}
