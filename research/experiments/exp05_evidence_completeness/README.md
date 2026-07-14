# exp05 — Evidence Completeness

**Answers:** RQ4 (memory integrity — provenance) and the evidence-chain claim.

**Maturity:** Research prototype v0.1 (commit `3f038fd`). Persistent
restart/tamper/restore is **not yet established** — persistence is in progress.

**Hypothesis:** The hash-chained, signed evidence ledger records every release and
action completely, and enables faithful post-hoc reconstruction; tampering is
detected and does not survive verification.

**Baselines compared:** B3 Continuum with provenance/evidence enabled vs. the
ablation C–Provenance (recording removed). B0–B2 as context.

**Metrics collected:** Provenance Completeness, Evidence-Chain Valid Rate,
tamper-detection rate, and reconstruction fidelity after restart/restore.

**Procedure outline:**
1. Run each workload and record the evidence-envelope count and chain verification
   result per run.
2. Attempt to edit, reorder, and drop envelopes; verify the chain detects each.
3. (Once persistence lands) restart the store and restore from backup; check the
   chain re-verifies and reconstruction matches the run manifest.
4. Report completeness and valid rates with N and Wilson 95% intervals.

**Status: planned — not yet run.**
