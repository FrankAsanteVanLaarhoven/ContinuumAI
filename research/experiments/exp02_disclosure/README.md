# exp02 — Disclosure Minimisation

**Answers:** RQ2 (disclosure minimisation).

**Maturity:** Research prototype v0.1 (commit `3f038fd`).

**Hypothesis:** The context broker releases the minimum necessary context, reducing
sensitive/unnecessary disclosure (`D_C < D_B`) while preserving task utility within
the predeclared tolerance (`U_C ≥ U_B − ε`).

**Baselines compared:** B0 direct agent access, B1 standard RAG, B2 RBAC-protected
RAG, B3 Continuum. Ablation: C–Redaction.

**Metrics collected:** Excess Disclosure Ratio, Sensitive Field Exposure Rate,
Context Precision, Context Recall, Task Success Rate, Utility–Disclosure Frontier.

**Procedure outline:**
1. On the procurement workload (sensitive fields: bank data, negotiated rates,
   internal budget), run every configuration over multiple seeds.
2. Record objects requested vs. released, fields redacted, and the disclosure
   digest per run.
3. Score task success against ground-truth correct outcomes.
4. Plot the Utility–Disclosure Frontier across configurations; report N, `ε`, and
   Wilson intervals for proportions.

**Status: planned — not yet run.**
