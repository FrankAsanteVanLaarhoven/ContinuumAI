# Limitations

**Maturity:** Research prototype v0.1 (commit `3f038fd`). These limitations bound
every claim in the paper and are stated first-class, not as caveats. They are
consistent with the claim boundary in
[`../../docs/CLAIMS.md`](../../docs/CLAIMS.md).

1. **Synthetic workloads.** All evaluation uses synthetic, hand-constructed
   scenarios (e.g. the Orion/Apex procurement scenario). No real user data, real
   enterprise corpus, or production traffic has been used.

2. **Simulated tool execution.** Consequential actions are executed by a simulated
   tool gateway with modelled state transitions. No real external side effect
   (payment, record change, infrastructure mutation) is performed, so
   compensation/rollback behaviour is untested against real systems.

3. **Limited model and provider diversity.** Only **one simulated model** exists in
   v0.1. There is no real model, no second provider, and no cross-model
   evaluation. Any statement about model-independence is therefore unsupported.

4. **Heuristic injection detector.** Prompt-injection screening is **pattern-based**
   (a fixed regular-expression set over the prompt and retrieved context). It
   raises attacker cost and catches known patterns; it is not a complete defence
   against adversarially-crafted injection.

5. **No formal verification.** The permit invariant and protocol properties are
   implemented and unit-tested, not machine-checked or proved. There is no formal
   model or mechanised proof of the authorization logic.

6. **No independent red team.** All adversarial cases were authored by the same
   party that built the system. No independent adversarial evaluation has been
   conducted.

7. **No longitudinal user study.** There is no study of operators or end users over
   time; usability, operator error, and approval-fatigue effects are unmeasured.

8. **No evidence of network effects.** Claims about protocol adoption or ecosystem
   network effects are unsupported; there is a single implementation.

9. **No absolute confidentiality guarantee.** Once context is released to a model,
   agent, human, tool, or device, no practical distributed system can guarantee it
   learns nothing. Continuum minimises disclosure and constrains authorization
   within an explicitly defined threat model; it does not make leakage impossible.

10. **In-memory to persistence transition in progress.** The v0.1 store is
    in-memory and single-process. Database, row-level-security, cache, vector, and
    backup isolation are being added in parallel; persistent guarantees (durable
    revocation, restart/tamper/restore of the evidence chain, database-enforced
    tenant isolation) are **in progress** and not yet demonstrated.

11. **SIF-Bench is an internal conformance harness.** SIF-Bench v0.1 is an
    invariant/consistency harness over the reference slice. It is **not** a
    validated external or industry-standard benchmark, and reporting "zero observed
    events" is not proof of impossibility.
