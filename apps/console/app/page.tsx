import { createRuntime, getRuntimeState, resolveConsoleContext } from "../lib/runtime";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Production console page — an async server component reading DURABLE state from
 * the async control-plane runtime. It imports the async runtime only; the
 * synchronous research engine never enters this path (gate 7).
 */
export default async function Page() {
  const rt = createRuntime();
  try {
    const ctx = await resolveConsoleContext(rt);
    const state = await getRuntimeState(rt, ctx);
    const h = state.health;
    return (
      <main style={{ fontFamily: "ui-monospace, monospace", padding: "2rem", maxWidth: 960, margin: "0 auto" }}>
        <h1>Continuum Console — durable runtime</h1>
        <p>
          store <strong>{state.mode}</strong> ({state.classification}) · tenant{" "}
          <strong>{state.tenant}</strong> · principal <strong>{state.principal}</strong>
        </p>
        <p>generated {state.generated_at}</p>
        <h2>Store health</h2>
        <ul>
          <li>status: <strong>{h.status}</strong></li>
          <li>database reachable: {String(h.databaseReachable)}</li>
          <li>migrations current: {String(h.migrationsCurrent)}</li>
          <li>RLS verified: {String(h.rlsVerified)}</li>
          <li>append-only role verified: {String(h.appendOnlyRoleVerified)}</li>
          <li>evidence chain verified: {String(h.evidenceChainVerified)}</li>
        </ul>
        <h2>Authorized memory ({state.authorized_memory_count})</h2>
        <ul>
          {state.authorized_memory.map((m) => (
            <li key={m.memory_id}>
              {m.memory_id} · {m.classification} · {m.read_operation}
            </li>
          ))}
        </ul>
        <h2>Evidence</h2>
        <p>
          {state.evidence_count} envelopes · chain{" "}
          <strong>{state.evidence_chain_valid ? "intact" : "BROKEN"}</strong> — {state.evidence_chain_detail}
        </p>
      </main>
    );
  } finally {
    await rt.store.close();
  }
}
