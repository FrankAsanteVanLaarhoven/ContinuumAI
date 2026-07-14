"use client";

import { useCallback, useMemo, useState } from "react";
import type { ConsoleState } from "../lib/dto";
import type { ActionRecord, EvidenceEnvelope } from "@continuum/core";

function short(id: string, n = 10): string {
  return id.length > n ? `${id.slice(0, n)}…` : id;
}

function classChip(c: string): string {
  if (c === "restricted") return "chip restricted";
  if (c === "confidential") return "chip confidential";
  if (c === "internal") return "chip internal";
  return "chip";
}

function stepDot(status: string): string {
  if (status === "ok") return "dot ok";
  if (status === "blocked") return "dot warn";
  if (status === "denied") return "dot bad";
  return "dot idle";
}

export function Console({ initial }: { initial: ConsoleState }) {
  const [state, setState] = useState<ConsoleState>(initial);
  const [busy, setBusy] = useState(false);

  const rerun = useCallback(async () => {
    setBusy(true);
    try {
      const res = await fetch("/api/rerun", { method: "POST" });
      if (res.ok) setState((await res.json()) as ConsoleState);
    } finally {
      setBusy(false);
    }
  }, []);

  const m = state.metrics;
  const memoryById = useMemo(
    () => new Map(state.memory.map((mem) => [mem.memory_id, mem])),
    [state.memory],
  );

  const permitted = state.decision.permitted_ids.length;
  const candidates = state.decision.candidate_count;

  const tiles = [
    { label: "Objects permitted", value: `${permitted} / ${candidates}`, ok: permitted === 2, target: "minimum necessary" },
    { label: "Disclosure reduction", value: `${(m.disclosure_reduction_vs_naive * 100).toFixed(0)}%`, ok: m.disclosure_reduction_vs_naive >= 0.6, target: "vs naive RAG · ≥60%" },
    { label: "Authorization p99", value: `${m.authz_p99_ms.toFixed(2)} ms`, ok: m.authz_p99_ms <= 50, target: "≤ 50 ms" },
    { label: "Revocation p99", value: `${m.revocation_p99_ms.toFixed(2)} ms`, ok: m.revocation_p99_ms <= 5000, target: "≤ 5000 ms" },
    { label: "Evidence envelopes", value: `${m.evidence_count}`, ok: m.evidence_chain_valid, target: m.evidence_chain_valid ? "chain intact" : "chain broken" },
    { label: "Canary exfiltration", value: `${(m.canary_exfiltration_rate * 100).toFixed(0)}%`, ok: m.canary_exfiltration_rate === 0, target: `${m.canary_trials} trials` },
    { label: "Cross-tenant leaks", value: `${m.cross_tenant_leaks}`, ok: m.cross_tenant_leaks === 0, target: `${m.cross_tenant_attempts} probed` },
  ];

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">◈</div>
          <div>
            <div className="brand-name">CONTINUUM</div>
            <div className="brand-sub">Sovereign Intent &amp; Agency Infrastructure</div>
          </div>
        </div>
        <div className="topbar-spacer" />
        <div className="meta-inline">
          <div className="meta-item">
            <span className="micro">policy</span>
            <span className="val">{m.policy_version}</span>
          </div>
          <div className="meta-item">
            <span className="micro">platform key</span>
            <span className="val">{short(state.platform_fingerprint, 22)}</span>
          </div>
        </div>
        <div className={`status-pill ${state.passed ? "pass" : "fail"}`}>
          <span className={`dot ${state.passed ? "ok" : "bad"}`} />
          {state.passed ? "SLICE VERIFIED" : "SLICE FAILING"}
        </div>
        <button className="btn" onClick={rerun} disabled={busy}>
          {busy ? "RUNNING…" : "▷ RE-RUN SLICE"}
        </button>
      </header>

      <section className="kpi-strip">
        {tiles.map((t) => (
          <div key={t.label} className={`tile ${t.ok ? "ok" : "bad"}`}>
            <div className="micro">{t.label}</div>
            <div className="tile-val tnum">{t.value}</div>
            <div className="tile-target">{t.target}</div>
          </div>
        ))}
      </section>

      <div className="grid">
        {/* Identities & trust */}
        <div className="col-3">
          <Panel title="Identities &amp; Trust" tag="Plane A">
            <div className="panel-body">
              {state.principals
                .filter((p) => p.tenant_id === "t_acme")
                .map((p) => (
                  <div className="principal" key={p.principal_id}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span className={`dot ${p.attested ? "ok" : "bad"}`} />
                      <span style={{ fontWeight: 600 }}>{p.display_name}</span>
                      <span className={`chip ${p.kind === "agent" ? "violet" : ""}`} style={{ marginLeft: "auto" }}>
                        {p.kind}
                      </span>
                    </div>
                    <div className="pid">{p.principal_id}</div>
                    {p.build_hash && (
                      <div className="pid" style={{ color: "var(--text-faint)" }}>
                        build {short(p.build_hash, 26)}
                      </div>
                    )}
                  </div>
                ))}
              <div style={{ marginTop: 12 }} className="micro">Trust domains</div>
              {state.tenants.map((t) => (
                <div className="kv" key={t.tenant_id}>
                  <span className="k">{t.display_name}</span>
                  <span className="v">{t.trust_domain} · {t.residency}</span>
                </div>
              ))}
              <div style={{ marginTop: 12 }} className="micro">Active intent</div>
              <div className="digest">{state.intent_id}</div>
              <div className="kv"><span className="k">purpose</span><span className="v">{state.purpose}</span></div>
            </div>
          </Panel>
        </div>

        {/* Authorization decision */}
        <div className="col-9">
          <Panel title="Authorization Decision" tag="Plane B · Deny by default">
            <div className="panel-body flush">
              <table className="dtable">
                <thead>
                  <tr>
                    <th>Memory object</th>
                    <th>Class</th>
                    <th>Sensitivity</th>
                    <th>Read op</th>
                    <th>Decision</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {state.decision.object_decisions.map((d) => {
                    const meta = memoryById.get(d.memory_id);
                    return (
                      <tr key={d.memory_id} className={d.permit ? "permit" : "deny"}>
                        <td style={{ color: "var(--text)" }}>{d.memory_id}</td>
                        <td><span className="chip">{meta?.memory_class ?? "—"}</span></td>
                        <td><span className={classChip(d.classification)}>{d.classification}</span></td>
                        <td style={{ color: "var(--text-dim)", fontSize: 10.5 }}>{meta?.read_operation ?? "—"}</td>
                        <td>
                          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                            <span className={`dot ${d.permit ? "ok" : "bad"}`} />
                            <span style={{ color: d.permit ? "var(--cyan)" : "var(--red)", fontSize: 10.5 }}>
                              {d.permit ? "PERMIT" : "DENY"}
                            </span>
                          </span>
                        </td>
                        <td>
                          <span className={`reason ${d.permit ? "ok" : ""}`}>
                            {d.permit ? (
                              <>all seven checks satisfied</>
                            ) : (
                              <><span className="k">{(d.denied_reason ?? "").split(":")[0]}</span>{(d.denied_reason ?? "").slice((d.denied_reason ?? "").indexOf(":"))}</>
                            )}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>

        {/* Minimum disclosure */}
        <div className="col-5">
          <Panel title="Minimum-Necessary Disclosure" tag="Plane C · Context broker">
            <div className="panel-body">
              {state.disclosure.disclosed.map((o) => (
                <div className="disc-obj" key={o.memory_id}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                    <span className="dot ok" />
                    <span className="mono" style={{ fontSize: 11 }}>{o.memory_id}</span>
                    <span className={classChip(o.classification)} style={{ marginLeft: "auto" }}>{o.classification}</span>
                  </div>
                  {Object.entries(o.content).map(([k, v]) => {
                    const redacted = v === "[REDACTED]";
                    return (
                      <div className="kv" key={k}>
                        <span className="k">{k}</span>
                        <span className={`v ${redacted ? "redacted" : ""}`}>{redacted ? "REDACTED" : String(v)}</span>
                      </div>
                    );
                  })}
                </div>
              ))}
              <div className="micro">disclosure digest (binds released set)</div>
              <div className="digest">sha256:{state.disclosure.disclosure_digest}</div>
              <div className="kv" style={{ marginTop: 8 }}>
                <span className="k">released / candidate</span>
                <span className="v">{state.disclosure.disclosed_count} / {state.disclosure.naive_baseline_count}</span>
              </div>
              <div className="bar">
                <span style={{ width: `${(state.disclosure.disclosed_count / Math.max(1, state.disclosure.naive_baseline_count)) * 100}%` }} />
              </div>
            </div>
          </Panel>
        </div>

        {/* Capability token */}
        <div className="col-4">
          <Panel title="Sovereign Capability Token" tag="CIP-004">
            <div className="panel-body cap-card">
              {m.capabilities_revoked > 0 && <div className="cap-revoked-stamp">REVOKED</div>}
              {state.capability ? (
                <>
                  <div className="kv"><span className="k">token</span><span className="v">{short(state.capability.token_id, 22)}</span></div>
                  <div className="kv"><span className="k">holder (PoP)</span><span className="v">{state.capability.holder_fingerprint}</span></div>
                  <div className="kv"><span className="k">purpose</span><span className="v">{state.capability.purpose}</span></div>
                  <div className="kv"><span className="k">audience</span><span className="v">{state.capability.audience}</span></div>
                  <div className="kv"><span className="k">environment</span><span className="v">{state.capability.environment}</span></div>
                  <div className="kv"><span className="k">max disclosure</span><span className="v">{state.capability.maximum_disclosure} objects</span></div>
                  <div style={{ marginTop: 6 }} className="micro">bound resources</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginTop: 5 }}>
                    {state.capability.resources.map((r) => <span key={r} className="chip cyan">{r}</span>)}
                  </div>
                  <div style={{ marginTop: 8 }} className="micro">operations</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginTop: 5 }}>
                    {state.capability.operations.map((op) => <span key={op} className="chip">{op}</span>)}
                  </div>
                  <div className="kv" style={{ marginTop: 8 }}>
                    <span className="k">ttl</span>
                    <span className="v">{(Date.parse(state.capability.expires_at) - Date.parse(state.capability.issued_at)) / 1000}s · non-transferable</span>
                  </div>
                  <div className="kv"><span className="k">revocation</span><span className="v">{short(state.capability.revocation_handle, 22)}</span></div>
                </>
              ) : (
                <div className="reason">no capability issued (request denied)</div>
              )}
            </div>
          </Panel>
        </div>

        {/* Action & human gate */}
        <div className="col-3">
          <Panel title="Action &amp; Human Gate" tag="Plane D · CIP-006">
            <div className="panel-body">
              {state.actions.map((a) => (
                <ActionFlow key={a.action_id} action={a} />
              ))}
            </div>
          </Panel>
        </div>

        {/* Evidence ledger */}
        <div className="col-6">
          <Panel title="Evidence Ledger" tag="Plane E · CIP-007 · hash-chained">
            <div className="panel-body flush">
              <div className="ledger panel-scroll">
                {state.evidence.entries.map((e) => (
                  <LedgerRow key={e.event_id} e={e} />
                ))}
              </div>
              <div className="chain-banner">
                <span className={`dot ${state.evidence.valid ? "ok" : "bad"}`} />
                <span style={{ color: state.evidence.valid ? "var(--cyan)" : "var(--red)" }}>
                  {state.evidence.detail}
                </span>
                <span style={{ marginLeft: "auto", color: "var(--text-faint)" }}>Ed25519 · sha256 links</span>
              </div>
            </div>
          </Panel>
        </div>

        {/* Release gates */}
        <div className="col-6">
          <Panel title="First-Milestone Release Gates" tag="Governance">
            <div className="panel-body">
              {state.gates.map((g) => (
                <div className="gate-row" key={g.name}>
                  <span className="gate-name">
                    <span className={`dot ${g.pass ? "ok" : "bad"}`} style={{ marginRight: 8 }} />
                    {g.name}
                  </span>
                  <span className="gate-val" style={{ color: g.pass ? "var(--cyan)" : "var(--red)" }}>{g.value}</span>
                  <span className="gate-target">{g.target}</span>
                </div>
              ))}
            </div>
          </Panel>
        </div>

        {/* Slice timeline */}
        <div className="col-5">
          <Panel title="Vertical-Slice Trace" tag="First milestone">
            <div className="panel-body panel-scroll">
              {state.steps.map((s) => (
                <div className="step-row" key={s.n}>
                  <span className="step-n">{String(s.n).padStart(2, "0")}</span>
                  <span className={stepDot(s.status)} style={{ marginTop: 5 }} />
                  <div className="step-body">
                    <div className="step-title">{s.title}</div>
                    <div className="step-summary">{s.summary}</div>
                    <div className="step-plane">{s.plane}</div>
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        </div>

        {/* Memory grid */}
        <div className="col-7">
          <Panel title="Sovereign Memory" tag="Plane C · tenant t_acme">
            <div className="panel-body flush">
              <table className="dtable">
                <thead>
                  <tr>
                    <th>Object</th><th>Class</th><th>Sensitivity</th><th>Purpose</th><th>State</th>
                  </tr>
                </thead>
                <tbody>
                  {state.memory.map((mem) => {
                    const flags: string[] = [];
                    if (mem.revocation_state === "revoked") flags.push("revoked");
                    if (mem.deletion_state === "deleted") flags.push("deleted");
                    return (
                      <tr key={mem.memory_id}>
                        <td style={{ color: "var(--text)" }}>{mem.memory_id}</td>
                        <td><span className="chip">{mem.memory_class}</span></td>
                        <td><span className={classChip(mem.classification)}>{mem.classification}</span></td>
                        <td style={{ color: "var(--text-dim)", fontSize: 10 }}>{mem.purpose_constraints.join(", ")}</td>
                        <td>
                          {flags.length ? (
                            flags.map((f) => <span key={f} className="chip red">{f}</span>)
                          ) : (
                            <span className="chip cyan">{mem.verification_state}</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>
      </div>

      <footer className="foot">
        <div>
          Continuum minimises disclosure, cryptographically constrains authorization, records every
          release and action, and provides measurable leakage-resistance guarantees within an explicitly
          defined threat model. It does not claim that leakage is mathematically impossible.
        </div>
        <div style={{ marginTop: 6 }}>
          Snapshot {state.generated_at} · in-memory reference control plane · zero observed events ≠ proof
          of impossibility — see docs/CLAIMS.md.
        </div>
      </footer>
    </div>
  );
}

function Panel({
  title,
  tag,
  children,
}: {
  title: string;
  tag: string;
  children: React.ReactNode;
}) {
  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title" dangerouslySetInnerHTML={{ __html: title }} />
        <span className="panel-tag">{tag}</span>
      </div>
      {children}
    </div>
  );
}

function ActionFlow({ action }: { action: ActionRecord }) {
  const denied = action.state === "DENIED";
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
        <span className={`dot ${denied ? "bad" : action.requires_human_approval ? "warn" : "ok"}`} />
        <span className="mono" style={{ fontSize: 10.5 }}>{action.operation}</span>
        <span className={`chip ${denied ? "red" : "amber"}`} style={{ marginLeft: "auto" }}>{action.action_class}</span>
      </div>
      <div className="flow">
        {action.history.map((h, i) => (
          <span key={i} style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            {i > 0 && <span className="arrow">→</span>}
            <span className={`stage ${h.state === "DENIED" ? "" : h.state === "HUMAN_APPROVED" ? "gate" : "done"}`}>
              {h.state}
            </span>
          </span>
        ))}
      </div>
      {denied && <div className="reason" style={{ marginTop: 4 }}><span className="k">blocked</span> · {action.denied_reason}</div>}
      {action.requires_human_approval && !denied && (
        <div className="reason" style={{ marginTop: 4 }}>human approval required · proposing agent cannot self-approve</div>
      )}
    </div>
  );
}

function LedgerRow({ e }: { e: EvidenceEnvelope }) {
  return (
    <div className="led-row">
      <span className="led-seq">{String(e.seq).padStart(2, "0")}</span>
      <span className="led-type">
        {e.event_type}
        {e.decision && <span style={{ color: "var(--text-faint)" }}> · {e.decision}</span>}
      </span>
      <span style={{ textAlign: "right" }}>
        <span className="led-hash">{e.hash.slice(0, 10)}</span>
        <span className="led-sig"> ✓sig</span>
      </span>
    </div>
  );
}
