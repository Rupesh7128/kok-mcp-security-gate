"use client";
import { useState } from "react";

export default function Gate() {
  const [url, setUrl] = useState("https://cofounderbase.com/api/mcp/");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const [err, setErr] = useState(null);

  async function go(e) {
    e.preventDefault();
    setBusy(true); setErr(null); setRes(null);
    try {
      const r = await fetch("/api/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }) });
      const j = await r.json();
      if (!r.ok) setErr(j.error || "Scan failed."); else setRes(j);
    } catch (x) { setErr(x.message); }
    setBusy(false);
  }

  return (
    <section id="gate">
      <h2>MCP Security Gate</h2>
      <p className="sub">Read-only. Sends initialize and tools/list (twice) and never calls a tool.</p>
      <form onSubmit={go}>
        <label htmlFor="mcpurl">Public MCP endpoint</label>
        <input id="mcpurl" type="url" required value={url} onChange={(e) => setUrl(e.target.value)} />
        <button disabled={busy}>{busy ? "Scanning…" : "Scan"}</button>
      </form>
      <div className="out" aria-live="polite">
        {err && <div className="err">{err}</div>}
        {res && res.error && <div className="err">{res.error}</div>}
        {res && !res.error && (
          <>
            <div className="score"><span className="n">{res.score}</span><span className="g">/ 100 · grade {res.grade}{res.partial ? " · partial scan" : ""}</span></div>
            <p className="sub">{res.server?.name || "unknown server"} · {res.toolCount ?? 0} tools · rug-pull check: {res.rugPullCheck ? (res.rugPullCheck.stable === true ? "stable across 2 fetches" : res.rugPullCheck.stable === false ? "CHANGED" : "inconclusive") : "n/a"}</p>
            {res.findings.map((f, i) => (
              <div className="card" key={i}><h3><span className={"tag " + (f.severity === "critical" ? "crit" : f.severity)}>{f.severity}</span>{f.title}</h3><p>{f.detail}</p></div>
            ))}
            <h3>Rubric</h3>
            <table><tbody>
              <tr><th>Check</th><th>Points</th><th>Rule</th></tr>
              {res.rubric.map((r) => <tr key={r.id}><td><code>{r.id}</code></td><td>{r.points}</td><td>{r.rule}</td></tr>)}
            </tbody></table>
            <p>Applied: {res.deductions.length ? res.deductions.map((d) => `${d.id} ${d.points}`).join(", ") : "none"} → 100 {res.deductions.reduce((s, d) => s + d.points, 0)} = {res.score}</p>
            <ul className="limits">{res.limits.map((l, i) => <li key={i}>{l}</li>)}</ul>
          </>
        )}
      </div>
    </section>
  );
}
