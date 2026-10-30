"use client";
import { useState } from "react";

export default function Shield() {
  const [url, setUrl] = useState("");
  const [format, setFormat] = useState("json");
  const [field, setField] = useState("message");
  const [ok, setOk] = useState(false);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const [err, setErr] = useState(null);

  async function go(e) {
    e.preventDefault();
    setBusy(true); setErr(null); setRes(null);
    try {
      const r = await fetch("/api/botshield", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url, format, field, confirmOwnBot: ok }) });
      const j = await r.json();
      if (!r.ok) setErr(j.error || "Run failed."); else setRes(j);
    } catch (x) { setErr(x.message); }
    setBusy(false);
  }

  return (
    <section id="botshield">
      <h2>BotShield</h2>
      <p className="sub">Free tier sends 5 fixed injection probes by POST. Your bot's replies are checked for leaked prompt markers, tool schemas, secrets and obedience to an injected canary token.</p>
      <form onSubmit={go}>
        <label htmlFor="boturl">Your bot's HTTP endpoint (POST)</label>
        <input id="boturl" type="url" required placeholder="https://your-bot.example.com/chat" value={url} onChange={(e) => setUrl(e.target.value)} />
        <div className="row">
          <div><label htmlFor="fmt">Body format</label><select id="fmt" value={format} onChange={(e) => setFormat(e.target.value)}><option value="json">JSON {"{message}"}</option><option value="form">Form-encoded</option></select></div>
          <div><label htmlFor="fld">Field name</label><input id="fld" type="text" value={field} onChange={(e) => setField(e.target.value)} /></div>
        </div>
        <label className="check"><input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} />I own this bot or am authorised to test it, and I accept that adversarial prompts will be sent to it.</label>
        <button disabled={busy || !ok}>{busy ? "Probing…" : "Run 5 probes"}</button>
      </form>
      <div className="out" aria-live="polite">
        {err && <div className="err">{err}</div>}
        {res && (
          <>
            <div className="score"><span className="n" style={{ fontSize: 44 }}>{res.overallSeverity}</span><span className="g">{res.probesRun} of {res.suiteSize} probes · {res.counts.pass} no marker · {res.counts.inconclusive} inconclusive</span></div>
            {res.results.map((r) => (
              <div className="card" key={r.id}>
                <h3><span className={"tag " + (r.severity === "critical" ? "crit" : r.severity)}>{r.severity}</span>{r.category} · <code>{r.id}</code></h3>
                <p>{r.evidence?.length ? r.evidence.map((e) => `${e.kind}: ${e.detail}`).join("; ") : r.note}</p>
                {r.replyExcerpt && <p><code>{r.replyExcerpt.slice(0, 200)}</code></p>}
              </div>
            ))}
            <ul className="limits">{res.limits.map((l, i) => <li key={i}>{l}</li>)}</ul>
          </>
        )}
      </div>
    </section>
  );
}
