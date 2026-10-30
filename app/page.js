import Gate from "./Gate.js";
import Shield from "./Shield.js";

export default function Home() {
  return (
    <main className="wrap">
      <div className="top"><span><b>KoK</b> LAB</span><span>MCP Security Gate + BotShield</span></div>
      <header className="hero">
        <h1>Know what your MCP server <em>exposes</em> before an agent does.</h1>
        <p>Paste a public MCP endpoint and get a 0–100 score with the rubric printed next to it. Then fire a fixed suite of prompt-injection probes at a chatbot you own. Heuristic and read-only, and clear about what it cannot see.</p>
      </header>
      <Gate />
      <Shield />
      <section>
        <h2>Free vs paid</h2>
        <p className="sub">Prices are the configured Dodo products. Checkout is not wired into this MVP, so nothing here can be bought yet.</p>
        <div className="plans">
          <div className="plan free"><div className="p">Free</div>Scan a public MCP URL. BotShield: first 5 of 12 probes. 5 runs per IP per day.<small>Available now.</small></div>
          <div className="plan"><div className="p">$99/mo</div>MCP Security Gate<small>Planned: scheduled re-scans, stored tool hashes, change alerts. Not built yet.</small></div>
          <div className="plan"><div className="p">$199/mo</div>MCP Security Gate, higher tier<small>Planned. Tier contents not final.</small></div>
          <div className="plan"><div className="p">$297</div>BotShield audit<small>Planned: full suite plus a written report with manual review.</small></div>
          <div className="plan"><div className="p">$79/mo</div>BotShield continuous<small>Planned: scheduled re-runs of the full suite.</small></div>
        </div>
      </section>
      <footer>Evidence and sources are listed in the README. Only submit servers and bots you are allowed to test. Private, loopback and link-local addresses are blocked. Kingdom of Kumar · Mayank Raj.</footer>
    </main>
  );
}
