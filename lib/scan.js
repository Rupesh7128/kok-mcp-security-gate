/**
 * MCP server risk scanner. Speaks plain JSON-RPC over streamable HTTP (JSON or SSE replies).
 * Read-only: only calls initialize, notifications/initialized and tools/list. It never calls a tool.
 */
import crypto from "node:crypto";
import { safeRequest } from "./ssrf.js";

export const RUBRIC = [
  { id: "transport", points: -20, rule: "Endpoint is plain http:// (no TLS)." },
  { id: "no-auth", points: -15, rule: "initialize + tools/list succeed with no Authorization header. May be intentional for a public read-only server; it still means anyone can enumerate and call tools." },
  { id: "broad-tool", points: -8, rule: "Per tool whose name/description signals arbitrary execution, raw SQL, arbitrary fetch or file write (max -24)." },
  { id: "poisoning", points: -25, rule: "Per tool whose description contains instruction-injection phrasing aimed at the model (max -50)." },
  { id: "rug-pull", points: -40, rule: "Tool name/description/schema hash differs between two tools/list fetches in the same session." },
  { id: "loose-schema", points: -3, rule: "Per tool with no inputSchema, or an object schema that allows arbitrary extra properties and has no declared properties (max -9)." },
  { id: "no-annotations", points: -4, rule: "No tool declares annotations (readOnlyHint/destructiveHint), so clients cannot gate risky calls." },
  { id: "wildcard-cors", points: -3, rule: "Access-Control-Allow-Origin: * on an endpoint that is unauthenticated or accepts bearer tokens: any web page can drive it from a user's browser." },
  { id: "no-tools", points: 0, rule: "Servers exposing zero tools score on the checks that still apply; this is reported, not penalised." },
];

const BROAD = [
  [/(^|[_\-.])(exec|execute|shell|bash|sh|cmd|command|run_?command|system|eval|spawn)([_\-.]|$)/i, "arbitrary command/code execution"],
  [/(^|[_\-.])(sql|raw_?query|query_?db|database)([_\-.]|$)/i, "raw database access"],
  [/(^|[_\-.])(fetch|http_?request|curl|browse|download|proxy)([_\-.]|$)/i, "arbitrary network fetch (SSRF surface)"],
  [/(write|delete|remove|overwrite|put)[_\-.]?(file|path|dir)|(^|[_\-.])(fs|file)[_\-.]?(write|delete)/i, "filesystem write/delete"],
  [/^(any|all|\*|do|admin|root|sudo|call|invoke|tool|run)$/i, "catch-all tool name"],
];
const POISON = [
  /ignore (all |any )?(previous|prior|above) (instructions|prompts?)/i,
  /<\s*important\s*>/i,
  /do not (tell|inform|mention|reveal)[^.]{0,40}(user|human)/i,
  /(without|before)[^.]{0,30}(asking|telling|informing)[^.]{0,20}(user|human)/i,
  /(read|send|include|exfiltrate)[^.]{0,60}(\.ssh|id_rsa|\.env|api[_ -]?key|credentials|password)/i,
  /system prompt/i,
  /you (must|should) (always )?(first )?call/i,
];

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
function canon(v) {
  if (Array.isArray(v)) return v.map(canon);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])]));
  return v;
}
export const hashTool = (t) => sha(JSON.stringify(canon({ name: t.name, description: t.description ?? "", inputSchema: t.inputSchema ?? null })));

function parseRpc(res) {
  const ct = String(res.headers["content-type"] || "");
  let text = res.body.trim();
  if (ct.includes("text/event-stream") || text.startsWith("event:") || text.startsWith("data:")) {
    const datas = text.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim());
    text = datas[datas.length - 1] || "";
  }
  try { return JSON.parse(text); } catch { return null; }
}

async function rpcRaw(url, payload, extra = {}, allowPrivate = false) {
  return safeRequest(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...extra },
    body: JSON.stringify(payload),
    timeoutMs: 12000,
    allowPrivate,
  });
}

export async function scanMcp(url, { allowPrivate = false } = {}) {
  const rpc = (u, p, e) => rpcRaw(u, p, e, allowPrivate);
  const started = Date.now();
  const findings = [];
  const deductions = [];
  const deduct = (id, points, detail) => deductions.push({ id, points, detail });
  const find = (severity, id, title, detail) => findings.push({ severity, id, title, detail });
  const out = { target: url, scannedAt: new Date().toISOString(), method: "initialize → notifications/initialized → tools/list ×2 (read-only; no tool is ever called)" };

  if (new URL(url).protocol === "http:") {
    deduct("transport", -20, "Endpoint is http://, traffic is unencrypted.");
    find("high", "transport", "No TLS", "Endpoint uses plain http://.");
  }

  // 1. initialize with NO credentials.
  const init = await rpc(url, {
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "kok-mcp-security-gate", version: "0.1.0" } },
  });
  out.initialize = { httpStatus: init.status };
  const wwwAuth = init.headers["www-authenticate"];
  if (init.status === 401 || init.status === 403) {
    out.authRequired = true;
    out.initialize.wwwAuthenticate = wwwAuth || null;
    find("info", "auth-required", "Server demands credentials", `HTTP ${init.status}${wwwAuth ? ` (WWW-Authenticate: ${wwwAuth})` : ""}. The scanner does not send credentials, so tools were not enumerated. Tool-level checks were skipped, score reflects only what is observable without auth.`);
    return finish(out, deductions, findings, started, { partial: true });
  }
  const initMsg = parseRpc(init);
  if (init.status >= 400 || !initMsg || !initMsg.result) {
    out.error = `Not a working MCP endpoint: HTTP ${init.status}, ${initMsg?.error ? "JSON-RPC error " + JSON.stringify(initMsg.error).slice(0, 200) : "no JSON-RPC initialize result"}.`;
    out.score = null;
    out.grade = null;
    out.rubric = RUBRIC;
    out.durationMs = Date.now() - started;
    return out;
  }
  out.authRequired = false;
  out.server = initMsg.result.serverInfo || null;
  out.protocolVersion = initMsg.result.protocolVersion || null;
  out.capabilities = initMsg.result.capabilities || null;
  const session = init.headers["mcp-session-id"];
  const sess = session ? { "mcp-session-id": session, "mcp-protocol-version": initMsg.result.protocolVersion || "2025-03-26" } : { "mcp-protocol-version": initMsg.result.protocolVersion || "2025-03-26" };
  await rpc(url, { jsonrpc: "2.0", method: "notifications/initialized" }, sess).catch(() => {});

  const acao = init.headers["access-control-allow-origin"];
  out.headers = {
    "access-control-allow-origin": acao || null,
    "content-security-policy": init.headers["content-security-policy"] || null,
    "strict-transport-security": init.headers["strict-transport-security"] || null,
    "x-content-type-options": init.headers["x-content-type-options"] || null,
  };

  // 2. tools/list twice, hash each tool.
  const fetchTools = async (id) => {
    const r = await rpc(url, { jsonrpc: "2.0", id, method: "tools/list", params: {} }, sess);
    if (r.status === 401 || r.status === 403) return { authRequired: true, status: r.status };
    const m = parseRpc(r);
    if (!m || !m.result || !Array.isArray(m.result.tools)) return { error: m?.error ? JSON.stringify(m.error).slice(0, 200) : `HTTP ${r.status}, no tools array` };
    let tools = m.result.tools;
    let cursor = m.result.nextCursor, pages = 1;
    while (cursor && pages < 5) {
      const rp = await rpc(url, { jsonrpc: "2.0", id: id + 100 * pages, method: "tools/list", params: { cursor } }, sess);
      const mp = parseRpc(rp);
      if (!mp?.result?.tools) break;
      tools = tools.concat(mp.result.tools);
      cursor = mp.result.nextCursor;
      pages++;
    }
    return { tools };
  };
  const a = await fetchTools(2);
  if (a.authRequired) {
    out.authRequired = true;
    find("info", "auth-required", "tools/list requires credentials", `initialize succeeded anonymously but tools/list returned HTTP ${a.status}. Tool checks skipped.`);
    return finish(out, deductions, findings, started, { partial: true });
  }
  if (a.error) {
    out.error = `tools/list failed: ${a.error}`;
    return finish(out, deductions, findings, started, { partial: true });
  }
  await new Promise((r) => setTimeout(r, 1500));
  const b = await fetchTools(3);

  deduct("no-auth", -15, "initialize and tools/list succeeded with no Authorization header.");
  find("medium", "no-auth", "No authentication required", "Anyone can enumerate tools. Acceptable for a deliberately public read-only server; not acceptable if any tool writes data, sends messages or spends money. OWASP MCP guidance: authenticate and authorise every client.");

  const tools = a.tools;
  out.toolCount = tools.length;
  out.tools = tools.map((t) => ({ name: t.name, hash: hashTool(t), hasAnnotations: !!t.annotations, annotations: t.annotations || null }));

  // rug-pull: compare two fetches
  if (b.tools) {
    const ha = new Map(tools.map((t) => [t.name, hashTool(t)]));
    const hb = new Map(b.tools.map((t) => [t.name, hashTool(t)]));
    const changed = [...ha.keys()].filter((n) => hb.has(n) && hb.get(n) !== ha.get(n));
    const added = [...hb.keys()].filter((n) => !ha.has(n));
    const removed = [...ha.keys()].filter((n) => !hb.has(n));
    out.rugPullCheck = { fetches: 2, gapMs: 1500, changed, added, removed, stable: !changed.length && !added.length && !removed.length };
    if (!out.rugPullCheck.stable) {
      deduct("rug-pull", -40, `Tool definitions changed between two fetches: changed=[${changed}] added=[${added}] removed=[${removed}].`);
      find("critical", "rug-pull", "Tool schema changed between fetches", `changed=[${changed}] added=[${added}] removed=[${removed}]`);
    }
  } else {
    out.rugPullCheck = { fetches: 1, stable: null, note: `Second fetch failed: ${b.error || "auth"}. Rug-pull check inconclusive.` };
  }

  // static tool checks
  let broad = 0, poison = 0, loose = 0;
  for (const t of tools) {
    const text = `${t.name} ${t.description || ""}`;
    const nameHit = BROAD.find(([re]) => re.test(t.name));
    const descHit = !nameHit && /(execute (arbitrary|any)|run (arbitrary|any)|arbitrary (command|code|sql|url)|any (shell )?command)/i.test(t.description || "");
    if ((nameHit || descHit) && broad < 3) {
      broad++;
      const why = nameHit ? nameHit[1] : "description claims arbitrary execution";
      deduct("broad-tool", -8, `Tool "${t.name}": ${why}.`);
      find("high", "broad-tool", `Overly broad tool: ${t.name}`, why);
    }
    const p = POISON.find((re) => re.test(t.description || ""));
    if (p && poison < 2) {
      poison++;
      deduct("poisoning", -25, `Tool "${t.name}" description matches injection phrasing ${p}.`);
      find("critical", "poisoning", `Possible tool-description injection: ${t.name}`, `Pattern ${p} matched in description. Review manually; regex hits can be false positives.`);
    }
    const s = t.inputSchema;
    const props = s && s.properties ? Object.keys(s.properties).length : 0;
    if ((!s || (s.type === "object" && !props && s.additionalProperties !== false)) && loose < 3) {
      loose++;
      deduct("loose-schema", -3, `Tool "${t.name}" has no declared input properties.`);
      find("low", "loose-schema", `Loose input schema: ${t.name}`, "No declared properties; the server must validate everything itself.");
    }
  }
  if (tools.length && !tools.some((t) => t.annotations)) {
    deduct("no-annotations", -4, "No tool carries annotations (readOnlyHint / destructiveHint / idempotentHint).");
    find("low", "no-annotations", "No tool annotations", "Clients cannot distinguish read-only from destructive tools.");
  }
  if (!tools.length) find("info", "no-tools", "Server exposes zero tools", "Nothing to analyse at tool level.");
  if (acao === "*") {
    deduct("wildcard-cors", -3, "Access-Control-Allow-Origin: * on an unauthenticated endpoint.");
    find("low", "wildcard-cors", "Wildcard CORS", "Any web origin can call this endpoint from a visitor's browser. Fine for public data; risky if tools act on a user's behalf.");
  }
  return finish(out, deductions, findings, started, {});
}

function finish(out, deductions, findings, started, { partial = false }) {
  const total = deductions.reduce((s, d) => s + d.points, 0);
  out.score = Math.max(0, 100 + total);
  out.grade = out.score >= 90 ? "A" : out.score >= 75 ? "B" : out.score >= 60 ? "C" : out.score >= 40 ? "D" : "F";
  out.partial = partial;
  out.deductions = deductions;
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  out.findings = findings.sort((x, y) => order[x.severity] - order[y.severity]);
  out.rubric = RUBRIC;
  out.limits = [
    "Black-box and read-only: no tool is invoked, so tool behaviour (injection handling, authz inside tools) is NOT tested.",
    "Rug-pull check compares two fetches ~1.5s apart in one session. It catches servers that change definitions dynamically, not a change made next week. Store the per-tool hashes and re-scan to pin.",
    "Poisoning and broad-tool checks are heuristics (name/description regexes). Expect false positives and misses.",
    "A high score is not a certification of safety.",
  ];
  out.durationMs = Date.now() - started;
  return out;
}
