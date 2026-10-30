# MCP Security Gate + BotShield

By Kingdom of Kumar Lab (Mayank Raj). Two tools in one Next.js app, plus a stdio MCP server:

- **MCP Security Gate** takes a public MCP endpoint and sends `initialize`, `notifications/initialized` and `tools/list` (twice). It never calls a tool. It returns a 0–100 score with the rubric printed beside it.
- **BotShield** POSTs a fixed suite of 12 prompt-injection probes to a bot you own, as JSON `{message}` or a form body. It classifies each reply for leaked system-prompt markers, tool dumps, secrets, an exfiltration channel and canary obedience.

## Run

```bash
npm install
npm run dev                 # UI + /api/scan, /api/botshield
npm test                    # SSRF guard: 18 blocked URL forms
npm run sample:scan         # rewrites docs/sample-scan.json (live request)
npm run sample:botshield    # starts scripts/mock-bot.js, rewrites docs/sample-botshield.json
npm run mcp                 # stdio MCP: scan_mcp_server, botshield_probe
```

## What the scanner checks

| Check | Points |
|---|---|
| Plain `http://` transport | −20 |
| No auth needed for initialize + tools/list | −15 |
| Overly broad tool (exec/shell/sql/fetch/file-write/catch-all name) | −8 each, max −24 |
| Injection phrasing in a tool description | −25 each, max −50 |
| **Rug-pull**: tool name/description/schema hash differs between two fetches | −40 |
| Tool with no declared input properties | −3 each, max −9 |
| No tool annotations | −4 |
| `Access-Control-Allow-Origin: *` on an unauthenticated endpoint | −3 |

Grades are A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below that. The full rubric, the deductions applied and a list of limits are in every JSON response.

Honest limits:
- The scanner is black-box and read-only. It does not test what tools do.
- The two fetches are about 1.5 s apart. They catch dynamic definition changes, not a change made next week. The per-tool SHA-256 hashes are in the output so you can pin them and re-scan.
- The broad-name and poisoning checks are regex heuristics and will produce false positives and misses.
- A server that demands credentials gets a partial scan, because the scanner never sends credentials.

## API

```
POST /api/scan       {"url": "https://host/mcp"}
POST /api/botshield  {"url": "https://host/chat", "confirmOwnBot": true, "format": "json"|"form", "field": "message"}
```

`confirmOwnBot` must be exactly `true` or the API returns 400. The free API runs the first 5 probes, with 5 runs per IP per day. The limit is held in process memory, so it is a courtesy limit and not a hard quota.

## SSRF policy

`lib/ssrf.js` blocks these:
- localhost and `*.localhost`, `*.local`, `*.internal`
- RFC1918, CGNAT, loopback, link-local (including 169.254.169.254), multicast and reserved IPv4 ranges
- IPv6 loopback, ULA, link-local, v4-mapped and 6to4/NAT64 forms
- decimal, hex and short IPv4 spellings, because WHATWG URL parsing normalises them

It also resolves DNS and checks every returned address. The checked address is the one connected to (a `lookup` hook), so DNS rebinding can't swap it. Redirects are not followed, and response size and time are capped. The `allowPrivate` override exists only for local CLI scripts. The HTTP API and the MCP tools never set it.

## Free vs paid

Free: scan any public MCP URL, and BotShield with 5 probes. Everything else is **planned and not shipped**. Checkout is not wired in this MVP. These are the configured Dodo product ids (`lib/pricing.js`):

| Product | Price | Id |
|---|---|---|
| Gate | $99/mo | pdt_0NqsRJm8bbkA8CqUWb3IR |
| Gate (higher tier) | $199/mo | pdt_0NqsRMpUeSxVRwjvfKRYl |
| BotShield audit | $297 | pdt_0NqsRJzZsDeF8GssBgAoj |
| BotShield continuous | $79/mo | pdt_0NqsRKDH4B9BBWSpBhHs6 |

## Evidence and sources

This README makes no claims about vulnerability counts. The checks come from threat classes described in the sources below.

- OWASP LLM01:2025 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/ (URL from memory; not fetched in this build.)
- OWASP MCP Security Cheat Sheet: the OWASP Cheat Sheet Series, `cheatsheetseries.owasp.org`. **The exact URL was not verified in this build because web access was denied. Confirm it before citing.**
- Astrix Security, 2025 MCP security research blog: astrix.security. **The exact post URL was not verified in this build. Confirm it, and quote any statistics from the post itself and not from this repo.**
- ArXiv: papers on MCP tool poisoning and rug-pull attacks exist. **None is cited here, because none could be verified in this build.** Add specific arXiv ids after checking them.

The probe categories (direct override, prompt extraction, role/delimiter confusion, obfuscation, exfiltration) follow the attack classes described under OWASP LLM01.

## Samples (real runs)

- `docs/sample-scan.json`: live scan of https://cofounderbase.com/api/mcp/, the test target you specified. Score 82 (B), 5 tools, stable across both fetches. Findings: no auth (medium) and wildcard CORS (low). The sandbox's resolver mapped every host to 198.18.0.1, which the guard correctly blocks. The sample therefore used the CLI-only `allowPrivate` override for that one target, and the JSON says so.
- `docs/sample-botshield.json`: full 12-probe suite against `scripts/mock-bot.js`, a deliberately weak local mock and **not an LLM**. It demonstrates the pipeline only. It says nothing about any real product.

Sibling project `citation-monitor` supplied the rate-limit and stdio MCP patterns.
