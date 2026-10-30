# REPORT: MCP Security Gate + BotShield

**Build:** `npm run build` is green (Next 15, static `/`, dynamic `/api/scan`, `/api/botshield`, `/api/health`).

## Verified
- `npm test`: 18 forms of private, loopback, link-local, metadata and encoded-IP URLs are blocked, and a public URL is allowed.
- Live API check: `localhost` and `169.254.169.254` return 400 SSRF_BLOCKED. BotShield without `confirmOwnBot:true` returns 400. With consent but a loopback URL it returns 400 SSRF_BLOCKED.
- Stdio MCP: `initialize` and `tools/list` list 2 tools. The consent gate and the SSRF guard also work through the MCP tools.
- Real scan of cofounderbase MCP: score 82/B. Deductions: no-auth −15 and wildcard CORS −3. Tools: search_agencies, match_agencies, get_agency, top_agencies, request_intro. Rug-pull check stable. See `docs/sample-scan.json`.
- Real BotShield against the local mock (`scripts/mock-bot.js`): 2 critical, 4 high, 6 no-marker. See `docs/sample-botshield.json`.

## Caveats (read these)
1. **Sandbox DNS vs the SSRF guard.** The sandbox maps all hosts to 198.18.0.1, so the guard blocked even the public target. The sample scan used the CLI-only `allowPrivate` override, and the JSON discloses it. The guard itself is not weakened, so on a normal host the API will scan cofounderbase without any override. I did not test that path end to end here.
2. **Sources not verified.** Web tools were denied, so the Astrix and OWASP MCP cheat-sheet URLs and any arXiv ids are unverified placeholders, flagged in the README. Only the OWASP LLM01 URL is given, from memory. No CVE counts or statistics are claimed.
3. **Heuristics.** Both the scanner and BotShield classifiers are regex-based. The README lists the limits.
4. **Billing not wired.** The product ids sit in `lib/pricing.js` and the UI marks all paid tiers "planned". The $99/$199 tier split is undefined, and I did not invent features for it.
5. **Rate limit.** In-memory, so it is not a hard quota on serverless.
6. **UI not visually checked.** I did not open a browser. It builds and is styled with only #b83a07, #0e1b1d and #eeebe3 (plus alpha tints of them).
7. No deploy and no push. No secrets in the repo (product ids are public identifiers).
