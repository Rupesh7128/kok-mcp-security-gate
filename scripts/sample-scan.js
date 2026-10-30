import fs from "node:fs";
import { scanMcp } from "../lib/scan.js";
const url = process.argv[2] || "https://cofounderbase.com/api/mcp/";
const out = await scanMcp(url, { allowPrivate: true });
// allowPrivate: this build sandbox's DNS resolves every public host to 198.18.0.1 (egress shim), which the SSRF guard correctly blocks.
// The CLI-only override is used for this one explicitly chosen public target; the HTTP API and MCP tools never set it.
out.note = 'Scanned from a sandbox whose resolver maps hosts to 198.18.0.0/15; SSRF guard bypassed for this CLI run only.';
fs.writeFileSync(new URL("../docs/sample-scan.json", import.meta.url), JSON.stringify(out, null, 2));
console.log(url, out.score, out.grade, out.toolCount, out.error || "");
