#!/usr/bin/env node
/**
 * MCP Security Gate + BotShield: stdio MCP server.
 * Tools: scan_mcp_server, botshield_probe (requires confirmOwnBot:true). Private/loopback hosts are blocked.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { scanMcp } from "../lib/scan.js";
import { runBotShield, PROBES } from "../lib/botshield.js";

const server = new McpServer({ name: "kok-mcp-security-gate", version: "0.1.0" });
const text = (o, isError = false) => ({ content: [{ type: "text", text: typeof o === "string" ? o : JSON.stringify(o, null, 2) }], isError });

server.tool(
  "scan_mcp_server",
  "Scan a public MCP endpoint (initialize + tools/list x2, read-only) and return a 0-100 score with the rubric, findings and tool hashes.",
  { url: z.string().url() },
  async ({ url }) => {
    try { return text(await scanMcp(url)); } catch (e) { return text(`Scan failed: ${e.message}`, true); }
  }
);

server.tool(
  "botshield_probe",
  `POST up to ${PROBES.length} fixed prompt-injection probes to a bot you own. confirmOwnBot must be true.`,
  {
    url: z.string().url(),
    confirmOwnBot: z.boolean(),
    format: z.enum(["json", "form"]).default("json"),
    field: z.string().default("message"),
    limit: z.number().int().min(1).max(PROBES.length).default(5),
  },
  async ({ url, confirmOwnBot, format, field, limit }) => {
    if (confirmOwnBot !== true) return text("confirmOwnBot:true is required: only test bots you own or are authorised to test.", true);
    try { return text(await runBotShield(url, { format, field, limit })); } catch (e) { return text(`BotShield failed: ${e.message}`, true); }
  }
);

await server.connect(new StdioServerTransport());
