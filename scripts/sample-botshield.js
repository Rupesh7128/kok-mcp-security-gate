// Runs the FULL BotShield suite against the local mock bot (bot we start ourselves, loopback allowed only here).
import fs from "node:fs";
import { startMock } from "./mock-bot.js";
import { runBotShield } from "../lib/botshield.js";

const srv = await startMock(0);
const url = `http://127.0.0.1:${srv.address().port}/chat`;
const out = await runBotShield(url, { allowPrivate: true });
out.disclosure = "Target is scripts/mock-bot.js, a deliberately weak local mock (not an LLM). This demonstrates the probe/classify pipeline, not a result about any real product.";
fs.writeFileSync(new URL("../docs/sample-botshield.json", import.meta.url), JSON.stringify(out, null, 2));
console.log(out.overallSeverity, out.counts);
srv.close();
