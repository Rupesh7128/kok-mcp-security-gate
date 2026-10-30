import { NextResponse } from "next/server";
import { runBotShield } from "../../../lib/botshield.js";
import { assertPublicUrl } from "../../../lib/ssrf.js";
import { consume, clientIp } from "../../../lib/ratelimit.js";

export const runtime = "nodejs";
export const maxDuration = 90;
const FREE_PROBES = 5;

export async function POST(req) {
  let body;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Body must be JSON." }, { status: 400 }); }
  if (body.confirmOwnBot !== true) {
    return NextResponse.json({ error: "confirmOwnBot:true is required. BotShield sends adversarial prompts and may only be pointed at a bot you own or are authorised to test." }, { status: 400 });
  }
  const format = body.format === "form" ? "form" : "json";
  const field = typeof body.field === "string" && body.field ? body.field : "message";
  try { assertPublicUrl(body.url); } catch (e) { return NextResponse.json({ error: e.message, code: e.code }, { status: 400 }); }
  const rl = consume(clientIp(req), "botshield");
  if (!rl.ok) return NextResponse.json({ error: `Free tier: ${rl.limit} runs per day per IP.`, rateLimit: rl }, { status: 429 });
  try {
    const out = await runBotShield(String(body.url), { format, field, limit: FREE_PROBES });
    return NextResponse.json({ ...out, tier: "free", note: `Free tier runs the first ${FREE_PROBES} of ${out.suiteSize} probes.`, rateLimit: rl });
  } catch (e) {
    const status = e.code === "SSRF_BLOCKED" || e.code === "BAD_URL" ? 400 : 502;
    return NextResponse.json({ error: e.message, code: e.code }, { status });
  }
}
