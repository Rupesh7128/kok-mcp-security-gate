import { NextResponse } from "next/server";
import { scanMcp } from "../../../lib/scan.js";
import { assertPublicUrl } from "../../../lib/ssrf.js";
import { consume, clientIp } from "../../../lib/ratelimit.js";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(req) {
  let body;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Body must be JSON." }, { status: 400 }); }
  try { assertPublicUrl(body.url); } catch (e) { return NextResponse.json({ error: e.message, code: e.code }, { status: 400 }); }
  const rl = consume(clientIp(req), "scan");
  if (!rl.ok) return NextResponse.json({ error: `Free tier: ${rl.limit} scans per day per IP.`, rateLimit: rl }, { status: 429 });
  try {
    return NextResponse.json({ ...(await scanMcp(String(body.url))), rateLimit: rl });
  } catch (e) {
    const status = e.code === "SSRF_BLOCKED" || e.code === "BAD_URL" ? 400 : 502;
    return NextResponse.json({ error: e.message, code: e.code }, { status });
  }
}
