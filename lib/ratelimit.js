/**
 * Free tier: N runs per IP per UTC day, in process memory (courtesy limit; resets on serverless cold start).
 * Use a shared store (Upstash/Vercel KV) for a real quota.
 */
const buckets = new Map();
export const freeLimit = () => { const n = Number(process.env.FREE_RUNS_PER_DAY); return Number.isFinite(n) && n > 0 ? n : 5; };

export function consume(ip, kind) {
  const day = new Date().toISOString().slice(0, 10);
  const key = `${day}|${kind}|${ip}`;
  if (buckets.size > 5000) for (const k of buckets.keys()) if (!k.startsWith(day)) buckets.delete(k);
  const used = buckets.get(key) ?? 0;
  const limit = freeLimit();
  if (used >= limit) return { ok: false, used, limit, remaining: 0 };
  buckets.set(key, used + 1);
  return { ok: true, used: used + 1, limit, remaining: limit - used - 1 };
}
export function clientIp(req) {
  const xf = req.headers.get("x-forwarded-for");
  return (xf ? xf.split(",")[0].trim() : req.headers.get("x-real-ip")) || "unknown";
}
