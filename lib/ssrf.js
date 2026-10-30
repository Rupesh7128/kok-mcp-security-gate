/**
 * SSRF guard + pinned-address HTTP client.
 * Every outbound request (scan or BotShield) goes through safeRequest():
 *  - only http/https, no credentials in the URL
 *  - hostnames and every resolved address are checked against private/loopback/link-local/etc. ranges
 *  - the address that was validated is the one connected to (lookup hook), so DNS rebinding can't swap it
 *  - redirects are never followed
 *  - response body is size-capped, request has a hard timeout
 * `allowPrivate` exists ONLY for local CLI scripts testing a bot you run yourself; the HTTP API never sets it.
 */
import dns from "node:dns";
import net from "node:net";
import http from "node:http";
import https from "node:https";

const BLOCKED_NAMES = [/^localhost$/i, /\.localhost$/i, /\.local$/i, /\.internal$/i, /\.lan$/i, /\.home$/i, /^metadata\.google\.internal$/i];

function v4ToInt(ip) {
  return ip.split(".").reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
}
const V4_BLOCKS = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
].map(([b, bits]) => ({ base: v4ToInt(b), mask: bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0 }));

export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const n = v4ToInt(ip);
    return V4_BLOCKS.some((b) => ((n & b.mask) >>> 0) === b.base);
  }
  if (net.isIPv6(ip)) {
    const s = ip.toLowerCase();
    if (s === "::" || s === "::1") return true;
    const mapped = s.match(/^(?:0*:)*:?ffff:(\d+\.\d+\.\d+\.\d+)$/) || s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIp(mapped[1]);
    const mappedHex = s.match(/^(?:0*:)*:?ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (mappedHex) {
      const hi = parseInt(mappedHex[1], 16), lo = parseInt(mappedHex[2], 16);
      return isPrivateIp(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }
    if (/^fe[89ab]/.test(s)) return true; // link-local fe80::/10
    if (/^f[cd]/.test(s)) return true; // unique local fc00::/7
    if (/^ff/.test(s)) return true; // multicast
    if (/^(64:ff9b|2001:db8|2002:)/.test(s)) return true; // NAT64, doc, 6to4 (can embed private v4)
    return false;
  }
  return true; // not an IP at all -> treat as unsafe
}

/** Throws Error(code=SSRF_BLOCKED | BAD_URL) unless the URL is safe to contact. Returns the parsed URL. */
export function assertPublicUrl(raw, { allowPrivate = false } = {}) {
  let u;
  try { u = new URL(String(raw)); } catch { throw coded("BAD_URL", "Not a valid URL."); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw coded("BAD_URL", "Only http(s) URLs are allowed.");
  if (u.username || u.password) throw coded("BAD_URL", "Credentials in URLs are not allowed.");
  if (allowPrivate) return u;
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (BLOCKED_NAMES.some((re) => re.test(host))) throw coded("SSRF_BLOCKED", `Host "${host}" is blocked (local/internal name).`);
  if (net.isIP(host) && isPrivateIp(host)) throw coded("SSRF_BLOCKED", `Address ${host} is in a blocked private/loopback/link-local range.`);
  // Integer / hex / octal IPv4 forms are normalised by WHATWG URL to dotted quad, so the check above covers them.
  if (/^[0-9.]+$/.test(host) && !net.isIP(host)) throw coded("BAD_URL", "Malformed IP address.");
  return u;
}

function coded(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

/**
 * @returns {Promise<{status:number, headers:Record<string,string|string[]>, body:string, truncated:boolean}>}
 */
export async function safeRequest(rawUrl, { method = "GET", headers = {}, body, timeoutMs = 10000, maxBytes = 262144, allowPrivate = false } = {}) {
  const u = assertPublicUrl(rawUrl, { allowPrivate });
  const lib = u.protocol === "https:" ? https : http;
  const lookup = (hostname, opts, cb) => {
    dns.lookup(hostname, { ...opts, all: true }, (err, addrs) => {
      if (err) return cb(err);
      const list = Array.isArray(addrs) ? addrs : [{ address: addrs, family: 4 }];
      const bad = !allowPrivate && list.find((a) => isPrivateIp(a.address));
      if (bad) return cb(coded("SSRF_BLOCKED", `Host resolves to blocked address ${bad.address}.`));
      if (opts && opts.all) return cb(null, list);
      cb(null, list[0].address, list[0].family);
    });
  };
  return new Promise((resolve, reject) => {
    const req = lib.request(
      u,
      { method, headers: { "user-agent": "kok-mcp-security-gate/0.1 (+https://work.kingdomofkumar.com)", ...headers }, lookup, timeout: timeoutMs },
      (res) => {
        const chunks = [];
        let size = 0, truncated = false;
        res.on("data", (c) => {
          size += c.length;
          if (size > maxBytes) { truncated = true; res.destroy(); return; }
          chunks.push(c);
        });
        const done = () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8"), truncated });
        res.on("end", done);
        res.on("close", done);
        res.on("error", reject);
      }
    );
    req.on("timeout", () => req.destroy(coded("TIMEOUT", `Timed out after ${timeoutMs}ms.`)));
    req.on("error", reject);
    if (body != null) req.write(body);
    req.end();
  });
}
