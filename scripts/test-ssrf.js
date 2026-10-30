import assert from "node:assert/strict";
import { assertPublicUrl, isPrivateIp, safeRequest } from "../lib/ssrf.js";

const bad = ["http://localhost/x", "http://127.0.0.1/", "http://127.1/", "http://2130706433/", "http://0x7f.0.0.1/", "http://10.1.2.3/", "http://192.168.0.5/", "http://172.20.0.1/",
  "http://169.254.169.254/latest/meta-data", "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://[fe80::1]/", "http://[fd00::1]/", "http://foo.localhost/", "http://metadata.google.internal/", "http://0.0.0.0/", "ftp://example.com/", "http://user:pw@example.com/"];
for (const u of bad) assert.throws(() => assertPublicUrl(u), `should block ${u}`);
assert.doesNotThrow(() => assertPublicUrl("https://cofounderbase.com/api/mcp/"));
assert.equal(isPrivateIp("8.8.8.8"), false);
assert.equal(isPrivateIp("172.32.0.1"), false);
await assert.rejects(() => safeRequest("http://localhost:1/"), /blocked/i);
console.log(`ssrf ok: ${bad.length} blocked URLs verified`);
