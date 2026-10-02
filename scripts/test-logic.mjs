import assert from "node:assert/strict";
import { webcrypto as crypto } from "node:crypto";

// --- SSRF Logic Check ---
function isPrivateIPv4(ip) {
  const parts = ip.split(".").map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return false;
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}

function validateTargetUrl(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return { valid: false, reason: "invalid_url_format" };
  }
  if (url.protocol !== "https:") return { valid: false, reason: "protocol_not_allowed" };
  if (url.username || url.password) return { valid: false, reason: "credentials_in_url" };
  const hostname = url.hostname.toLowerCase();
  if (!hostname) return { valid: false, reason: "empty_hostname" };
  if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") || hostname.endsWith(".internal")) {
    return { valid: false, reason: "private_host_blocked" };
  }
  const isIpv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  if (isIpv4 && isPrivateIPv4(hostname)) return { valid: false, reason: "private_ip_blocked" };
  return { valid: true, target: { url, hostname } };
}

function isTargetAllowed(hostname, allowedList) {
  const normHost = hostname.toLowerCase();
  for (const entry of allowedList) {
    const normEntry = entry.trim().toLowerCase();
    if (!normEntry) continue;
    if (normHost === normEntry) return true;
    if (normEntry.startsWith("*.") && normHost.endsWith(normEntry.slice(1))) return true;
  }
  return false;
}

// --- Crypto Logic Check ---
const toBase64 = (b) => Buffer.from(b).toString("base64");
const fromBase64 = (b64) => Buffer.from(b64, "base64");

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let c = 0;
  for (let i = 0; i < a.length; i++) c |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return c === 0;
}

async function hashAdminPassword(password) {
  const iter = 100000;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, key, 256);
  return `pbkdf2$${iter}$${toBase64(salt)}$${toBase64(bits)}`;
}

async function verifyAdminPassword(password, storedHash) {
  const parts = storedHash.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iter = parseInt(parts[1], 10);
  const salt = fromBase64(parts[2]);
  const expectedBitsB64 = parts[3];
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, key, 256);
  return timingSafeEqual(toBase64(bits), expectedBitsB64);
}

// --- RUN TESTS ---
console.log("Running self-check tests...");

// 1. SSRF Tests
assert.equal(validateTargetUrl("http://api.xkiro.com").valid, false, "HTTP must be blocked");
assert.equal(validateTargetUrl("https://localhost/foo").valid, false, "localhost must be blocked");
assert.equal(validateTargetUrl("https://127.0.0.1/test").valid, false, "127.0.0.1 must be blocked");
assert.equal(validateTargetUrl("https://169.254.169.254/metadata").valid, false, "AWS metadata must be blocked");
assert.equal(validateTargetUrl("https://192.168.1.1/admin").valid, false, "192.168.* must be blocked");
assert.equal(validateTargetUrl("https://10.0.0.5/api").valid, false, "10.* must be blocked");
assert.equal(validateTargetUrl("https://user:pass@api.xkiro.com").valid, false, "Credentials in URL blocked");
assert.equal(validateTargetUrl("https://api.xkiro.com/v1").valid, true, "Valid HTTPS URL allowed");

// 2. Target Whitelist tests
const whitelist = ["api.xkiro.com", "api.openai.com", "*.anthropic.com"];
assert.equal(isTargetAllowed("api.xkiro.com", whitelist), true, "Exact host allowed");
assert.equal(isTargetAllowed("api.xkiro.com.evil.com", whitelist), false, "Subdomain evasion blocked");
assert.equal(isTargetAllowed("evil-api.xkiro.com", whitelist), false, "Prefix evasion blocked");
assert.equal(isTargetAllowed("v1.anthropic.com", whitelist), true, "Wildcard subdomain allowed");

// 3. Password Verification
const samplePw = "PasswordSuperAman123!";
const hash = await hashAdminPassword(samplePw);
assert.equal(await verifyAdminPassword(samplePw, hash), true, "Password matches");
assert.equal(await verifyAdminPassword("SalahPassword123!", hash), false, "Wrong password rejected");

console.log("All self-check tests PASSED!");
