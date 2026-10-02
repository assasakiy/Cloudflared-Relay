// Pakai: npm run setup-admin -- admin@example.com "password-minimal-12"
// Lokal (wrangler dev): LOCAL=1 npm run setup-admin -- ...
import { webcrypto as crypto } from "node:crypto";
import { execSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const [email, password] = process.argv.slice(2);
if (!email || !password || password.length < 12) {
  console.error('Pakai: npm run setup-admin -- <email> "<password minimal 12 karakter>"');
  process.exit(1);
}
const ITER = 100000;
const salt = crypto.getRandomValues(new Uint8Array(16));
const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: ITER }, key, 256);
const b64 = (b) => Buffer.from(b).toString("base64");
const value = JSON.stringify({ email: email.trim().toLowerCase(), hash: `pbkdf2$${ITER}$${b64(salt)}$${b64(bits)}` });

const tmpFile = path.join(os.tmpdir(), `relay-admin-${Date.now()}.json`);
fs.writeFileSync(tmpFile, value, "utf8");

try {
  const targetFlag = process.env.LOCAL ? "--local" : "--remote";
  const cmd = `npx wrangler kv key put admin --path "${tmpFile}" --binding=RELAY_KV ${targetFlag}`;
  execSync(cmd, { stdio: "inherit", shell: true });
  console.log("Admin dibuat:", email);
} finally {
  if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
}
