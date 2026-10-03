import { Hono, type Context } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import type { Bindings, Client, ApiKeyRecord, SessionRecord, AdminRecord } from "./types";
import {
  sha256Hex,
  randomHex,
  randomAlphanumeric,
  verifyAdminPassword,
  hashAdminPassword,
} from "./lib/crypto";
import { validateTargetUrl, isTargetAllowed } from "./lib/ssrf";
import {
  getAdmin,
  saveAdmin,
  createSession,
  getSession,
  deleteSession,
  getGlobalSettings,
  saveGlobalSettings,
  getGlobalTargets,
  saveGlobalTargets,
  listAllClients,
  getClient,
  saveClient,
  deleteClient,
  findAndAuthenticateClient,
  appendRelayLog,
  getRecentRelayLogs,
  clearRelayLogs,
} from "./lib/kv";
import dashboardHtml from "./dashboard";

type Variables = {
  session: SessionRecord;
};

interface Env {
  Bindings: Bindings;
  Variables: Variables;
}

const app = new Hono<Env>();

// --- Relay Request Parser & Handler ---

interface ParsedRelay {
  apiKey?: string;
  password?: string;
  targetUrl: string;
}

function parseRelayRequest(c: Context<Env>): { parsed?: ParsedRelay; error?: string } {
  let rawPath = c.req.path;
  const urlObj = new URL(c.req.url);

  // 1. Ekstraksi API Key & Password dari Header & Query Params
  let apiKey =
    c.req.header("x-relay-api-key") ||
    c.req.query("key") ||
    c.req.query("api_key") ||
    c.req.query("apiKey");

  let password =
    c.req.header("x-relay-password") ||
    c.req.query("password") ||
    c.req.query("pass") ||
    c.req.query("pwd");

  // 2. Ekstraksi Kredensial dari URL Path jika ada
  let remainingPath = rawPath;

  if (remainingPath.startsWith("/key/") || remainingPath.startsWith("/k/")) {
    const parts = remainingPath.split("/").filter(Boolean);
    if (parts.length >= 2) {
      if (!apiKey) apiKey = parts[1];
      remainingPath = "/" + parts.slice(2).join("/");
    }
  } else if (remainingPath.startsWith("/pass/") || remainingPath.startsWith("/p/")) {
    const parts = remainingPath.split("/").filter(Boolean);
    if (parts.length >= 2) {
      if (!password) password = parts[1];
      remainingPath = "/" + parts.slice(2).join("/");
    }
  } else if (remainingPath.startsWith("/relay_")) {
    const parts = remainingPath.split("/").filter(Boolean);
    if (parts.length >= 1) {
      if (!apiKey) apiKey = parts[0];
      remainingPath = "/" + parts.slice(1).join("/");
    }
  } else if (remainingPath === "/relay" || remainingPath.startsWith("/relay/")) {
    remainingPath = remainingPath.replace(/^\/relay/, "") || "/";
  }

  // 3. Ekstraksi Target Upstream
  const targetHeader = c.req.header("x-relay-target");
  const pathHeader = c.req.header("x-relay-path");
  const queryUrl = c.req.query("url");

  let fullTargetUrl = "";

  if (targetHeader) {
    let base = targetHeader.trim();
    if (base.endsWith("/")) base = base.slice(0, -1);

    let subpath = "";
    if (pathHeader) {
      subpath = pathHeader.trim();
    } else if (remainingPath && remainingPath !== "/") {
      subpath = remainingPath;
    }
    if (subpath && !subpath.startsWith("/")) subpath = "/" + subpath;

    // Masukkan search query params selain auth param relay
    const forwardQuery = new URLSearchParams(urlObj.searchParams);
    forwardQuery.delete("key");
    forwardQuery.delete("api_key");
    forwardQuery.delete("apiKey");
    forwardQuery.delete("password");
    forwardQuery.delete("pass");
    forwardQuery.delete("pwd");
    forwardQuery.delete("url");
    const qs = forwardQuery.toString();

    fullTargetUrl = base + subpath + (qs ? "?" + qs : "");
  } else if (queryUrl) {
    fullTargetUrl = queryUrl.trim();
  } else if (remainingPath.startsWith("/http://") || remainingPath.startsWith("/https://")) {
    // Format target langsung di path: /<key>/https://api.openai.com/v1/...
    fullTargetUrl = remainingPath.slice(1);
    const forwardQuery = new URLSearchParams(urlObj.searchParams);
    forwardQuery.delete("key");
    forwardQuery.delete("api_key");
    forwardQuery.delete("apiKey");
    forwardQuery.delete("password");
    forwardQuery.delete("pass");
    forwardQuery.delete("pwd");
    const qs = forwardQuery.toString();
    if (qs) fullTargetUrl += (fullTargetUrl.includes("?") ? "&" : "?") + qs;
  }

  if (!fullTargetUrl) {
    return { error: "missing_target" };
  }

  return { parsed: { apiKey, password, targetUrl: fullTargetUrl } };
}

async function handleRelay(c: Context<Env>) {
  const kv = c.env.RELAY_KV;

  // 1. Parse request (URL path, query, headers)
  const reqData = parseRelayRequest(c);
  if (!reqData.parsed) {
    return c.json({ error: reqData.error || "missing_target" }, 400);
  }
  const { apiKey, password, targetUrl: fullTargetUrl } = reqData.parsed;

  // 2. Validasi SSRF
  const targetCheck = validateTargetUrl(fullTargetUrl);
  if (!targetCheck.valid) {
    return c.json({ error: "invalid_target" }, 400);
  }
  const { url: targetUrl, hostname: targetHost } = targetCheck.target;

  // 3. Autentikasi Client
  const clientIp = c.req.header("cf-connecting-ip") || "";

  const authResult = await findAndAuthenticateClient(kv, { apiKey, password, clientIp });
  if (!authResult.client) {
    if (authResult.reason === "client_disabled") {
      return c.json({ error: "access_denied" }, 403);
    }
    return c.json({ error: "unauthorized" }, 401);
  }
  const client = authResult.client;

  // 4. Target Restriction Check
  if (client.restrict) {
    if (!isTargetAllowed(targetHost, client.targets)) {
      return c.json({ error: "target_not_allowed" }, 403);
    }
  }

  const globalSettings = await getGlobalSettings(kv);
  if (globalSettings.targetRestrict) {
    const globalTargets = await getGlobalTargets(kv);
    if (!isTargetAllowed(targetHost, globalTargets)) {
      return c.json({ error: "target_not_allowed" }, 403);
    }
  }

  // 5. Forward Request Upstream
  const forwardHeaders = new Headers();
  for (const [key, value] of c.req.raw.headers.entries()) {
    const k = key.toLowerCase();
    if (
      k === "host" ||
      k.startsWith("x-relay-") ||
      k.startsWith("cf-") ||
      k === "cookie"
    ) {
      continue;
    }
    forwardHeaders.set(key, value);
  }

  const method = c.req.method.toUpperCase();
  const init: RequestInit = {
    method,
    headers: forwardHeaders,
    redirect: "follow",
  };

  if (method !== "GET" && method !== "HEAD") {
    init.body = c.req.raw.body;
    (init as any).duplex = "half";
  }

  const startTime = Date.now();
  try {
    const upstreamRes = await fetch(targetUrl.toString(), init);
    const durationMs = Date.now() - startTime;

    // Catat metadata request (tanpa body/credential)
    c.executionCtx.waitUntil(
      appendRelayLog(kv, {
        id: randomAlphanumeric(10),
        timestamp: Date.now(),
        clientId: client.id,
        clientName: client.name,
        method,
        targetHost,
        targetPath: targetUrl.pathname + targetUrl.search,
        status: upstreamRes.status,
        durationMs,
        ip: clientIp,
      })
    );

    return new Response(upstreamRes.body, {
      status: upstreamRes.status,
      statusText: upstreamRes.statusText,
      headers: upstreamRes.headers,
    });
  } catch (err: any) {
    const durationMs = Date.now() - startTime;
    c.executionCtx.waitUntil(
      appendRelayLog(kv, {
        id: randomAlphanumeric(10),
        timestamp: Date.now(),
        clientId: client.id,
        clientName: client.name,
        method,
        targetHost,
        targetPath: targetUrl.pathname + targetUrl.search,
        status: 502,
        durationMs,
        ip: clientIp,
      })
    );
    return c.json({ error: "upstream_error", message: err?.message || "fetch failed" }, 502);
  }
}

// --- Server-Side Dashboard Rendering with Baked-in Branding ---

function escapeHtml(s: string): string {
  return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

async function getRenderedDashboard(kv: KVNamespace): Promise<string> {
  const settings = await getGlobalSettings(kv);
  const name = settings.appName || "Relay Gateway";
  const logo = settings.logoUrl || "";
  const favicon = logo || "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%233b5bfd' stroke-width='2.2'><path d='M4 12h12M12 6l6 6-6 6'/></svg>";

  let html = dashboardHtml;
  html = html.replace("<title>Relay Gateway Dashboard</title>", `<title>${escapeHtml(name)}</title>`);
  html = html.replace(/<link rel="icon" id="dynamicFavicon" href="[^"]*">/, `<link rel="icon" id="dynamicFavicon" href="${escapeHtml(favicon)}">`);

  if (logo) {
    html = html.replace('<div class="mark" id="lMark"></div>', `<div class="mark has-logo" id="lMark"><img src="${escapeHtml(logo)}" class="logo-img" alt="logo"></div>`);
    html = html.replace('<div class="mark" id="mMark"></div>', `<div class="mark has-logo" id="mMark"><img src="${escapeHtml(logo)}" class="logo-img" alt="logo"></div>`);
    html = html.replace('<div class="mark" id="sMark"></div>', `<div class="mark has-logo" id="sMark"><img src="${escapeHtml(logo)}" class="logo-img" alt="logo"></div>`);
  }
  html = html.replace(/<span id="lName">Relay Gateway<\/span>/g, `<span id="lName">${escapeHtml(name)}</span>`);
  html = html.replace(/<span id="mName">Relay Gateway<\/span>/g, `<span id="mName">${escapeHtml(name)}</span>`);
  html = html.replace(/<span id="sName">Relay Gateway<\/span>/g, `<span id="sName">${escapeHtml(name)}</span>`);

  return html;
}

// --- Static Dashboard & Page Routing ---

app.get("/", async (c) => {
  // Jika ada query param relay url, forward ke relay
  if (c.req.query("url") || c.req.header("x-relay-target")) {
    return handleRelay(c);
  }
  if (c.executionCtx) {
    c.executionCtx.waitUntil(ensureBootstrap(c.env.RELAY_KV, c.env));
  }
  const token = getCookie(c, "relay_session");
  if (token) {
    const session = await getSession(c.env.RELAY_KV, token);
    if (session) {
      return c.redirect("/dashboard/clients");
    }
  }
  return c.redirect("/login");
});

app.get("/login", async (c) => {
  if (c.executionCtx) {
    c.executionCtx.waitUntil(ensureBootstrap(c.env.RELAY_KV, c.env));
  }
  const token = getCookie(c, "relay_session");
  if (token) {
    const session = await getSession(c.env.RELAY_KV, token);
    if (session) {
      return c.redirect("/dashboard/clients");
    }
  }
  const html = await getRenderedDashboard(c.env.RELAY_KV);
  return c.html(html);
});

app.get("/dashboard", (c) => c.redirect("/dashboard/clients"));

app.get("/dashboard/*", async (c) => {
  const token = getCookie(c, "relay_session");
  if (!token) {
    return c.redirect("/login");
  }
  const session = await getSession(c.env.RELAY_KV, token);
  if (!session) {
    return c.redirect("/login");
  }
  const html = await getRenderedDashboard(c.env.RELAY_KV);
  return c.html(html);
});

app.get("/clients", (c) => c.redirect("/dashboard/clients"));
app.get("/targets", (c) => c.redirect("/dashboard/targets"));
app.get("/logs", (c) => c.redirect("/dashboard/logs"));
app.get("/analytics", (c) => c.redirect("/dashboard/logs"));
app.get("/settings", (c) => c.redirect("/dashboard/settings"));

// --- Auth Middleware untuk API ---

app.use("/api/*", async (c, next) => {
  const path = c.req.path;
  if (path === "/api/auth/login" || path === "/api/auth/status") {
    return next();
  }

  const token = getCookie(c, "relay_session");
  if (!token) {
    return c.json({ error: "unauthorized" }, 401);
  }

  const session = await getSession(c.env.RELAY_KV, token);
  if (!session) {
    return c.json({ error: "unauthorized" }, 401);
  }

  c.set("session", session);
  return next();
});

// --- Auth APIs ---

const CURRENT_BUILD_VERSION = "2026.10.03.2";

async function ensureBootstrap(kv: KVNamespace, env: Bindings): Promise<AdminRecord> {
  let admin = await getAdmin(kv);
  if (!admin) {
    const defaultEmail = (env.ADMIN_INITIAL_EMAIL || "admin@example.com").trim().toLowerCase();
    const defaultPass = env.ADMIN_INITIAL_PASSWORD || "AdminSuperSecret123!";
    const hash = await hashAdminPassword(defaultPass);
    admin = { email: defaultEmail, hash };
    await saveAdmin(kv, admin);

    const targets = await getGlobalTargets(kv);
    if (targets.length === 0) {
      await saveGlobalTargets(kv, ["api.openai.com", "httpbin.org"]);
    }
  }

  const envAccountId = (env.CLOUDFLARE_ACCOUNT_ID || env.CF_ANALYTICS_ACCOUNT_ID || "").trim();
  const envToken = (env.CLOUDFLARE_API_TOKEN || env.CF_ANALYTICS_API_TOKEN || "").trim();
  const settings = await getGlobalSettings(kv);
  let changed = false;

  if (!settings.appName) {
    settings.appName = "Relay Gateway";
    settings.targetRestrict = false;
    settings.theme = "auto";
    changed = true;
  }

  // Update Account ID dari environment build jika berubah / baru
  if (envAccountId && envAccountId !== settings.cfAccountId) {
    settings.cfAccountId = envAccountId;
    changed = true;
  }

  // Cek apakah token berubah dari environment build
  const tokenToVerify = envToken || settings.cfApiToken || "";
  const tokenChanged = envToken && envToken !== settings.cfApiToken;

  if (tokenChanged) {
    settings.cfApiToken = envToken;
    changed = true;
  }

  // Verifikasi token hanya saat token baru/berubah atau build baru (bukan di setiap request)
  if (tokenToVerify && (tokenChanged || settings.cfTokenVerified === undefined || settings.cfTokenLastVersion !== CURRENT_BUILD_VERSION)) {
    try {
      const res = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
        headers: { Authorization: "Bearer " + tokenToVerify },
      });
      const data: any = await res.json().catch(() => ({}));
      if (res.ok && data.success && data.result?.status === "active") {
        settings.cfTokenVerified = true;
        settings.cfTokenStatusMsg = "Token aktif & valid. Siap untuk deploy & build repo.";
      } else {
        settings.cfTokenVerified = false;
        settings.cfTokenStatusMsg = data.errors?.[0]?.message || "Token tidak aktif / di-revoke di Cloudflare";
      }
    } catch {
      settings.cfTokenVerified = null;
      settings.cfTokenStatusMsg = "Gagal memverifikasi ke Cloudflare API";
    }
    settings.cfTokenLastVersion = CURRENT_BUILD_VERSION;
    settings.cfTokenLastChecked = Date.now();
    changed = true;
  }

  if (changed) {
    await saveGlobalSettings(kv, settings);
  }

  return admin;
}

interface LoginBody {
  email?: string;
  password?: string;
}

app.get("/api/auth/status", async (c) => {
  const admin = await ensureBootstrap(c.env.RELAY_KV, c.env);
  const settings = await getGlobalSettings(c.env.RELAY_KV);
  const token = getCookie(c, "relay_session");
  let loggedIn = false;
  let email: string | null = null;
  if (token) {
    const session = await getSession(c.env.RELAY_KV, token);
    if (session) {
      loggedIn = true;
      email = session.email;
    }
  }
  return c.json({
    configured: true,
    loggedIn,
    email,
    branding: {
      appName: settings.appName || "Relay Gateway",
      logoUrl: settings.logoUrl || "",
      theme: settings.theme || "auto",
    },
  });
});

app.post("/api/auth/login", async (c) => {
  const body = await c.req.json<LoginBody>().catch(() => ({} as LoginBody));
  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";

  if (!email || !password) {
    return c.json({ error: "missing_credentials" }, 400);
  }

  const kv = c.env.RELAY_KV;
  const admin = await ensureBootstrap(kv, c.env);

  if (admin.email !== email) {
    return c.json({ error: "invalid_credentials" }, 401);
  }

  const ok = await verifyAdminPassword(password, admin.hash);
  if (!ok) {
    return c.json({ error: "invalid_credentials" }, 401);
  }

  const token = randomHex(32);
  await createSession(kv, token, email);
  setCookie(c, "relay_session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    maxAge: 604800,
  });

  return c.json({ success: true, email });
});

app.post("/api/auth/logout", async (c) => {
  const token = getCookie(c, "relay_session");
  if (token) {
    await deleteSession(c.env.RELAY_KV, token);
    deleteCookie(c, "relay_session", { path: "/" });
  }
  return c.json({ success: true });
});

app.get("/api/auth/me", (c) => {
  const session = c.get("session");
  return c.json({ authenticated: true, email: session.email });
});

// --- Client Management APIs ---

interface ClientMutationBody {
  name?: string;
  status?: boolean;
  logic?: "ANY" | "ALL";
  ips?: string[];
  newPassword?: string;
  generatePassword?: boolean;
  removePassword?: boolean;
  generateKey?: boolean;
  revokeKeyId?: string;
  restrict?: boolean;
  targets?: string[];
}

app.get("/api/clients", async (c) => {
  const clients = await listAllClients(c.env.RELAY_KV);
  const safe = clients.map((cl) => ({
    id: cl.id,
    name: cl.name,
    status: cl.status,
    logic: cl.logic,
    ips: cl.ips,
    pass: !!cl.passHash,
    key: cl.keys.find((k) => k.status === "active")?.prefix || null,
    keys: cl.keys.map((k) => ({
      id: k.id,
      name: k.name,
      prefix: k.prefix,
      status: k.status,
      createdAt: k.createdAt,
      lastUsedAt: k.lastUsedAt,
    })),
    restrict: cl.restrict,
    targets: cl.targets,
    createdAt: cl.createdAt,
    updatedAt: cl.updatedAt,
  }));
  return c.json(safe);
});

app.post("/api/clients", async (c) => {
  const kv = c.env.RELAY_KV;
  const body = await c.req.json<ClientMutationBody>().catch(() => ({} as ClientMutationBody));

  const name = (body.name || "").trim();
  if (!name) {
    return c.json({ error: "missing_name" }, 400);
  }

  const id = "c_" + randomAlphanumeric(6);
  let passHash: string | null = null;
  let rawPassword: string | null = null;

  if (body.newPassword) {
    passHash = await sha256Hex(body.newPassword);
  } else if (body.generatePassword) {
    rawPassword = randomAlphanumeric(20);
    passHash = await sha256Hex(rawPassword);
  }

  const keys: ApiKeyRecord[] = [];
  let rawKey: string | null = null;

  if (body.generateKey) {
    rawKey = "relay_" + randomAlphanumeric(16);
    const keyHash = await sha256Hex(rawKey);
    keys.push({
      id: "ak_" + randomAlphanumeric(6),
      name: "Default Key",
      prefix: rawKey.slice(0, 11),
      hash: keyHash,
      status: "active",
      createdAt: Date.now(),
    });
  }

  const client: Client = {
    id,
    name,
    status: body.status !== false,
    logic: body.logic === "ALL" ? "ALL" : "ANY",
    ips: Array.isArray(body.ips) ? body.ips.map((ip: string) => ip.trim()).filter(Boolean) : [],
    passHash,
    keys,
    restrict: !!body.restrict,
    targets: Array.isArray(body.targets) ? body.targets.map((t: string) => t.trim().toLowerCase()).filter(Boolean) : [],
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };

  await saveClient(kv, client);

  return c.json({
    client: {
      id: client.id,
      name: client.name,
      status: client.status,
      logic: client.logic,
      ips: client.ips,
      pass: !!client.passHash,
      key: client.keys.find((k) => k.status === "active")?.prefix || null,
      restrict: client.restrict,
      targets: client.targets,
    },
    rawPassword,
    rawKey,
  }, 201);
});

app.put("/api/clients/:id", async (c) => {
  const kv = c.env.RELAY_KV;
  const id = c.req.param("id");
  const client = await getClient(kv, id);

  if (!client) {
    return c.json({ error: "client_not_found" }, 404);
  }

  const body = await c.req.json<ClientMutationBody>().catch(() => ({} as ClientMutationBody));

  if (body.name !== undefined) client.name = body.name.trim() || client.name;
  if (body.status !== undefined) client.status = !!body.status;
  if (body.logic !== undefined) client.logic = body.logic === "ALL" ? "ALL" : "ANY";
  if (Array.isArray(body.ips)) {
    client.ips = body.ips.map((ip: string) => ip.trim()).filter(Boolean);
  }
  if (body.restrict !== undefined) client.restrict = !!body.restrict;
  if (Array.isArray(body.targets)) {
    client.targets = body.targets.map((t: string) => t.trim().toLowerCase()).filter(Boolean);
  }

  let rawPassword: string | null = null;
  if (body.newPassword) {
    client.passHash = await sha256Hex(body.newPassword);
  } else if (body.generatePassword) {
    rawPassword = randomAlphanumeric(20);
    client.passHash = await sha256Hex(rawPassword);
  } else if (body.removePassword) {
    client.passHash = null;
  }

  let rawKey: string | null = null;
  if (body.generateKey) {
    for (const k of client.keys) {
      if (k.status === "active") k.status = "revoked";
    }
    rawKey = "relay_" + randomAlphanumeric(16);
    const keyHash = await sha256Hex(rawKey);
    client.keys.push({
      id: "ak_" + randomAlphanumeric(6),
      name: "Rotated Key",
      prefix: rawKey.slice(0, 11),
      hash: keyHash,
      status: "active",
      createdAt: Date.now(),
    });
  }

  if (body.revokeKeyId) {
    for (const k of client.keys) {
      if (k.id === body.revokeKeyId) k.status = "revoked";
    }
  }

  client.updatedAt = Date.now();
  await saveClient(kv, client);

  return c.json({
    client: {
      id: client.id,
      name: client.name,
      status: client.status,
      logic: client.logic,
      ips: client.ips,
      pass: !!client.passHash,
      key: client.keys.find((k) => k.status === "active")?.prefix || null,
      restrict: client.restrict,
      targets: client.targets,
    },
    rawPassword,
    rawKey,
  });
});

app.delete("/api/clients/:id", async (c) => {
  const kv = c.env.RELAY_KV;
  const id = c.req.param("id");
  const ok = await deleteClient(kv, id);
  if (!ok) {
    return c.json({ error: "client_not_found" }, 404);
  }
  return c.json({ success: true });
});

// --- Targets & Settings APIs ---

interface TargetsBody {
  target?: string;
  targets?: string[];
}

app.get("/api/targets", async (c) => {
  const targets = await getGlobalTargets(c.env.RELAY_KV);
  return c.json(targets);
});

app.post("/api/targets", async (c) => {
  const body = await c.req.json<TargetsBody>().catch(() => ({} as TargetsBody));
  const kv = c.env.RELAY_KV;
  const current = await getGlobalTargets(kv);

  if (body.target) {
    const clean = body.target.trim().toLowerCase();
    if (clean && !current.includes(clean)) {
      current.push(clean);
      await saveGlobalTargets(kv, current);
    }
  } else if (Array.isArray(body.targets)) {
    const cleanList = body.targets.map((t: string) => t.trim().toLowerCase()).filter(Boolean);
    await saveGlobalTargets(kv, Array.from(new Set(cleanList)));
  }

  const updated = await getGlobalTargets(kv);
  return c.json(updated);
});

app.delete("/api/targets/:target", async (c) => {
  const target = decodeURIComponent(c.req.param("target")).trim().toLowerCase();
  const kv = c.env.RELAY_KV;
  const current = await getGlobalTargets(kv);
  const updated = current.filter((t) => t !== target);
  await saveGlobalTargets(kv, updated);
  return c.json(updated);
});

interface SettingsBody {
  targetRestrict?: boolean;
  appName?: string;
  logoUrl?: string;
  theme?: "auto" | "light" | "dark";
  cfAccountId?: string;
  cfApiToken?: string;
  adminEmail?: string;
  newPassword?: string;
}

app.get("/api/settings", async (c) => {
  const kv = c.env.RELAY_KV;
  const settings = await getGlobalSettings(kv);
  const admin = await getAdmin(kv);

  const envAccountId = (c.env.CLOUDFLARE_ACCOUNT_ID || c.env.CF_ANALYTICS_ACCOUNT_ID || "").trim();
  const envToken = (c.env.CLOUDFLARE_API_TOKEN || c.env.CF_ANALYTICS_API_TOKEN || "").trim();

  const effectiveAccountId = settings.cfAccountId || envAccountId;
  const effectiveToken = settings.cfApiToken || envToken;
  const hasToken = !!effectiveToken;
  const tokenSource = envToken ? "env" : (settings.cfApiToken ? "kv" : "none");

  return c.json({
    targetRestrict: settings.targetRestrict,
    appName: settings.appName || "Relay Gateway",
    logoUrl: settings.logoUrl || "",
    theme: settings.theme || "auto",
    adminEmail: admin?.email || "Belum diatur",
    cfAccountId: effectiveAccountId,
    cfApiToken: effectiveToken,
    hasCfToken: hasToken,
    cfTokenSource: tokenSource,
    tokenVerified: settings.cfTokenVerified ?? null,
    tokenStatusMsg: settings.cfTokenStatusMsg || "",
  });
});

app.post("/api/settings/verify-cf", async (c) => {
  const kv = c.env.RELAY_KV;
  const settings = await getGlobalSettings(kv);
  const token = (settings.cfApiToken || c.env.CLOUDFLARE_API_TOKEN || c.env.CF_ANALYTICS_API_TOKEN || "").trim();

  if (!token) {
    return c.json({ valid: false, error: "Token Cloudflare tidak ditemukan di secret/KV" });
  }

  try {
    const res = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
      headers: { Authorization: "Bearer " + token },
    });
    const data: any = await res.json().catch(() => ({}));
    if (res.ok && data.success && data.result?.status === "active") {
      settings.cfTokenVerified = true;
      settings.cfTokenStatusMsg = "Token aktif & valid. Siap untuk deploy & build repo.";
      settings.cfTokenLastChecked = Date.now();
      await saveGlobalSettings(kv, settings);
      return c.json({
        valid: true,
        status: "active",
        message: "Token Cloudflare valid dan aktif. Aman untuk build & update repo.",
      });
    }
    settings.cfTokenVerified = false;
    settings.cfTokenStatusMsg = data.errors?.[0]?.message || "Token tidak valid atau sudah di-revoke";
    settings.cfTokenLastChecked = Date.now();
    await saveGlobalSettings(kv, settings);
    return c.json({
      valid: false,
      status: "invalid",
      error: settings.cfTokenStatusMsg,
    });
  } catch (err: any) {
    return c.json({
      valid: false,
      error: err?.message || "Gagal menghubungi Cloudflare API",
    });
  }
});

app.post("/api/settings", async (c) => {
  const kv = c.env.RELAY_KV;
  const body = await c.req.json<SettingsBody>().catch(() => ({} as SettingsBody));

  const settings = await getGlobalSettings(kv);

  if (body.targetRestrict !== undefined) {
    settings.targetRestrict = !!body.targetRestrict;
  }
  if (body.appName !== undefined) {
    settings.appName = body.appName.trim() || "Relay Gateway";
  }
  if (body.logoUrl !== undefined) {
    settings.logoUrl = body.logoUrl.trim();
  }
  if (body.theme !== undefined) {
    settings.theme = body.theme;
  }
  if (body.cfAccountId !== undefined) {
    settings.cfAccountId = body.cfAccountId.trim();
  }
  if (body.cfApiToken !== undefined && body.cfApiToken.trim()) {
    settings.cfApiToken = body.cfApiToken.trim();
  }

  await saveGlobalSettings(kv, settings);

  if (body.adminEmail || body.newPassword) {
    let admin = await getAdmin(kv);
    if (!admin) {
      if (body.newPassword && body.newPassword.length >= 12) {
        const hash = await hashAdminPassword(body.newPassword);
        admin = { email: (body.adminEmail || "admin@example.com").trim().toLowerCase(), hash };
        await saveAdmin(kv, admin);
      } else {
        return c.json({ error: "password_too_short" }, 400);
      }
    } else {
      if (body.adminEmail) {
        admin.email = body.adminEmail.trim().toLowerCase();
      }
      if (body.newPassword) {
        if (body.newPassword.length < 12) {
          return c.json({ error: "password_too_short" }, 400);
        }
        admin.hash = await hashAdminPassword(body.newPassword);
      }
      await saveAdmin(kv, admin);
    }
  }

  const updatedSettings = await getGlobalSettings(kv);
  const updatedAdmin = await getAdmin(kv);

  const envAccountId = c.env.CF_ANALYTICS_ACCOUNT_ID || c.env.CLOUDFLARE_ACCOUNT_ID || "";
  const envToken = c.env.CF_ANALYTICS_API_TOKEN || c.env.CLOUDFLARE_API_TOKEN || "";
  const effectiveAccountId = updatedSettings.cfAccountId || envAccountId;
  const effectiveToken = updatedSettings.cfApiToken || envToken;
  const hasToken = !!effectiveToken;
  const tokenSource = updatedSettings.cfApiToken ? "dashboard" : (envToken ? "env" : "none");

  return c.json({
    success: true,
    targetRestrict: updatedSettings.targetRestrict,
    appName: updatedSettings.appName || "Relay Gateway",
    logoUrl: updatedSettings.logoUrl || "",
    theme: updatedSettings.theme || "auto",
    adminEmail: updatedAdmin?.email || "",
    cfAccountId: effectiveAccountId,
    cfApiToken: effectiveToken,
    hasCfToken: hasToken,
    cfTokenSource: tokenSource,
  });
});

// --- Analytics API (Murni dihitung dari relay log) ---

app.get("/api/analytics", async (c) => {
  const kv = c.env.RELAY_KV;
  const recentLogs = await getRecentRelayLogs(kv);

  const totalRequests = recentLogs.length;
  const totalErrors = recentLogs.filter((l) => l.status >= 400).length;
  const successRate = totalRequests > 0
    ? (((totalRequests - totalErrors) / totalRequests) * 100).toFixed(1)
    : "100.0";
  const avgDurationMs = totalRequests > 0
    ? Math.round(recentLogs.reduce((acc, l) => acc + (l.durationMs || 0), 0) / totalRequests)
    : 0;

  // Bangun timeline 24 jam terakhir berdasarkan relay log
  const now = Date.now();
  const past24h = now - 24 * 3600 * 1000;
  const hourlyMap: Record<string, { requests: number; errors: number }> = {};

  for (let i = 23; i >= 0; i--) {
    const d = new Date(now - i * 3600 * 1000);
    d.setMinutes(0, 0, 0);
    hourlyMap[d.toISOString()] = { requests: 0, errors: 0 };
  }

  for (const l of recentLogs) {
    if (l.timestamp >= past24h) {
      const d = new Date(l.timestamp);
      d.setMinutes(0, 0, 0);
      const iso = d.toISOString();
      if (hourlyMap[iso]) {
        hourlyMap[iso].requests++;
        if (l.status >= 400) hourlyMap[iso].errors++;
      }
    }
  }

  const hourly = Object.entries(hourlyMap)
    .map(([hour, val]) => ({ hour, ...val }))
    .sort((a, b) => a.hour.localeCompare(b.hour));

  return c.json({
    configured: true,
    totalRequests,
    totalErrors,
    avgDurationMs,
    successRate,
    hourly,
    logs: recentLogs,
  });
});

app.delete("/api/analytics/logs", async (c) => {
  const kv = c.env.RELAY_KV;
  await clearRelayLogs(kv);
  return c.json({ success: true });
});

// --- Catch-All Relay Endpoints (Path / Query / Header formats) ---

// Semua endpoint relay: /relay, /relay_*, /key/*, /pass/*, /k/*, /p/*, atau POST /
app.all("/relay", handleRelay);
app.all("/relay/*", handleRelay);
app.all("/relay_*", handleRelay);
app.all("/key/*", handleRelay);
app.all("/k/*", handleRelay);
app.all("/pass/*", handleRelay);
app.all("/p/*", handleRelay);

// Fallback untuk route lain (misal client kirim ke POST /v1/... atau POST / dengan query/header)
app.all("*", async (c) => {
  const method = c.req.method.toUpperCase();
  const hasRelayHeaders =
    c.req.header("x-relay-target") ||
    c.req.header("x-relay-api-key") ||
    c.req.header("x-relay-password");
  const hasRelayQuery =
    c.req.query("key") ||
    c.req.query("api_key") ||
    c.req.query("password") ||
    c.req.query("pass") ||
    c.req.query("url");

  if (method !== "GET" || hasRelayHeaders || hasRelayQuery) {
    return handleRelay(c);
  }
  return c.redirect("/login");
});

export default app;
