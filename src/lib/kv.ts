import type { Client, AdminRecord, GlobalSettings, SessionRecord } from "../types";
import { sha256Hex, timingSafeEqual } from "./crypto";

const KEY_ADMIN = "admin";
const KEY_CLIENTS = "clients";
const KEY_SETTINGS = "settings";
const KEY_TARGETS = "targets:global";
const KEY_LOGS = "logs:recent";
const PREFIX_CLIENT = "client:";
const PREFIX_SESSION = "session:";
const PREFIX_IDX_IP = "index:ip:";
const PREFIX_IDX_KEY = "index:key:";
const PREFIX_IDX_PASS = "index:pass:";

export interface RelayLogEntry {
  id: string;
  timestamp: number;
  clientId: string;
  clientName: string;
  method: string;
  targetHost: string;
  targetPath: string;
  status: number;
  durationMs: number;
  ip: string;
}

// --- Admin & Session ---

export async function getAdmin(kv: KVNamespace): Promise<AdminRecord | null> {
  return await kv.get<AdminRecord>(KEY_ADMIN, "json");
}

export async function saveAdmin(kv: KVNamespace, admin: AdminRecord): Promise<void> {
  await kv.put(KEY_ADMIN, JSON.stringify(admin));
}

export async function createSession(kv: KVNamespace, token: string, email: string): Promise<void> {
  const session: SessionRecord = { email, createdAt: Date.now() };
  await kv.put(PREFIX_SESSION + token, JSON.stringify(session), { expirationTtl: 604800 });
}

export async function getSession(kv: KVNamespace, token: string): Promise<SessionRecord | null> {
  return await kv.get<SessionRecord>(PREFIX_SESSION + token, "json");
}

export async function deleteSession(kv: KVNamespace, token: string): Promise<void> {
  await kv.delete(PREFIX_SESSION + token);
}

// --- Global Settings & Targets ---

export async function getGlobalSettings(kv: KVNamespace): Promise<GlobalSettings> {
  const settings = await kv.get<GlobalSettings>(KEY_SETTINGS, "json");
  return settings || { targetRestrict: false };
}

export async function saveGlobalSettings(kv: KVNamespace, settings: GlobalSettings): Promise<void> {
  await kv.put(KEY_SETTINGS, JSON.stringify(settings));
}

export async function getGlobalTargets(kv: KVNamespace): Promise<string[]> {
  const targets = await kv.get<string[]>(KEY_TARGETS, "json");
  return targets || [];
}

export async function saveGlobalTargets(kv: KVNamespace, targets: string[]): Promise<void> {
  await kv.put(KEY_TARGETS, JSON.stringify(targets));
}

// --- Client Management ---

export async function listClientIds(kv: KVNamespace): Promise<string[]> {
  const ids = await kv.get<string[]>(KEY_CLIENTS, "json");
  return ids || [];
}

export async function getClient(kv: KVNamespace, id: string): Promise<Client | null> {
  return await kv.get<Client>(PREFIX_CLIENT + id, "json");
}

export async function listAllClients(kv: KVNamespace): Promise<Client[]> {
  const ids = await listClientIds(kv);
  if (ids.length === 0) return [];
  const clients: Client[] = [];
  for (const id of ids) {
    const c = await getClient(kv, id);
    if (c) clients.push(c);
  }
  return clients;
}

export async function saveClient(kv: KVNamespace, client: Client): Promise<void> {
  const old = await getClient(kv, client.id);

  if (old) {
    for (const ip of old.ips) {
      await kv.delete(PREFIX_IDX_IP + ip);
    }
    for (const key of old.keys) {
      await kv.delete(PREFIX_IDX_KEY + key.hash);
    }
    if (old.passHash) {
      await kv.delete(PREFIX_IDX_PASS + old.passHash);
    }
  }

  for (const ip of client.ips) {
    const cleanIp = ip.trim();
    if (cleanIp) {
      await kv.put(PREFIX_IDX_IP + cleanIp, client.id);
    }
  }
  for (const key of client.keys) {
    if (key.status === "active") {
      await kv.put(PREFIX_IDX_KEY + key.hash, client.id);
    }
  }
  if (client.passHash) {
    await kv.put(PREFIX_IDX_PASS + client.passHash, client.id);
  }

  await kv.put(PREFIX_CLIENT + client.id, JSON.stringify(client));

  const ids = await listClientIds(kv);
  if (!ids.includes(client.id)) {
    ids.push(client.id);
    await kv.put(KEY_CLIENTS, JSON.stringify(ids));
  }
}

export async function deleteClient(kv: KVNamespace, id: string): Promise<boolean> {
  const old = await getClient(kv, id);
  if (!old) return false;

  for (const ip of old.ips) {
    await kv.delete(PREFIX_IDX_IP + ip);
  }
  for (const key of old.keys) {
    await kv.delete(PREFIX_IDX_KEY + key.hash);
  }
  if (old.passHash) {
    await kv.delete(PREFIX_IDX_PASS + old.passHash);
  }

  await kv.delete(PREFIX_CLIENT + id);

  const ids = await listClientIds(kv);
  const updatedIds = ids.filter((x) => x !== id);
  await kv.put(KEY_CLIENTS, JSON.stringify(updatedIds));
  return true;
}

// --- Relay Auth Lookup & Verification ---

export interface ClientCredentials {
  apiKey?: string;
  password?: string;
  clientIp?: string;
}

export async function findAndAuthenticateClient(
  kv: KVNamespace,
  creds: ClientCredentials
): Promise<{ client: Client; reason?: string } | { client: null; reason: string }> {
  let clientId: string | null = null;
  let keyHash: string | null = null;
  let passHash: string | null = null;

  if (creds.apiKey) {
    keyHash = await sha256Hex(creds.apiKey);
    clientId = await kv.get(PREFIX_IDX_KEY + keyHash);
  }

  if (!clientId && creds.password) {
    passHash = await sha256Hex(creds.password);
    clientId = await kv.get(PREFIX_IDX_PASS + passHash);
  }

  if (!clientId && creds.clientIp) {
    clientId = await kv.get(PREFIX_IDX_IP + creds.clientIp);
  }

  if (!clientId) {
    return { client: null, reason: "client_not_found" };
  }

  const client = await getClient(kv, clientId);
  if (!client) {
    return { client: null, reason: "client_not_found" };
  }

  if (!client.status) {
    return { client: null, reason: "client_disabled" };
  }

  const hasIp = client.ips.length > 0;
  const hasPass = !!client.passHash;
  const hasKey = client.keys.some((k) => k.status === "active");

  if (!hasIp && !hasPass && !hasKey) {
    return { client: null, reason: "no_auth_configured" };
  }

  const ipValid = hasIp && !!creds.clientIp && client.ips.includes(creds.clientIp);

  if (!passHash && creds.password) {
    passHash = await sha256Hex(creds.password);
  }
  const passValid = hasPass && !!passHash && timingSafeEqual(client.passHash!, passHash);

  if (!keyHash && creds.apiKey) {
    keyHash = await sha256Hex(creds.apiKey);
  }
  const keyValid =
    hasKey &&
    !!keyHash &&
    client.keys.some((k) => k.status === "active" && timingSafeEqual(k.hash, keyHash!));

  if (client.logic === "ALL") {
    if (hasIp && !ipValid) return { client: null, reason: "ip_failed" };
    if (hasPass && !passValid) return { client: null, reason: "password_failed" };
    if (hasKey && !keyValid) return { client: null, reason: "key_failed" };
    return { client };
  } else {
    if (ipValid || passValid || keyValid) {
      return { client };
    }
    return { client: null, reason: "all_methods_failed" };
  }
}

// --- Relay Ring Buffer Logs (Max 100 entri metadata tanpa log body/credentials) ---

export async function appendRelayLog(kv: KVNamespace, entry: RelayLogEntry): Promise<void> {
  try {
    const logs = (await kv.get<RelayLogEntry[]>(KEY_LOGS, "json")) || [];
    logs.unshift(entry);
    if (logs.length > 100) logs.length = 100; // Jaga maksimal 100 log terakhir
    await kv.put(KEY_LOGS, JSON.stringify(logs));
  } catch {}
}

export async function getRecentRelayLogs(kv: KVNamespace): Promise<RelayLogEntry[]> {
  const logs = await kv.get<RelayLogEntry[]>(KEY_LOGS, "json");
  return logs || [];
}

export async function clearRelayLogs(kv: KVNamespace): Promise<void> {
  await kv.delete(KEY_LOGS);
}
