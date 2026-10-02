export type AuthLogic = "ANY" | "ALL";

export interface ApiKeyRecord {
  id: string;
  name: string;
  key?: string;
  prefix: string;
  hash: string;
  status: "active" | "revoked";
  createdAt: number;
  lastUsedAt?: number;
}

export interface Client {
  id: string;
  name: string;
  status: boolean;
  logic: AuthLogic;
  ips: string[];
  pass?: string | null;
  passHash: string | null;
  keys: ApiKeyRecord[];
  restrict: boolean;
  targets: string[];
  createdAt: number;
  updatedAt: number;
}

export interface AdminRecord {
  email: string;
  hash: string;
}

export interface SessionRecord {
  email: string;
  createdAt: number;
}

export interface GlobalSettings {
  targetRestrict: boolean;
  appName?: string;
  logoUrl?: string;
  theme?: "auto" | "light" | "dark";
}

export interface Bindings {
  RELAY_KV: KVNamespace;
  ADMIN_INITIAL_EMAIL?: string;
  ADMIN_INITIAL_PASSWORD?: string;
  SESSION_SECRET?: string;
  CLOUDFLARE_ACCOUNT_ID?: string;
  CLOUDFLARE_API_TOKEN?: string;
  CF_ANALYTICS_ACCOUNT_ID?: string;
  CF_ANALYTICS_API_TOKEN?: string;
}
