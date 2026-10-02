function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return false;
  }
  const [a, b] = parts;
  // 0.0.0.0/8
  if (a === 0) return true;
  // 10.0.0.0/8
  if (a === 10) return true;
  // 127.0.0.0/8
  if (a === 127) return true;
  // 169.254.0.0/16 (Link Local / Cloud Metadata 169.254.169.254)
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12 (172.16 - 172.31)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16
  if (a === 192 && b === 168) return true;
  // 100.64.0.0/10 (CGNAT)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // Multicast & Reserved (224.0.0.0+)
  if (a >= 224) return true;
  return false;
}

function isPrivateIPv6(host: string): boolean {
  const clean = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (clean === "::1" || clean === "::") return true;
  if (clean.startsWith("fe8") || clean.startsWith("fe9") || clean.startsWith("fea") || clean.startsWith("feb")) return true; // link-local
  if (clean.startsWith("fc") || clean.startsWith("fd")) return true; // ULA
  if (clean.startsWith("::ffff:")) {
    const v4 = clean.replace("::ffff:", "");
    if (isPrivateIPv4(v4)) return true;
  }
  return false;
}

export interface ValidatedTarget {
  url: URL;
  hostname: string;
}

export function validateTargetUrl(rawUrl: string): { valid: true; target: ValidatedTarget } | { valid: false; reason: string } {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { valid: false, reason: "invalid_url_format" };
  }

  // Hanya https diizinkan
  if (url.protocol !== "https:") {
    return { valid: false, reason: "protocol_not_allowed" };
  }

  // Tolak credential di URL (user:pass@host)
  if (url.username || url.password) {
    return { valid: false, reason: "credentials_in_url" };
  }

  const hostname = url.hostname.toLowerCase();
  if (!hostname) {
    return { valid: false, reason: "empty_hostname" };
  }

  // Blokir nama host internal
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    return { valid: false, reason: "private_host_blocked" };
  }

  // Cek IP privat
  const isIpv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  if (isIpv4 && isPrivateIPv4(hostname)) {
    return { valid: false, reason: "private_ip_blocked" };
  }

  const isIpv6 = hostname.includes(":") || (hostname.startsWith("[") && hostname.endsWith("]"));
  if (isIpv6 && isPrivateIPv6(hostname)) {
    return { valid: false, reason: "private_ip_blocked" };
  }

  return { valid: true, target: { url, hostname } };
}

export function isTargetAllowed(hostname: string, allowedList: string[]): boolean {
  const normHost = hostname.toLowerCase();
  for (const entry of allowedList) {
    const normEntry = entry.trim().toLowerCase();
    if (!normEntry) continue;
    // Exact hostname match
    if (normHost === normEntry) return true;
    // Wildcard subdomain support: *.example.com matches sub.example.com
    if (normEntry.startsWith("*.") && normHost.endsWith(normEntry.slice(1))) {
      return true;
    }
  }
  return false;
}
