# Cloudflare Relay Gateway

Gateway reverse proxy aman berbasis Cloudflare Workers, Hono, TypeScript, dan Cloudflare KV dengan dashboard admin terintegrasi untuk manajemen client, target whitelist, serta live request logs.

---

## Fitur Utama

- **Otentikasi Multi-Metode**:
  - IP Whitelist (IPv4 & IPv6).
  - API Key dengan format prefix aman (`relay_<prefix>...`).
  - Client Password dengan hash SHA-256.
  - Mode evaluasi fleksibel: **ANY** (salah satu lolos) atau **ALL** (semua kriteria wajib lolos).
- **Proteksi SSRF Ketat**:
  - Memblokir loopback (`127.0.0.1`, `::1`), private IP (RFC 1918), link-local, dan multicast.
  - Memblokir userinfo credential dalam URL (`user:pass@host`).
  - Wajib skema HTTPS untuk upstream.
- **Target Upstream Whitelist**:
  - Whitelist global host target.
  - Whitelist spesifik per client untuk isolasi akses API.
- **Format Relay Fleksibel**:
  - **Header**: `x-relay-target`, `x-relay-path`, `x-relay-api-key`, `x-relay-password`.
  - **Path Prefix**: `/<api_key>/<path>` atau `/p/<password>/<path>`.
  - **Query Parameter**: `?key=<api_key>` atau `?pass=<password>`.
- **Dashboard Admin Terintegrasi**:
  - Single-Page App (SPA) modern berbasis native HTML, CSS, dan vanilla JS tanpa dependensi bundle frontend berat.
  - Dukungan tema **System**, **Light**, dan **Dark** dengan ikon.
  - Kustomisasi Branding (Nama aplikasi, URL Logo, dan Favicon dinamis).
  - Mobile sticky header fixed dan navigasi bottom bar.
  - Generator kredensial otomatis (Generate API Key & Password sekali klik).
  - Action View khusus untuk copy format URL dan kredensial client.
- **Live Request Logs & Observability**:
  - Metrik statistik (Total Requests, Success Rate, Errors, Avg Latency) dihitung murni dari request relay aktual.
  - Grafik visual 24 jam responsif dengan auto-scroll di layar mobile.
  - Riwayat 100 request relay terakhir (Waktu, Client, Method, Target Host/Path, HTTP Status, Durasi).
  - Fitur hapus/reset log langsung dari dashboard.

---

## Struktur Proyek

```
.
├── src/
│   ├── index.ts           # Router Hono, handler relay, auth middleware & API endpoint
│   ├── dashboard.html     # Source UI dashboard SPA admin
│   ├── dashboard.ts       # HTML bundle untuk Cloudflare Worker
│   ├── types.ts           # Definisi interface TypeScript
│   ├── env.d.ts           # Type bindings Cloudflare Worker
│   └── lib/
│       ├── crypto.ts      # Kriptografi PBKDF2 (Admin) & SHA-256 (Client)
│       ├── kv.ts          # CRUD KV, indexing kredensial, & ring buffer log
│       └── ssrf.ts        # Validasi URL & pencegahan SSRF
├── scripts/
│   ├── setup-admin.mjs    # Script inisialisasi akun admin ke KV
│   ├── sync-dashboard.mjs # Sinkronisasi dashboard.html ke dashboard.ts
│   └── test-logic.mjs     # Test runner verifikasi logic otentikasi
├── wrangler.toml          # Konfigurasi Cloudflare Workers & KV binding
├── tsconfig.json          # Konfigurasi TypeScript
└── package.json
```

---

## Panduan Instalasi & Deploy

### 1. Clone & Install Dependensi

```bash
git clone https://github.com/assasakiy/Cloudflared-Relay.git
cd Cloudflared-Relay
npm install
```

### 2. Buat Cloudflare KV Namespace

```bash
npx wrangler kv namespace create RELAY_KV
```

Salin `id` KV yang dihasilkan ke dalam file `wrangler.toml`:

```toml
name = "cloudflare-relay"
main = "src/index.ts"
compatibility_date = "2026-06-01"

[observability]
enabled = true

[[kv_namespaces]]
binding = "RELAY_KV"
id = "<ID_KV_NAMESPACE_ANDA>"

[[rules]]
type = "Text"
globs = ["**/*.html"]
fallthrough = true
```

### 3. Setup Akun Admin Awal

Jalankan script untuk membuat kredensial admin awal di KV remote Cloudflare:

```bash
npm run setup-admin
```

> Kredensial default:
> - **Email**: `admin@example.com`
> - **Password**: `AdminSuperSecret123!`
> *(Segera ubah email dan password di menu **Settings > Akun Admin** setelah login pertama kali).*

### 4. Deploy ke Cloudflare Workers

```bash
npm run deploy
```

---

## Contoh Penggunaan Relay

### 1. Menggunakan Path Prefix (Rekomendasi)

Format: `https://<WORKER_DOMAIN>/<API_KEY>/<TARGET_PATH>`

```bash
curl -X GET "https://cloudflare-relay.yourdomain.workers.dev/relay_abcdef123456/v1/chat/completions" \
  -H "x-relay-target: https://api.openai.com" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}'
```

### 2. Menggunakan Header

```bash
curl -X POST "https://cloudflare-relay.yourdomain.workers.dev/relay" \
  -H "x-relay-target: https://api.openai.com" \
  -H "x-relay-path: /v1/chat/completions" \
  -H "x-relay-api-key: relay_abcdef123456" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}'
```

### 3. Menggunakan Client Password

```bash
curl -X GET "https://cloudflare-relay.yourdomain.workers.dev/p/MySecretPass123/get" \
  -H "x-relay-target: https://httpbin.org"
```

---

## Pengelolaan Dashboard

Buka URL Worker Anda di browser (misal: `https://<WORKER_DOMAIN>/dashboard`):
- **/dashboard/clients**: Tambah, edit, aktifkan/nonaktifkan, dan atur kredensial client.
- **/dashboard/targets**: Kelola daftar domain whitelist global yang diizinkan relay.
- **/dashboard/logs**: Pantau statistik performa, grafik 24 jam responsif, dan log riwayat request secara live.
- **/dashboard/settings**: Atur branding (nama & logo), batasan target, dan ganti kredensial login admin.

---

## Lisensi

Didistribusikan di bawah lisensi MIT.
