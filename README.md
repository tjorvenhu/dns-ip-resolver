> ⚠️ **Note:** This project was created with Codex for testing purposes.

# 🔎 Port Tester / DNS-IP Resolver

An all-in-one web app for **IPv4/domain analysis**, **GeoIP**, **WHOIS**, **reputation checks**, and **staged port scanning (up to 6500)**.

---

## Highlights

- **GeoIP (local-first, no external GeoIP APIs required)**
  - `geoip-lite`
  - `maxmind` (MMDB reader)
  - `@maxmind/geoip2-node` (MMDB reader)
  - ASN enrichment via `@ip-location-db/geolite2-asn-mmdb` for ISP/ASN quality
- **WHOIS + domain context** (parsed fields + raw preview)
- **Reputation checks** (`dnsbl`, `privacy`, `community`, `crowdsec`)
- **Two-stage port scan**
  - Stage 1: selected known ports
  - Stage 2: remaining ports up to `6500`
- **Server-side scan history** with share links and JSON download per entry
- **Debug panel** with provider status and rate-limit hints
- **Multi-language UI**: German, English, Dutch, French
- **Encrypted config storage** (`AES-256-GCM` + `scrypt`)

---

## Tech Stack

- **Backend:** Node.js + Express
- **Frontend:** Vanilla HTML/CSS/JS
- **Geo/Net libs:** `geoip-lite`, `maxmind`, `@maxmind/geoip2-node`, `whois`

---

## Local Setup

### 1) Requirements

- Node.js 18+ (24 recommended)
- npm

### 2) Install

```bash
npm install
```

### 3) Required env var

`RESOLVER_PASSWORD` is mandatory.

PowerShell example:

```powershell
$env:RESOLVER_PASSWORD="your-secure-password"
npm start
```

Open: `http://localhost:3000`

---

## GeoIP / MMDB Notes

The app auto-detects MMDB files from:

- `data/GeoLite2-City.mmdb`
- `GeoLite2-City.mmdb` in project root
- `GEOIP_MMDB_PATH`
- package files from `@ip-location-db/geolite2-city-mmdb`
- package files from `@ip-location-db/geolite2-asn-mmdb`

Target paths for auto-copy can be controlled by env vars:

- `GEOIP_MMDB_PATH` or `GEOIP_CITY_MMDB_PATH` (city DB target)
- `GEOIP_ASN_MMDB_PATH` (ASN DB target)

The `postinstall` script (`scripts/setup-mmdb.js`) copies both MMDBs automatically when available:

- `data/GeoLite2-City.mmdb`
- `data/GeoLite2-ASN.mmdb`

If MMDB readers are unavailable, the app gracefully falls back to `geoip-lite`.

The MMDB files are derived from MaxMind GeoLite2 and are **not** committed to this
repository (they ship with the npm packages above and are copied locally on install).
Please respect the [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) before
redistributing them.

---

## Configuration

Via in-app config panel:

- site title
- history retention limit
- remaining-scan speed (ports/sec)
- enabled GeoIP providers
- enabled reputation providers
- optional site access password
- logo + favicon upload

Encrypted config file:

- `data/site-config.enc`

---

## Debug Panel

The debug run tests GeoIP/WHOIS/Reputation providers and surfaces reasons like:

- `rate_limited`
- `http_429`
- `request_failed`
- `disabled_in_config`

Useful for validating provider behavior after config changes.

---

## Docker Compose

Use the included `docker-compose.yml`.

### 1) Create `.env`

Copy `.env.example` to `.env` and set your own password:

```env
RESOLVER_PASSWORD=your-secure-password
```

### 2) Start

```bash
docker compose up --build
```

Compose includes:

- Node `24-alpine`
- `RESOLVER_PASSWORD` injected from `.env` (never hardcode it in the compose file)
- a bind mount for `/app` so `data/` and `public/history/` persist on the host

---

## Project Structure

- `server.js` - API, scan engine, provider logic
- `public/index.html` - UI layout
- `public/app.js` - frontend logic, state, i18n
- `public/styles.css` - styling + responsive behavior
- `public/locales/` - `de`, `en`, `nl`, `fr`
- `public/history/` - persisted scan records (gitignored)
- `data/` - encrypted config + runtime assets (gitignored)
- `scripts/setup-mmdb.js` - MMDB bootstrap

---

## ⚠️ Legal

Only scan systems you own or are explicitly authorized to test.
