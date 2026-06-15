const express = require("express");
const path = require("path");
const net = require("net");
const fs = require("fs");
const crypto = require("crypto");
const tls = require("tls");
const dns = require("dns").promises;
const geoip = require("geoip-lite");
const maxmind = safeRequire("maxmind");
const geoip2Node = safeRequire("@maxmind/geoip2-node");
const countryToCurrency = require("country-to-currency");
const whois = require("whois");
const Sqlite = null;

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_SCAN_PORT = 6500;
const HISTORY_DIR = path.join(__dirname, "public", "history");
const DEFAULT_HISTORY_MAX_ENTRIES = 10;
const HISTORY_MAX_AGE_MS = 14 * 24 * 60 * 60 * 1000;
const CONFIG_DIR = path.join(__dirname, "data");
const CONFIG_FILE = path.join(CONFIG_DIR, "site-config.enc");
const IMAGES_DIR = path.join(CONFIG_DIR, "images");
const LOGO_FILE = path.join(IMAGES_DIR, "logo.png");
const FAVICON_FILE = path.join(IMAGES_DIR, "favicon.png");
const LOCALES_DIR = path.join(__dirname, "public", "locales");
const RESOLVER_PASSWORD = String(process.env.RESOLVER_PASSWORD || "").trim();
const ACCESS_COOKIE_NAME = "resolver_access";
const CACHE_TTL_DOMAIN_INTEL_MS = 2 * 60 * 1000;
const CACHE_TTL_SUBDOMAIN_INTEL_MS = 20 * 60 * 1000;
const CACHE_TTL_HTTP_MS = 15 * 60 * 1000;
const CACHE_TTL_ANALYZE_MS = 3 * 60 * 1000;
const CACHE_TTL_WHOIS_MS = 20 * 60 * 1000;
const CACHE_TTL_REPUTATION_MS = 5 * 60 * 1000;
const LOCAL_GEO_SOURCES = ["geoiplite", "maxmind", "geoip2node"];
const GEOIP_CITY_MMDB_CANDIDATE_FILES = [
  String(process.env.GEOIP_MMDB_PATH || process.env.GEOIP_CITY_MMDB_PATH || "").trim(),
  path.join(__dirname, "data", "GeoLite2-City.mmdb"),
  path.join(__dirname, "GeoLite2-City.mmdb"),
  safeResolvePackageFile("@ip-location-db/geolite2-city-mmdb/geolite2-city-ipv4.mmdb"),
  safeResolvePackageFile("@ip-location-db/geolite2-city-mmdb/geolite2-city-ipv6.mmdb"),
].filter(Boolean);
const GEOIP_ASN_MMDB_CANDIDATE_FILES = [
  String(process.env.GEOIP_ASN_MMDB_PATH || "").trim(),
  path.join(__dirname, "data", "GeoLite2-ASN.mmdb"),
  path.join(__dirname, "GeoLite2-ASN.mmdb"),
  safeResolvePackageFile("@ip-location-db/geolite2-asn-mmdb/geolite2-asn-ipv4.mmdb"),
  safeResolvePackageFile("@ip-location-db/geolite2-asn-mmdb/geolite2-asn-ipv6.mmdb"),
].filter(Boolean);
const domainIntelCache = new Map();
const subdomainIntelCache = new Map();
const httpTextCache = new Map();
const analyzeCache = new Map();
const whoisCache = new Map();
const reputationCache = new Map();
let resolvedGeoCityMmdbPath = undefined;
let resolvedGeoAsnMmdbPath = undefined;
let maxmindCityReaderPromise = null;
let maxmindAsnReaderPromise = null;
let geoip2CityReaderPromise = null;
const dbState = initObservationStore();
const COUNTRY_NAMES = safeDisplayNames("region");
const CURRENCY_NAMES = safeDisplayNames("currency");

const CONTINENT_NAMES = {
  AF: "Afrika",
  AN: "Antarktis",
  AS: "Asien",
  EU: "Europa",
  NA: "Nordamerika",
  OC: "Ozeanien",
  SA: "Südamerika",
};

const COUNTRY_CALLING_CODES = {
  DE: "+49", FR: "+33", NL: "+31", BE: "+32", AT: "+43", CH: "+41", IT: "+39", ES: "+34", PT: "+351",
  PL: "+48", CZ: "+420", SK: "+421", HU: "+36", RO: "+40", BG: "+359", HR: "+385", SI: "+386", RS: "+381",
  GB: "+44", IE: "+353", NO: "+47", SE: "+46", FI: "+358", DK: "+45", IS: "+354",
  US: "+1", CA: "+1", MX: "+52", BR: "+55", AR: "+54", CL: "+56", CO: "+57", PE: "+51",
  RU: "+7", UA: "+380", TR: "+90", IL: "+972", AE: "+971", SA: "+966", IN: "+91", PK: "+92",
  CN: "+86", JP: "+81", KR: "+82", SG: "+65", MY: "+60", TH: "+66", VN: "+84", ID: "+62", PH: "+63",
  AU: "+61", NZ: "+64", ZA: "+27", EG: "+20", MA: "+212", TN: "+216", DZ: "+213", NG: "+234",
};

const KNOWN_PORTS = [
  20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
  143, 161, 389, 443, 445, 465, 587, 993, 995, 1433, 1521, 1723, 1883, 2049,
  2375, 3000, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
];

const PORT_LABELS = {
  20: "FTP Data",
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  67: "DHCP Server",
  68: "DHCP Client",
  69: "TFTP",
  80: "HTTP",
  110: "POP3",
  111: "RPC",
  123: "NTP",
  135: "MS RPC",
  137: "NetBIOS NS",
  138: "NetBIOS DGM",
  139: "NetBIOS SSN",
  143: "IMAP",
  161: "SNMP",
  389: "LDAP",
  443: "HTTPS",
  445: "SMB",
  465: "SMTPS",
  587: "SMTP Submission",
  993: "IMAPS",
  995: "POP3S",
  1433: "MSSQL",
  1521: "Oracle DB",
  1723: "PPTP",
  1883: "MQTT",
  2049: "NFS",
  2375: "Docker",
  3000: "Node Dev",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  5900: "VNC",
  6379: "Redis",
  8080: "HTTP Alt",
  8443: "HTTPS Alt",
};

app.use(express.json({ limit: "5mb" }));

app.use((req, res, next) => {
  if (RESOLVER_PASSWORD) {
    return next();
  }

  if (req.path === "/api/config/status") {
    return next();
  }

  if (req.path.startsWith("/api")) {
    return res.status(503).json({ error: "RESOLVER_PASSWORD ist nicht gesetzt." });
  }

  return res.status(503).send(`<!doctype html><html lang="de"><head><meta charset="utf-8"/><title>Konfiguration fehlt</title><meta name="viewport" content="width=device-width,initial-scale=1"/></head><body style="font-family:Segoe UI,sans-serif;background:#101317;color:#f4d29a;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;"><div style="max-width:700px;padding:20px;border:1px solid #f2bb6b66;border-radius:12px;background:#3b2a11a6;"><h1 style="margin:0 0 12px;">Konfiguration fehlt</h1><p style="margin:0;line-height:1.5;">Die Umgebungsvariable <code>RESOLVER_PASSWORD</code> ist nicht gesetzt. Bitte setze sie in Docker und starte den Service neu.</p></div></body></html>`);
});

app.use(async (req, res, next) => {
  if (req.path === "/api/config/status" || req.path.startsWith("/api/auth/")) {
    return next();
  }

  const config = await readSiteConfig();
  const accessPassword = String(config?.accessPassword || "").trim();
  if (!accessPassword) {
    return next();
  }

  const cookieValue = parseCookies(req.headers.cookie || "")[ACCESS_COOKIE_NAME] || "";
  if (cookieValue && cookieValue === buildAccessCookieValue(accessPassword)) {
    return next();
  }

  if (req.path.startsWith("/api")) {
    return res.status(401).json({ error: "Site password required." });
  }

  return res.status(401).send(`<!doctype html><html lang="de"><head><meta charset="utf-8"/><title>Zugriff geschützt</title><meta name="viewport" content="width=device-width,initial-scale=1"/></head><body style="font-family:Segoe UI,sans-serif;background:#141012;color:#ffd1d1;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;"><div style="max-width:520px;width:calc(100% - 28px);padding:20px;border:1px solid #ef7d7d66;border-radius:12px;background:#3a1616b0;"><h1 style="margin:0 0 12px;color:#ffdede;">Passwort erforderlich</h1><p style="margin:0 0 12px;line-height:1.5;color:#ffc8c8;">Diese Seite ist geschützt. Bitte Passwort eingeben.</p><div style="display:flex;gap:8px;"><input id="site-pwd" type="password" placeholder="Passwort" style="flex:1;border:1px solid #e08f8f66;border-radius:8px;background:#261212;color:#ffe1e1;padding:10px 12px;" /><button id="site-unlock" style="border:0;border-radius:8px;background:#8f2f2f;color:#ffe6e6;padding:10px 14px;cursor:pointer;">Öffnen</button></div><p id="site-msg" style="min-height:18px;color:#ffb3b3;font-size:13px;"></p></div><script>document.getElementById('site-unlock').addEventListener('click',async()=>{const p=document.getElementById('site-pwd').value;const r=await fetch('/api/auth/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});if(r.ok){location.reload();return;}document.getElementById('site-msg').textContent='Passwort ungültig.';});</script></body></html>`);
});
app.use(express.static(path.join(__dirname, "public")));

app.get("/logo.png", async (req, res) => {
  return sendConfiguredImage(res, LOGO_FILE);
});

app.get("/favicon.png", async (req, res) => {
  return sendConfiguredImage(res, FAVICON_FILE);
});

app.get("/favicon.ico", async (req, res) => {
  return sendConfiguredImage(res, FAVICON_FILE);
});

app.post("/api/analyze", async (req, res) => {
  const targetRaw = (req.body?.target || "").trim();

  if (!targetRaw) {
    return res.status(400).json({ error: "Bitte eine IPv4-Adresse oder Domain angeben." });
  }

  const cacheKey = `analyze:${normalizeDomain(targetRaw)}`;
  const cachedAnalyze = getCached(analyzeCache, cacheKey);
  if (cachedAnalyze) {
    return res.json({ ...cachedAnalyze, cached: true });
  }

  try {
    let targetType = "ip";
    let domain = null;
    let resolvedIps = [];
    let ip = targetRaw;

    if (isValidIPv4(targetRaw)) {
      ip = targetRaw;
    } else if (isValidDomain(targetRaw)) {
      targetType = "domain";
      domain = normalizeDomain(targetRaw);
      resolvedIps = await dns.resolve4(domain);

      if (!resolvedIps.length) {
        return res.status(400).json({ error: "Keine IPv4-Adresse für diese Domain gefunden." });
      }

      ip = resolvedIps[0];
    } else {
      return res.status(400).json({ error: "Ungültiges Format. Bitte IPv4 oder Domain eingeben." });
    }

    let whoisData = null;
    let domainIntel = null;
    if (targetType === "domain") {
      try {
        const rawWhois = await lookupWhoisCached(domain);
        whoisData = parseWhois(rawWhois, domain);
      } catch (error) {
        whoisData = {
          source: `https://www.whois.com/whois/${domain}`,
          error: "WHOIS konnte nicht vollständig geladen werden.",
        };
      }

      domainIntel = await collectDomainIntel(domain);
    }

    const payload = {
      input: targetRaw,
      targetType,
      domain,
      resolvedIps,
      ip,
      knownPorts: KNOWN_PORTS.map((port) => ({
        port,
        service: PORT_LABELS[port] || "Unbekannt",
      })),
      whois: whoisData,
      domainIntel,
      cached: false,
    };

    setCached(analyzeCache, cacheKey, payload, CACHE_TTL_ANALYZE_MS);
    return res.json(payload);
  } catch (error) {
    if (error?.code === "ENOTFOUND" || error?.code === "ENODATA") {
      return res.status(400).json({ error: "Domain konnte nicht aufgelöst werden." });
    }
    return res.status(500).json({ error: "Interner Fehler bei der Analyse." });
  }
});

app.post("/api/geoip", async (req, res) => {
  const { ip, source } = req.body || {};

  if (!isValidIPv4(ip)) {
    return res.status(400).json({ error: "Bitte eine gültige IPv4-Adresse angeben." });
  }

  const selectedSource = normalizeGeoSource(source);

  try {
    const allowedSources = await getConfiguredGeoSources();
    const attempts = [];
    const preferredSource = allowedSources.includes(selectedSource) ? selectedSource : allowedSources[0] || LOCAL_GEO_SOURCES[0];
    const sourceOrder = [preferredSource, ...allowedSources.filter((s) => s !== preferredSource)];

    let usedSource = preferredSource;
    let geo = null;
    for (const sourceName of sourceOrder) {
      const result = await getGeoBySourceWithMeta(ip, sourceName);
      attempts.push({ source: sourceName, ok: Boolean(result.geo), reason: result.reason || null });
      if (result.geo) {
        geo = result.geo;
        usedSource = sourceName;
        break;
      }
    }
    if (!geo) {
      return res.status(404).json({ error: "Für dieses Ziel wurden keine GeoIP-Daten gefunden." });
    }

    geo = await enrichGeoProviderInfo(ip, geo);

    return res.json({
      source: usedSource,
      requestedSource: selectedSource,
      fallbackUsed: usedSource !== selectedSource,
      geo,
      attempts,
    });
  } catch (error) {
    return res.status(500).json({ error: "GeoIP-Abfrage fehlgeschlagen." });
  }
});

app.post("/api/reputation", async (req, res) => {
  const ip = String(req.body?.ip || "").trim();
  const domain = req.body?.domain ? normalizeDomain(req.body.domain) : null;
  const requestedSource = String(req.body?.source || "community").toLowerCase();

  if (!isValidIPv4(ip)) {
    return res.status(400).json({ error: "Bitte eine gültige IPv4-Adresse angeben." });
  }

  const allowedReputationSources = await getConfiguredReputationSources();
  let mode = normalizeReputationMode(requestedSource);
  if (!allowedReputationSources.includes(mode)) {
    mode = allowedReputationSources[0] || "community";
  }

  const hasCrowdSec = await hasCrowdSecApiKey();
  const cacheKey = `rep:${ip}:${mode}:crowdsec:${hasCrowdSec ? 1 : 0}`;
  const cached = getCached(reputationCache, cacheKey);
  if (cached) {
    return res.json({ ...cached, cached: true });
  }

  try {
    const report = await buildReputationReport(ip, domain, mode);
    setCached(reputationCache, cacheKey, report, CACHE_TTL_REPUTATION_MS);
    return res.json({ ...report, cached: false });
  } catch (error) {
    return res.status(500).json({ error: "Reputation-Prüfung fehlgeschlagen." });
  }
});

app.post("/api/subdomain/resolve", async (req, res) => {
  const subdomain = normalizeDomain(req.body?.subdomain || "");
  const rootDomain = normalizeDomain(req.body?.rootDomain || "");

  if (!isValidDomain(subdomain) || !isValidDomain(rootDomain)) {
    return res.status(400).json({ error: "Bitte eine gültige Domain/Subdomain angeben." });
  }

  if (!isSubdomainOf(subdomain, rootDomain)) {
    return res.status(400).json({ error: "Subdomain gehört nicht zur ausgewählten Domain." });
  }

  try {
    const intel = await getSubdomainIntel(subdomain, { forceFresh: true });

    return res.json({
      subdomain,
      records: intel.records,
      tls: intel.tls,
      history: intel.history,
      risk: intel.risk,
      ipv4History: intel.ipv4History,
    });
  } catch (error) {
    return res.status(500).json({ error: "Subdomain-Auflösung fehlgeschlagen." });
  }
});

app.post("/api/scan/start", async (req, res) => {
  const { ip, ports } = req.body || {};

  if (!isValidIPv4(ip)) {
    return res.status(400).json({ error: "Bitte eine gültige IPv4-Adresse angeben." });
  }

  const selectedKnownPorts = normalizeRequestedKnownPorts(ports);
  if (!selectedKnownPorts.length) {
    return res.status(400).json({ error: "Bitte mindestens einen bekannten Port für den Scan auswählen." });
  }

  try {
    const openPorts = await scanPorts(ip, selectedKnownPorts, { timeoutMs: 360, concurrency: 180 });

    return res.json({
      ip,
      phase: "known",
      scanned: selectedKnownPorts.length,
      totalPlanned: MAX_SCAN_PORT,
      openPorts,
      remainingPorts: MAX_SCAN_PORT - selectedKnownPorts.length,
      selectedKnownPorts,
      knownPorts: KNOWN_PORTS,
    });
  } catch (error) {
    return res.status(500).json({ error: "Portscan der bekannten Ports fehlgeschlagen." });
  }
});

app.post("/api/scan/continue", async (req, res) => {
  const { ip, skipPorts, ports } = req.body || {};

  if (!isValidIPv4(ip)) {
    return res.status(400).json({ error: "Bitte eine gültige IPv4-Adresse angeben." });
  }

  const normalizedSkip = normalizePortList(skipPorts, MAX_SCAN_PORT);
  const explicitScanList = normalizePortList(ports, MAX_SCAN_PORT);
  const skipSet = new Set(normalizedSkip);
  const allPorts = Array.from({ length: MAX_SCAN_PORT }, (_, idx) => idx + 1);
  const remaining = explicitScanList.length ? explicitScanList : allPorts.filter((port) => !skipSet.has(port));
  const restPortsPerSecond = await getConfiguredRestPortsPerSecond();
  const paceMs = Math.max(1, Math.floor(1000 / Math.max(1, restPortsPerSecond)));
  let aborted = false;

  req.on("aborted", () => {
    aborted = true;
  });
  res.on("close", () => {
    if (!res.writableEnded) {
      aborted = true;
    }
  });

  try {
    const openPorts = [];

    for (const port of remaining) {
      if (aborted) {
        return;
      }

      const startedAt = Date.now();
      const result = await scanSinglePort(ip, port, 420);
      if (result) {
        openPorts.push(result);
      }

      const elapsed = Date.now() - startedAt;
      if (elapsed < paceMs) {
        await sleep(paceMs - elapsed);
      }
    }

    return res.json({
      ip,
      phase: "full",
      scanned: remaining.length,
      scannedPorts: remaining,
      totalPlanned: MAX_SCAN_PORT,
      openPorts,
      remainingPorts: 0,
    });
  } catch (error) {
    return res.status(500).json({ error: "Vollständiger Portscan fehlgeschlagen." });
  }
});

app.post("/api/scan/port", async (req, res) => {
  const { ip, port } = req.body || {};
  const parsedPort = Number(port);

  if (!isValidIPv4(ip)) {
    return res.status(400).json({ error: "Bitte eine gültige IPv4-Adresse angeben." });
  }

  if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
    return res.status(400).json({ error: "Bitte einen gültigen Port zwischen 1 und 65535 angeben." });
  }

  try {
    const result = await scanSinglePort(ip, parsedPort, 600);
    return res.json({
      ip,
      port: parsedPort,
      open: Boolean(result),
      service: PORT_LABELS[parsedPort] || "Unbekannt",
    });
  } catch (error) {
    return res.status(500).json({ error: "Einzelport-Prüfung fehlgeschlagen." });
  }
});

app.get("/api/history", async (req, res) => {
  try {
    const items = await readHistoryStore();
    return res.json({ items });
  } catch (error) {
    return res.status(500).json({ error: "Historie konnte nicht geladen werden." });
  }
});

app.post("/api/history", async (req, res) => {
  const incoming = req.body?.items;
  if (!Array.isArray(incoming)) {
    return res.status(400).json({ error: "Ungültige Historie." });
  }

  try {
    const limit = await getConfiguredHistoryLimit();
    const items = normalizeHistoryItems(incoming, limit);
    await writeHistoryStore(items);
    return res.json({ ok: true, count: items.length });
  } catch (error) {
    return res.status(500).json({ error: "Historie konnte nicht gespeichert werden." });
  }
});

app.get("/api/config/status", async (req, res) => {
  if (!RESOLVER_PASSWORD) {
    return res.json({ ok: false, missingResolverPassword: true });
  }
  return res.json({ ok: true, missingResolverPassword: false });
});

app.get("/api/config/public", async (req, res) => {
  try {
    const config = await readSiteConfig();
    const logoExists = fs.existsSync(LOGO_FILE);
    const faviconExists = fs.existsSync(FAVICON_FILE);
    const historyMaxEntries = await getConfiguredHistoryLimit();
    const restPortsPerSecond = await getConfiguredRestPortsPerSecond();
    const allowedGeoSources = await getConfiguredGeoSources();
    const allowedReputationSources = await getConfiguredReputationSources();
    return res.json({
      title: config.title || "DNS / IP-Resolver",
      logoDataUrl: logoExists ? `/logo.png?v=${encodeURIComponent(config.updatedAt || "1")}` : null,
      faviconDataUrl: faviconExists ? `/favicon.png?v=${encodeURIComponent(config.updatedAt || "1")}` : null,
      hasCrowdSecKey: await hasCrowdSecApiKey(),
      historyMaxEntries,
      restPortsPerSecond,
      allowedGeoSources,
      allowedReputationSources,
      hasAccessPassword: Boolean(String(config.accessPassword || "").trim()),
    });
  } catch (error) {
    return res.json({
      title: "DNS / IP-Resolver",
      logoDataUrl: null,
      faviconDataUrl: null,
      hasCrowdSecKey: false,
      historyMaxEntries: DEFAULT_HISTORY_MAX_ENTRIES,
      restPortsPerSecond: 2,
      allowedGeoSources: [...LOCAL_GEO_SOURCES],
      allowedReputationSources: ["dnsbl", "privacy", "community", "crowdsec"],
      hasAccessPassword: false,
    });
  }
});

app.post("/api/config/open", async (req, res) => {
  if (!RESOLVER_PASSWORD) {
    return res.status(503).json({ error: "RESOLVER_PASSWORD ist nicht gesetzt." });
  }

  const password = String(req.body?.password || "");
  if (password !== RESOLVER_PASSWORD) {
    return res.status(401).json({ error: "Ungültiges Passwort." });
  }

  const config = await readSiteConfig();
  return res.json({
    ok: true,
    config: {
      title: config.title || "DNS / IP-Resolver",
      historyMaxEntries: await getConfiguredHistoryLimit(),
      restPortsPerSecond: await getConfiguredRestPortsPerSecond(),
      allowedGeoSources: await getConfiguredGeoSources(),
      allowedReputationSources: await getConfiguredReputationSources(),
      hasCrowdSecKey: await hasCrowdSecApiKey(),
      hasAccessPassword: Boolean(String(config.accessPassword || "").trim()),
    },
  });
});

app.post("/api/config/save", async (req, res) => {
  if (!RESOLVER_PASSWORD) {
    return res.status(503).json({ error: "RESOLVER_PASSWORD ist nicht gesetzt." });
  }

  const password = String(req.body?.password || "");
  if (password !== RESOLVER_PASSWORD) {
    return res.status(401).json({ error: "Ungültiges Passwort." });
  }

  try {
    const current = await readSiteConfig();
    const historyMaxEntries = Math.max(1, Math.min(200, Number(req.body?.historyMaxEntries) || DEFAULT_HISTORY_MAX_ENTRIES));
    const restPortsPerSecond = Math.max(1, Math.min(2000, Number(req.body?.restPortsPerSecond) || 2));
    const requestedGeo = Array.isArray(req.body?.allowedGeoSources)
      ? req.body.allowedGeoSources.map((v) => String(v || "").toLowerCase())
      : [...LOCAL_GEO_SOURCES];
    const allowedGeoSources = normalizeAllowedGeoSources(requestedGeo);
    const requestedRep = Array.isArray(req.body?.allowedReputationSources)
      ? req.body.allowedReputationSources.map((v) => String(v || "").toLowerCase())
      : ["dnsbl", "privacy", "community", "crowdsec"];
    const allowedReputationSources = Array.from(
      new Set(requestedRep.filter((v) => ["dnsbl", "privacy", "community", "crowdsec"].includes(v)))
    );
    if (!allowedReputationSources.length) {
      allowedReputationSources.push("community");
    }

    const next = {
      ...current,
      title: String(req.body?.title || current.title || "DNS / IP-Resolver"),
      historyMaxEntries,
      restPortsPerSecond,
      allowedGeoSources,
      allowedReputationSources,
      crowdsecApiKey: String(req.body?.crowdsecApiKey || "").trim() || current.crowdsecApiKey || "",
      accessPassword:
        req.body?.clearAccessPassword === true
          ? ""
          : String(req.body?.accessPassword || "").trim() || current.accessPassword || "",
      updatedAt: new Date().toISOString(),
    };

    const logoPngDataUrl = normalizePngDataUrl(req.body?.logoDataUrl);
    const faviconPngDataUrl = normalizePngDataUrl(req.body?.faviconDataUrl);

    if (logoPngDataUrl) {
      await writeDataUrlAsPng(logoPngDataUrl, LOGO_FILE);
    }
    if (faviconPngDataUrl) {
      await writeDataUrlAsPng(faviconPngDataUrl, FAVICON_FILE);
    }

    await writeSiteConfig(next);
    if (next.accessPassword) {
      const cookieValue = buildAccessCookieValue(next.accessPassword);
      res.setHeader("Set-Cookie", `${ACCESS_COOKIE_NAME}=${cookieValue}; Path=/; HttpOnly; SameSite=Lax`);
    }
    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: "Konfiguration konnte nicht gespeichert werden." });
  }
});

app.post("/api/config/debug/test", async (req, res) => {
  const ip = String(req.body?.ip || "").trim();
  const domain = normalizeDomain(req.body?.domain || "");
  if (!isValidIPv4(ip)) {
    return res.status(400).json({ error: "Bitte eine gültige IPv4-Adresse angeben." });
  }
  if (!isValidDomain(domain)) {
    return res.status(400).json({ error: "Bitte eine gültige Domain angeben." });
  }

  const configuredGeoSources = await getConfiguredGeoSources();
  const geoSources = [...LOCAL_GEO_SOURCES];
  const geoip = await Promise.all(
    geoSources.map(async (src) => {
      const r = await getGeoBySourceWithMeta(ip, src);
      const connectivityOnly = r.reason === "remote_lookup_not_supported";
      return {
        source: src,
        enabled: configuredGeoSources.includes(src),
        ok: Boolean(r.geo) || connectivityOnly,
        reason: connectivityOnly ? "reachable_but_remote_ip_not_supported" : r.reason || null,
      };
    })
  );

  const whoisRaw = await lookupWhoisCached(domain).catch(() => "");
  const whois = [
    {
      provider: "whois",
      ok: Boolean(String(whoisRaw || "").trim()),
      reason: String(whoisRaw || "").trim() ? null : "no_response",
    },
  ];

  const repSources = await getConfiguredReputationSources();
  const reputation = await Promise.all(
    repSources.map(async (src) => {
      try {
        const report = await buildReputationReport(ip, domain, src, null);
        const enabled = report?.sources?.enabled || {};
        const ok = src === "dnsbl"
          ? enabled.dnsbl
          : src === "privacy"
            ? enabled.tor
            : src === "community"
              ? enabled.stopForumSpam || enabled.dnsbl
              : src === "crowdsec"
                ? enabled.crowdsec
                : false;
        let reason = null;
        if (src === "crowdsec") {
          const cs = report?.sources?.crowdSec || null;
          if (cs?.reason === "http_429") {
            reason = "rate_limited";
          } else if (cs?.reason) {
            reason = cs.reason;
          }
        }
        return { provider: src, ok: Boolean(ok), reason };
      } catch (error) {
        return { provider: src, ok: false, reason: "request_failed" };
      }
    })
  );

  return res.json({ ok: true, geoip, whois, reputation });
});

app.post("/api/auth/unlock", async (req, res) => {
  const config = await readSiteConfig();
  const accessPassword = String(config?.accessPassword || "").trim();
  if (!accessPassword) {
    return res.json({ ok: true, disabled: true });
  }

  const password = String(req.body?.password || "");
  if (password !== accessPassword) {
    return res.status(401).json({ error: "invalid_password" });
  }

  const cookieValue = buildAccessCookieValue(accessPassword);
  res.setHeader("Set-Cookie", `${ACCESS_COOKIE_NAME}=${cookieValue}; Path=/; HttpOnly; SameSite=Lax`);
  return res.json({ ok: true });
});

app.get("/api/locales", async (req, res) => {
  try {
    const files = await fs.promises.readdir(LOCALES_DIR, { withFileTypes: true });
    const list = [];
    for (const entry of files) {
      if (!entry.isFile() || !entry.name.endsWith(".json")) {
        continue;
      }
      const code = entry.name.replace(/\.json$/i, "");
      const filePath = path.join(LOCALES_DIR, entry.name);
      try {
        const raw = await fs.promises.readFile(filePath, "utf8");
        const parsed = JSON.parse(raw);
        list.push({
          code,
          name: String(parsed?.meta?.name || code),
          flag: String(parsed?.meta?.flag || ""),
        });
      } catch (error) {
        /* ignore bad locale */
      }
    }
    return res.json({ locales: list.sort((a, b) => a.code.localeCompare(b.code)) });
  } catch (error) {
    return res.json({ locales: [] });
  }
});

app.get("/api/locales/:code", async (req, res) => {
  const code = String(req.params?.code || "").trim().toLowerCase();
  if (!/^[a-z0-9_-]+$/.test(code)) {
    return res.status(400).json({ error: "Ungültiger Sprachcode." });
  }
  const filePath = path.join(LOCALES_DIR, `${code}.json`);
  try {
    const raw = await fs.promises.readFile(filePath, "utf8");
    return res.type("application/json").send(raw);
  } catch (error) {
    return res.status(404).json({ error: "Sprache nicht gefunden." });
  }
});

app.get("/api/history/:id/download", async (req, res) => {
  const id = String(req.params?.id || "").trim();
  const filePath = historyFilePathById(id);
  if (!filePath) {
    return res.status(400).json({ error: "Ungültige History-ID." });
  }

  try {
    const raw = await fs.promises.readFile(filePath, "utf8");
    const parsed = JSON.parse(raw);
    const item = normalizeHistoryItem(parsed);
    if (!item) {
      return res.status(404).json({ error: "Historischer Scan nicht gefunden." });
    }

    const downloadName = `scan-${item.id}.json`;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${downloadName}"`);
    return res.send(JSON.stringify(item, null, 2));
  } catch (error) {
    return res.status(404).json({ error: "Historischer Scan nicht gefunden." });
  }
});

app.listen(PORT, () => {
  console.log(`IP Inspector läuft auf http://localhost:${PORT}`);
});

ensureHistoryStore().catch(() => {
  /* ignore */
});

function isValidIPv4(ip) {
  if (typeof ip !== "string") {
    return false;
  }

  const parts = ip.trim().split(".");
  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    if (!/^\d+$/.test(part)) {
      return false;
    }
    if (part.length > 1 && part.startsWith("0")) {
      return false;
    }
    const value = Number(part);
    return value >= 0 && value <= 255;
  });
}

function isValidDomain(value) {
  if (typeof value !== "string") {
    return false;
  }

  const domain = normalizeDomain(value);
  if (!domain || domain.length > 253) {
    return false;
  }

  if (!domain.includes(".")) {
    return false;
  }

  const labels = domain.split(".");
  return labels.every((label) => /^[a-z0-9-]{1,63}$/i.test(label) && !label.startsWith("-") && !label.endsWith("-"));
}

function normalizeDomain(value) {
  return value.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
}

async function collectDomainIntel(domain) {
  const cached = getCached(domainIntelCache, domain);
  if (cached && (cached.subdomains?.length || 0) >= 5) {
    return cached;
  }

  const [fromCt, fromCtExact, fromCommon, fromCertSpotter] = await Promise.all([
    collectSubdomainsFromCt(domain),
    collectSubdomainsFromCt(domain, false),
    collectCommonSubdomains(domain),
    collectSubdomainsFromCertSpotter(domain),
  ]);

  const subdomains = Array.from(
    new Set([...fromCt, ...fromCtExact, ...fromCommon, ...fromCertSpotter])
  )
    .sort()
    .slice(0, 500);

  const result = {
    subdomains,
  };

  if (subdomains.length >= 5) {
    setCached(domainIntelCache, domain, result, CACHE_TTL_DOMAIN_INTEL_MS);
  } else {
    domainIntelCache.delete(domain);
  }
  return result;
}

function isSubdomainOf(subdomain, rootDomain) {
  if (subdomain === rootDomain) {
    return true;
  }
  return subdomain.endsWith(`.${rootDomain}`);
}

async function safeDnsResolve(fn, fallback = []) {
  try {
    return await fn();
  } catch (error) {
    return fallback;
  }
}

async function collectSubdomainsFromCt(domain, wildcardOnly = true) {
  try {
    const query = wildcardOnly ? `%.${domain}` : domain;
    const body = await fetchTextWithTimeout(
      `https://crt.sh/?q=${encodeURIComponent(query)}&output=json`,
      18000,
      2
    );
    if (!body) {
      return [];
    }

    const rows = parseCrtShRows(body);
    if (!Array.isArray(rows)) {
      return [];
    }

    const set = new Set();

    rows.forEach((row) => {
      const raw = String(row?.name_value || "");
      raw.split("\n").forEach((value) => {
        const normalized = value.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
        if (!normalized) {
          return;
        }
        if (normalized === domain || normalized.endsWith(`.${domain}`)) {
          set.add(normalized);
        }
      });
    });

    return Array.from(set).sort().slice(0, 250);
  } catch (error) {
    return [];
  }
}

async function collectSubdomainsFromCertSpotter(domain) {
  try {
    const url =
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}` +
      `&include_subdomains=true&expand=dns_names`;
    const body = await fetchTextWithTimeout(url, 18000, 1);
    if (!body) {
      return [];
    }

    const rows = JSON.parse(body);
    if (!Array.isArray(rows)) {
      return [];
    }

    const set = new Set();
    rows.forEach((row) => {
      const names = Array.isArray(row?.dns_names) ? row.dns_names : [];
      names.forEach((value) => {
        const normalized = String(value || "")
          .trim()
          .toLowerCase()
          .replace(/^\*\./, "")
          .replace(/\.$/, "");
        if (!normalized) {
          return;
        }
        if (normalized === domain || normalized.endsWith(`.${domain}`)) {
          set.add(normalized);
        }
      });
    });

    return Array.from(set).sort().slice(0, 350);
  } catch (error) {
    return [];
  }
}

async function getSubdomainIntel(subdomain, options = {}) {
  const forceFresh = Boolean(options.forceFresh);
  const cached = forceFresh ? null : getCached(subdomainIntelCache, subdomain);
  if (cached) {
    return cached;
  }

  const [a, aaaa, cname, tlsInfo, history] = await Promise.all([
    safeDnsResolve(() => dns.resolve4(subdomain)),
    safeDnsResolve(() => dns.resolve6(subdomain)),
    safeDnsResolve(() => dns.resolveCname(subdomain)),
    getTlsInfo(subdomain),
    getHistoricalChanges(subdomain),
  ]);

  const risk = calculateSubdomainRisk({ a, aaaa, cname, tlsInfo, history });
  saveObservation(subdomain, a, tlsInfo, risk);
  const ipv4History = getIpv4History(subdomain);

  const result = {
    records: {
      A: a,
      AAAA: aaaa,
      CNAME: cname,
    },
    tls: tlsInfo,
    history,
    risk,
    ipv4History,
  };

  setCached(subdomainIntelCache, subdomain, result, CACHE_TTL_SUBDOMAIN_INTEL_MS);
  return result;
}

function getTlsInfo(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          socket.end();
          if (!cert || !cert.subject) {
            resolve({ available: false });
            return;
          }

          resolve({
            available: true,
            subjectCn: cert.subject.CN || null,
            issuerCn: cert.issuer?.CN || null,
            validFrom: cert.valid_from || null,
            validTo: cert.valid_to || null,
            serialNumber: cert.serialNumber || null,
            san: cert.subjectaltname || null,
          });
        } catch (error) {
          resolve({ available: false });
        }
      }
    );

    socket.setTimeout(6000, () => {
      socket.destroy();
      resolve({ available: false });
    });

    socket.on("error", () => {
      socket.destroy();
      resolve({ available: false });
    });
  });
}

async function getHistoricalChanges(subdomain) {
  try {
    const query = encodeURIComponent(subdomain);
    const body = await fetchTextWithTimeout(`https://crt.sh/?q=${query}&output=json`, 12000);
    if (!body) {
      return [];
    }

    const rows = parseCrtShRows(body);
    const entries = rows
      .map((row) => ({
        loggedAt: row.entry_timestamp || null,
        notBefore: row.not_before || null,
        notAfter: row.not_after || null,
        issuer: row.issuer_name || null,
      }))
      .filter((item) => item.loggedAt || item.notBefore || item.notAfter || item.issuer)
      .sort((a, b) => String(b.loggedAt || "").localeCompare(String(a.loggedAt || "")));

    return entries.slice(0, 12);
  } catch (error) {
    return [];
  }
}

async function fetchTextWithTimeout(url, timeoutMs, retries = 0) {
  const cached = getCached(httpTextCache, url);
  if (cached) {
    return cached;
  }

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { signal: controller.signal });
      if (!response.ok) {
        continue;
      }
      const text = await response.text();
      if (text) {
        setCached(httpTextCache, url, text, CACHE_TTL_HTTP_MS);
        return text;
      }
    } catch (error) {
      if (attempt === retries) {
        return "";
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  return "";
}

function calculateSubdomainRisk({ a, aaaa, cname, tlsInfo, history }) {
  let score = 0;
  const reasons = [];

  const hasAddress = (a?.length || 0) + (aaaa?.length || 0) > 0;
  const hasCname = (cname?.length || 0) > 0;

  if (!hasAddress && !hasCname) {
    score += 22;
    reasons.push("Keine aktiven DNS-Records gefunden");
  }

  if (!tlsInfo?.available) {
    score += 34;
    reasons.push("Kein TLS-Zertifikat auf Port 443");
  } else {
    const days = daysUntil(tlsInfo.validTo);
    if (days !== null && days < 0) {
      score += 45;
      reasons.push("TLS-Zertifikat abgelaufen");
    } else if (days !== null && days <= 14) {
      score += 28;
      reasons.push("TLS-Zertifikat läuft sehr bald ab");
    } else if (days !== null && days <= 45) {
      score += 14;
      reasons.push("TLS-Zertifikat läuft bald ab");
    }
  }

  if ((history?.length || 0) >= 25) {
    score += 18;
    reasons.push("Viele historische Zertifikatsänderungen");
  } else if ((history?.length || 0) >= 12) {
    score += 10;
    reasons.push("Mehrere historische Zertifikatsänderungen");
  }

  if (hasCname) {
    score += 6;
    reasons.push("CNAME-Kette vorhanden");
  }

  const bounded = Math.max(0, Math.min(100, score));
  let level = "niedrig";
  if (bounded >= 65) {
    level = "hoch";
  } else if (bounded >= 35) {
    level = "mittel";
  }

  return {
    score: bounded,
    level,
    reasons,
  };
}

function daysUntil(dateValue) {
  if (!dateValue) {
    return null;
  }
  const ts = Date.parse(dateValue);
  if (!Number.isFinite(ts)) {
    return null;
  }
  return Math.floor((ts - Date.now()) / 86400000);
}

function getCached(map, key) {
  const hit = map.get(key);
  if (!hit) {
    return null;
  }
  if (Date.now() > hit.expiresAt) {
    map.delete(key);
    return null;
  }
  return hit.value;
}

function setCached(map, key, value, ttlMs) {
  map.set(key, {
    value,
    expiresAt: Date.now() + ttlMs,
  });
}

function parseCrtShRows(text) {
  const raw = String(text || "").trim();
  if (!raw) {
    return [];
  }

  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    try {
      const normalized = `[${raw.replace(/}\s*{/g, "},{")}]`;
      const parsed = JSON.parse(normalized);
      return Array.isArray(parsed) ? parsed : [];
    } catch (error2) {
      return [];
    }
  }
}

async function collectCommonSubdomains(domain) {
  const candidates = [
    "www",
    "api",
    "mail",
    "dev",
    "staging",
    "test",
    "admin",
    "app",
    "cdn",
    "blog",
  ].map((prefix) => `${prefix}.${domain}`);

  const checks = await Promise.all(
    candidates.map(async (host) => {
      const a = await safeDnsResolve(() => dns.resolve4(host));
      const cname = await safeDnsResolve(() => dns.resolveCname(host));
      return a.length || cname.length ? host : null;
    })
  );

  return checks.filter(Boolean);
}

async function buildReputationReport(ip, domain, mode) {
  const dnsblZones = ["zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net"];
  const runDnsbl = mode === "dnsbl" || mode === "community";
  const runStopForumSpam = mode === "community";
  const runTor = mode === "privacy" || mode === "community";
  const runCrowdSec =
    (mode === "community" || mode === "crowdsec") &&
    (await hasCrowdSecApiKey());

  const [dnsblResults, stopForumSpam, torExit, crowdSec] = await Promise.all([
    runDnsbl ? Promise.all(dnsblZones.map((zone) => checkDnsbl(ip, zone))) : null,
    runStopForumSpam ? checkStopForumSpam(ip) : null,
    runTor ? checkTorExit(ip) : null,
    runCrowdSec ? checkCrowdSec(ip) : null,
  ]);

  const dnsblListed = Array.isArray(dnsblResults) ? dnsblResults.filter((entry) => entry.listed).length : null;
  const dnsblChecked = Array.isArray(dnsblResults) ? dnsblResults.length : null;
  const signals = {
    dnsblListed,
    dnsblChecked,
    torExit,
    stopForumSpamAppears: stopForumSpam ? Boolean(stopForumSpam.appears) : null,
    crowdsecLocation: crowdSec?.queried ? crowdSec.location || null : null,
    crowdsecReputation: crowdSec?.queried ? crowdSec.reputation || null : null,
    crowdsecAggressive: crowdSec?.queried ? Boolean(crowdSec.aggressive) : null,
    crowdsecMalicious: crowdSec?.queried ? Boolean(crowdSec.malicious) : null,
    crowdsecConfidence: crowdSec?.queried ? Number(crowdSec.confidence || 0) : null,
  };

  const score = calculateReputationScore(signals);

  return {
    target: {
      ip,
      domain: domain || null,
    },
    mode,
    sourceSummary: buildReputationSourceSummary({
      runDnsbl,
      runStopForumSpam,
      runTor,
      runCrowdSec,
    }),
    score,
    signals,
    sources: {
      dnsbl: dnsblResults || [],
      stopForumSpam,
      torExit,
      crowdSec,
      enabled: {
        dnsbl: runDnsbl,
        stopForumSpam: runStopForumSpam,
        tor: runTor,
        crowdsec: runCrowdSec,
      },
    },
  };
}

async function hasCrowdSecApiKey() {
  const config = await readSiteConfig();
  const apiKey = String(config?.crowdsecApiKey || process.env.CROWDSEC_API_KEY || "").trim();
  return Boolean(apiKey);
}

function buildReputationSourceSummary(flags) {
  const list = [];
  if (flags.runDnsbl) {
    list.push("Spamhaus/Spamcop/SORBS");
  }
  if (flags.runStopForumSpam) {
    list.push("StopForumSpam");
  }
  if (flags.runTor) {
    list.push("TOR Exit List");
  }
  if (flags.runCrowdSec) {
    list.push("CrowdSec CTI");
  }
  return list.join(", ");
}

async function checkCrowdSec(ip) {
  const config = await readSiteConfig();
  const apiKey = String(config?.crowdsecApiKey || process.env.CROWDSEC_API_KEY || "").trim();
  if (!apiKey) {
    return {
      enabled: false,
      queried: false,
      reason: "missing_api_key",
    };
  }

  try {
    const response = await fetch(`https://cti.api.crowdsec.net/v2/smoke/${encodeURIComponent(ip)}`, {
      headers: {
        "x-api-key": apiKey,
        Accept: "application/json",
      },
    });

    if (!response.ok) {
      return {
        enabled: true,
        queried: false,
        reason: `http_${response.status}`,
      };
    }

    const data = await response.json();
    const reputation = String(
      data?.reputation || data?.classification || data?.severity || ""
    ).toLowerCase();
    const confidence = Number(data?.confidence ?? data?.score ?? 0);
    const classes = Array.isArray(data?.classifications) ? data.classifications : [];
    const classText = classes.map((entry) => String(entry).toLowerCase());
    const malicious =
      Boolean(data?.malicious) ||
      reputation.includes("malicious") ||
      reputation.includes("aggressive") ||
      classText.some((entry) => entry.includes("malicious") || entry.includes("aggressive")) ||
      confidence >= 4;

    const location =
      data?.location?.country || data?.location?.country_code || data?.location || null;
    const aggressive =
      Boolean(data?.aggressive) ||
      reputation.includes("aggressive") ||
      classText.some((entry) => entry.includes("aggressive"));

    return {
      enabled: true,
      queried: true,
      malicious,
      aggressive,
      location,
      reputation: data?.reputation || null,
      confidence,
      score: Number(data?.score || 0),
      classifications: classes,
      references: Number(data?.references || 0),
    };
  } catch (error) {
    return {
      enabled: true,
      queried: false,
      reason: "request_failed",
    };
  }
}

function normalizeReputationMode(value) {
  const mode = String(value || "community").toLowerCase();
  if (["dnsbl", "privacy", "community", "crowdsec"].includes(mode)) {
    return mode;
  }
  return "community";
}

async function checkDnsbl(ip, zone) {
  try {
    const reversed = ip.split(".").reverse().join(".");
    const query = `${reversed}.${zone}`;
    const result = await dns.resolve4(query);
    return {
      zone,
      listed: Array.isArray(result) && result.length > 0,
      response: result || [],
    };
  } catch (error) {
    return {
      zone,
      listed: false,
      response: [],
    };
  }
}

async function checkStopForumSpam(ip) {
  try {
    const body = await fetchTextWithTimeout(
      `https://api.stopforumspam.org/api?ip=${encodeURIComponent(ip)}&json`,
      8000,
      1
    );
    if (!body) {
      return { appears: false, confidence: 0, frequency: 0 };
    }
    const parsed = JSON.parse(body);
    const ipData = parsed?.ip || {};
    return {
      appears: Boolean(ipData.appears),
      confidence: Number(ipData.confidence || 0),
      frequency: Number(ipData.frequency || 0),
    };
  } catch (error) {
    return { appears: false, confidence: 0, frequency: 0 };
  }
}

async function checkTorExit(ip) {
  try {
    const body = await fetchTextWithTimeout(
      "https://check.torproject.org/torbulkexitlist",
      12000,
      1
    );
    if (!body) {
      return false;
    }
    const set = new Set(
      body
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
    );
    return set.has(ip);
  } catch (error) {
    return false;
  }
}

function calculateReputationScore(signals) {
  let value = 0;
  const reasons = [];

  if ((signals.dnsblListed || 0) > 0) {
    const add = Math.min(40, signals.dnsblListed * 15);
    value += add;
    reasons.push(`DNSBL Treffer: ${signals.dnsblListed}/${signals.dnsblChecked}`);
  }
  if (signals.torExit === true) {
    value += 20;
    reasons.push("IP ist Tor Exit Node");
  }
  if (signals.stopForumSpamAppears === true) {
    value += 18;
    reasons.push("StopForumSpam Treffer");
  }
  if (signals.crowdsecMalicious === true) {
    value += 26;
    reasons.push("CrowdSec meldet bösartige Aktivität");
  }
  if (signals.crowdsecAggressive === true) {
    value += 18;
    reasons.push("CrowdSec stuft IP als aggressiv ein");
  }
  if ((signals.crowdsecConfidence || 0) >= 3) {
    value += 10;
    reasons.push("CrowdSec Confidence erhöht");
  }
  value = Math.max(0, Math.min(100, value));
  let level = "niedrig";
  if (value >= 65) {
    level = "hoch";
  } else if (value >= 35) {
    level = "mittel";
  }

  return { value, level, reasons };
}

function initObservationStore() {
  const fallback = {
    type: "memory",
    rows: [],
  };

  if (!Sqlite) {
    return fallback;
  }

  try {
    const dbPath = path.join(__dirname, "intel-cache.db");
    const db = new Sqlite(dbPath);
    db.pragma("journal_mode = WAL");
    db.exec(`
      CREATE TABLE IF NOT EXISTS subdomain_observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subdomain TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        ipv4_csv TEXT,
        tls_cn TEXT,
        tls_valid_to TEXT,
        risk_score INTEGER,
        risk_level TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_subdomain_observations_subdomain
      ON subdomain_observations(subdomain, observed_at DESC);
    `);

    return {
      type: "sqlite",
      db,
      insertStmt: db.prepare(
        `INSERT INTO subdomain_observations (subdomain, observed_at, ipv4_csv, tls_cn, tls_valid_to, risk_score, risk_level)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ),
      selectStmt: db.prepare(
        `SELECT observed_at, ipv4_csv, tls_cn, tls_valid_to, risk_score, risk_level
         FROM subdomain_observations
         WHERE subdomain = ?
         ORDER BY observed_at DESC
         LIMIT ?`
      ),
    };
  } catch (error) {
    return fallback;
  }
}

function saveObservation(subdomain, aRecords, tlsInfo, risk) {
  const observedAt = new Date().toISOString();
  const ipv4Csv = Array.isArray(aRecords) ? aRecords.join(",") : "";
  const tlsCn = tlsInfo?.subjectCn || "";
  const tlsValidTo = tlsInfo?.validTo || "";
  const riskScore = Number.isFinite(risk?.score) ? risk.score : 0;
  const riskLevel = risk?.level || "niedrig";

  if (dbState.type === "sqlite") {
    try {
      dbState.insertStmt.run(subdomain, observedAt, ipv4Csv, tlsCn, tlsValidTo, riskScore, riskLevel);
      return;
    } catch (error) {
      return;
    }
  }

  dbState.rows.push({
    subdomain,
    observedAt,
    ipv4Csv,
    tlsCn,
    tlsValidTo,
    riskScore,
    riskLevel,
  });
  if (dbState.rows.length > 4000) {
    dbState.rows.splice(0, dbState.rows.length - 4000);
  }
}

function getIpv4History(subdomain) {
  if (dbState.type === "sqlite") {
    try {
      const rows = dbState.selectStmt.all(subdomain, 20);
      return rows
        .map((row) => ({
          observedAt: row.observed_at,
          ipv4: String(row.ipv4_csv || "")
            .split(",")
            .map((value) => value.trim())
            .filter(Boolean),
          tlsCn: row.tls_cn || null,
          tlsValidTo: row.tls_valid_to || null,
          riskScore: row.risk_score ?? null,
          riskLevel: row.risk_level || null,
        }))
        .filter((entry) => entry.ipv4.length || entry.tlsCn || entry.tlsValidTo || entry.riskScore !== null);
    } catch (error) {
      return [];
    }
  }

  return dbState.rows
    .filter((row) => row.subdomain === subdomain)
    .slice(-20)
    .reverse()
    .map((row) => ({
      observedAt: row.observedAt,
      ipv4: String(row.ipv4Csv || "")
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean),
      tlsCn: row.tlsCn || null,
      tlsValidTo: row.tlsValidTo || null,
      riskScore: row.riskScore ?? null,
      riskLevel: row.riskLevel || null,
    }));
}

function normalizeGeoSource(source) {
  const normalized = String(source || "geoiplite").toLowerCase();
  if (LOCAL_GEO_SOURCES.includes(normalized)) {
    return normalized;
  }
  return "geoiplite";
}

function safeRequire(moduleName) {
  try {
    return require(moduleName);
  } catch (error) {
    return null;
  }
}

function safeResolvePackageFile(modulePath) {
  try {
    return require.resolve(modulePath);
  } catch (error) {
    return "";
  }
}

function normalizeRequestedKnownPorts(value) {
  if (!Array.isArray(value)) {
    return [...KNOWN_PORTS];
  }

  const knownSet = new Set(KNOWN_PORTS);
  const unique = new Set();

  value.forEach((item) => {
    const port = Number(item);
    if (Number.isInteger(port) && knownSet.has(port)) {
      unique.add(port);
    }
  });

  return Array.from(unique).sort((a, b) => a - b);
}

function normalizePortList(value, maxPort) {
  if (!Array.isArray(value)) {
    return [];
  }

  const unique = new Set();
  value.forEach((item) => {
    const port = Number(item);
    if (Number.isInteger(port) && port >= 1 && port <= maxPort) {
      unique.add(port);
    }
  });

  return Array.from(unique).sort((a, b) => a - b);
}

async function ensureHistoryStore() {
  await fs.promises.mkdir(HISTORY_DIR, { recursive: true });
}

async function readHistoryStore() {
  await ensureHistoryStore();

  try {
    const files = await listHistoryFiles();
    const rows = await Promise.all(
      files.map(async (fileName) => {
        const filePath = path.join(HISTORY_DIR, fileName);
        try {
          const raw = await fs.promises.readFile(filePath, "utf8");
          const parsed = JSON.parse(raw);
          return normalizeHistoryItem(parsed);
        } catch (error) {
          return null;
        }
      })
    );

    const limit = await getConfiguredHistoryLimit();
    const normalized = normalizeHistoryItems(rows.filter(Boolean), limit);
    await syncHistoryFiles(normalized);
    return normalized;
  } catch (error) {
    return [];
  }
}

async function writeHistoryStore(items) {
  await ensureHistoryStore();

  const limit = await getConfiguredHistoryLimit();
  const normalized = normalizeHistoryItems(items, limit);
  await syncHistoryFiles(normalized);
}

async function listHistoryFiles() {
  const entries = await fs.promises.readdir(HISTORY_DIR, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith(".json"))
    .map((entry) => entry.name);
}

async function syncHistoryFiles(items) {
  const keepIds = new Set(items.map((item) => item.id));

  await Promise.all(
    items.map(async (item) => {
      const filePath = historyFilePathById(item.id);
      if (!filePath) {
        return;
      }
      await writeJsonAtomic(filePath, item);
    })
  );

  const files = await listHistoryFiles();
  await Promise.all(
    files.map(async (fileName) => {
      const id = historyIdFromFileName(fileName);
      if (!id || !keepIds.has(id)) {
        try {
          await fs.promises.unlink(path.join(HISTORY_DIR, fileName));
        } catch (error) {
          /* ignore */
        }
      }
    })
  );
}

async function writeJsonAtomic(filePath, value) {
  const payload = JSON.stringify(value, null, 2);
  const tmpFile = `${filePath}.tmp`;
  await fs.promises.writeFile(tmpFile, payload, "utf8");
  await fs.promises.rename(tmpFile, filePath);
}

function historyFilePathById(id) {
  const safeId = sanitizeHistoryId(id);
  if (!safeId) {
    return null;
  }
  return path.join(HISTORY_DIR, `${safeId}.json`);
}

function historyIdFromFileName(fileName) {
  const normalized = String(fileName || "").trim().toLowerCase();
  if (!normalized.endsWith(".json")) {
    return null;
  }
  const id = fileName.slice(0, -5);
  return sanitizeHistoryId(id);
}

function sanitizeHistoryId(id) {
  const value = String(id || "").trim();
  if (!value) {
    return "";
  }
  return value.replace(/[^a-z0-9_-]/gi, "_");
}

async function sendConfiguredImage(res, filePath) {
  if (fs.existsSync(filePath)) {
    return res.sendFile(filePath);
  }
  return res.status(404).end();
}

function normalizePngDataUrl(value) {
  const input = String(value || "").trim();
  if (!input) {
    return "";
  }
  const parsed = parseDataUrlPng(input);
  return parsed ? input : "";
}

function parseDataUrlPng(value) {
  const match = String(value || "").match(/^data:(image\/png);base64,([a-z0-9+/=\r\n]+)$/i);
  if (!match) {
    return null;
  }
  const mimeType = match[1].toLowerCase();
  const payload = match[2].replace(/\s+/g, "");
  try {
    const buffer = Buffer.from(payload, "base64");
    if (!buffer.length) {
      return null;
    }
    return { mimeType, buffer };
  } catch (error) {
    return null;
  }
}

async function writeDataUrlAsPng(dataUrl, filePath) {
  const parsed = parseDataUrlPng(dataUrl);
  if (!parsed) {
    return;
  }
  await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
  await fs.promises.writeFile(filePath, parsed.buffer);
}

async function getConfiguredHistoryLimit() {
  const config = await readSiteConfig();
  const value = Number(config?.historyMaxEntries);
  if (!Number.isFinite(value)) {
    return DEFAULT_HISTORY_MAX_ENTRIES;
  }
  return Math.max(1, Math.min(200, Math.floor(value)));
}

async function getConfiguredRestPortsPerSecond() {
  const config = await readSiteConfig();
  const value = Number(config?.restPortsPerSecond);
  if (!Number.isFinite(value)) {
    return 2;
  }
  return Math.max(1, Math.min(2000, Math.floor(value)));
}

async function getConfiguredGeoSources() {
  const config = await readSiteConfig();
  const list = Array.isArray(config?.allowedGeoSources)
    ? config.allowedGeoSources.map((v) => String(v || "").toLowerCase())
    : [...LOCAL_GEO_SOURCES];
  return normalizeAllowedGeoSources(list);
}

function normalizeAllowedGeoSources(list) {
  const mapped = (Array.isArray(list) ? list : [])
    .map((v) => String(v || "").toLowerCase())
    .map((v) => {
      if (v === "ipinfo" || v === "geojs" || v === "ipapi") {
        return "geoiplite";
      }
      return v;
    });

  const allowed = Array.from(new Set(mapped.filter((v) => LOCAL_GEO_SOURCES.includes(v))));
  return allowed.length ? allowed : ["geoiplite"];
}

async function getConfiguredReputationSources() {
  const config = await readSiteConfig();
  const list = Array.isArray(config?.allowedReputationSources)
    ? config.allowedReputationSources.map((v) => String(v || "").toLowerCase())
    : ["dnsbl", "privacy", "community", "crowdsec"];
  const allowed = Array.from(
    new Set(list.filter((v) => ["dnsbl", "privacy", "community", "crowdsec"].includes(v)))
  );
  return allowed.length ? allowed : ["community"];
}

async function ensureConfigStore() {
  await fs.promises.mkdir(CONFIG_DIR, { recursive: true });
  await fs.promises.mkdir(IMAGES_DIR, { recursive: true });
}

function parseCookies(headerValue) {
  const out = {};
  String(headerValue || "")
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .forEach((part) => {
      const idx = part.indexOf("=");
      if (idx <= 0) {
        return;
      }
      const key = part.slice(0, idx).trim();
      const value = part.slice(idx + 1).trim();
      out[key] = value;
    });
  return out;
}

function buildAccessCookieValue(accessPassword) {
  const source = `${accessPassword}|${RESOLVER_PASSWORD}`;
  return crypto.createHash("sha256").update(source).digest("hex");
}

async function readSiteConfig() {
  if (!RESOLVER_PASSWORD) {
    return {};
  }
  await ensureConfigStore();
  try {
    const raw = await fs.promises.readFile(CONFIG_FILE, "utf8");
    const parsed = JSON.parse(raw);
    const decrypted = decryptPayload(parsed, RESOLVER_PASSWORD);
    return decrypted && typeof decrypted === "object" ? decrypted : {};
  } catch (error) {
    return {};
  }
}

async function writeSiteConfig(config) {
  if (!RESOLVER_PASSWORD) {
    throw new Error("RESOLVER_PASSWORD missing");
  }

  await ensureConfigStore();
  const encrypted = encryptPayload(config, RESOLVER_PASSWORD);
  const payload = JSON.stringify(encrypted, null, 2);
  const tmpFile = `${CONFIG_FILE}.tmp`;
  await fs.promises.writeFile(tmpFile, payload, "utf8");
  await fs.promises.rename(tmpFile, CONFIG_FILE);
}

function encryptPayload(value, password) {
  const iv = crypto.randomBytes(12);
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    v: 1,
    alg: "aes-256-gcm",
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: encrypted.toString("base64"),
  };
}

function decryptPayload(payload, password) {
  if (!payload || payload.v !== 1 || payload.alg !== "aes-256-gcm") {
    return {};
  }

  const salt = Buffer.from(String(payload.salt || ""), "base64");
  const iv = Buffer.from(String(payload.iv || ""), "base64");
  const tag = Buffer.from(String(payload.tag || ""), "base64");
  const data = Buffer.from(String(payload.data || ""), "base64");
  const key = crypto.scryptSync(password, salt, 32);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
  return JSON.parse(decrypted);
}

function normalizeHistoryItems(items, maxEntries = DEFAULT_HISTORY_MAX_ENTRIES) {
  const now = Date.now();

  return items
    .map((item) => normalizeHistoryItem(item))
    .filter(Boolean)
    .filter((item) => Date.parse(item.updatedAt || item.createdAt || 0) >= now - HISTORY_MAX_AGE_MS)
    .sort((a, b) => Date.parse(b.updatedAt || b.createdAt || 0) - Date.parse(a.updatedAt || a.createdAt || 0))
    .slice(0, Math.max(1, Number(maxEntries) || DEFAULT_HISTORY_MAX_ENTRIES));
}

function normalizeHistoryItem(item) {
  if (!item || typeof item !== "object") {
    return null;
  }

  const id = sanitizeHistoryId(item.id);
  const input = String(item.input || "").trim();
  const targetType = String(item.targetType || "").trim();
  const createdAt = String(item.createdAt || "").trim();
  const updatedAt = String(item.updatedAt || "").trim();
  const lastAction = String(item.lastAction || "").trim();
  const snapshot = item.snapshot && typeof item.snapshot === "object" ? item.snapshot : null;

  if (!id || !input || !createdAt || !updatedAt || !snapshot) {
    return null;
  }

  if (!Number.isFinite(Date.parse(createdAt)) || !Number.isFinite(Date.parse(updatedAt))) {
    return null;
  }

  return {
    id,
    input,
    targetType,
    createdAt,
    updatedAt,
    lastAction,
    snapshot,
  };
}

async function getGeoBySource(ip, source) {
  if (source === "geoiplite") {
    return getGeoIpInfoGeoIpLite(ip);
  }
  if (source === "maxmind") {
    return getGeoIpInfoMaxMindMmdb(ip);
  }
  if (source === "geoip2node") {
    return getGeoIpInfoGeoIp2Node(ip);
  }
  return getGeoIpInfoGeoIpLite(ip);
}

async function getGeoBySourceWithMeta(ip, source) {
  try {
    if (source === "geoiplite") {
      const geo = getGeoIpInfoGeoIpLite(ip);
      return { geo, reason: geo ? null : "no_data" };
    }
    if (source === "maxmind") {
      return await getGeoIpInfoMaxMindMmdbWithMeta(ip);
    }
    if (source === "geoip2node") {
      return await getGeoIpInfoGeoIp2NodeWithMeta(ip);
    }
    const geo = getGeoIpInfoGeoIpLite(ip);
    return { geo, reason: geo ? null : "no_data" };
  } catch (error) {
    return { geo: null, reason: "request_failed" };
  }
}

async function enrichGeoProviderInfo(ip, geo) {
  if (!geo || typeof geo !== "object") {
    return geo;
  }
  const asnInfo = await lookupAsnInfo(ip);
  let nextGeo = {
    ...geo,
    isp: geo.isp || asnInfo.isp || null,
    asn: geo.asn || asnInfo.asn || null,
  };

  if (nextGeo.domain) {
    return nextGeo;
  }

  try {
    const ptrResult = await Promise.race([
      dns.reverse(ip),
      sleep(1200).then(() => []),
    ]);
    const ptrHost = Array.isArray(ptrResult) ? String(ptrResult[0] || "").trim() : "";
    if (!ptrHost) {
      return nextGeo;
    }
    return {
      ...nextGeo,
      domain: ptrHost,
    };
  } catch (error) {
    return nextGeo;
  }
}

async function lookupAsnInfo(ip) {
  try {
    const reader = await getMaxmindAsnReader();
    if (!reader) {
      logGeoDataset(ip, "maxmind-asn", { reason: "mmdb_unavailable" });
      return { asn: null, isp: null };
    }
    const raw = reader.get(ip);
    logGeoDataset(ip, "maxmind-asn", raw);
    const asnNumber = mmdbValue(raw, "autonomous_system_number", "autonomousSystemNumber", "asn");
    const asnOrg = mmdbValue(
      raw,
      "autonomous_system_organization",
      "autonomousSystemOrganization",
      "organization",
      "isp",
      "provider"
    );
    return {
      asn: asnNumber ? `AS${asnNumber}` : null,
      isp: normalizeIspLabel(asnOrg),
    };
  } catch (error) {
    logGeoDataset(ip, "maxmind-asn", { reason: "request_failed", error: String(error?.message || error || "unknown") });
    return { asn: null, isp: null };
  }
}

function getGeoIpInfoGeoIpLite(ip) {
  const info = geoip.lookup(ip);
  logGeoDataset(ip, "geoip-lite", info);
  if (!info) {
    if (isPrivateOrReservedIPv4(ip)) {
      logGeoDataset(ip, "geoip-lite-synthetic", {
        reason: "private_or_reserved",
      });
      return {
        provider: "geoip-lite",
        ip,
        type: "IPv4",
        continent: "Lokal/Reserviert",
        continentCode: null,
        country: "Private/Reserved",
        countryCode: null,
        region: null,
        city: null,
        latitude: null,
        longitude: null,
        postal: null,
        capital: null,
        borders: null,
        flag: null,
        timezone: null,
        timezoneOffset: null,
        currency: null,
        currencyName: null,
        phonePrefix: null,
        isp: "Local Network",
        organization: "RFC1918 / Reserved Range",
        asn: null,
        domain: null,
        countryFlagImage: null,
      };
    }
    return null;
  }

  const [latitude, longitude] = Array.isArray(info.ll) ? info.ll : [null, null];
  const countryCode = info.country || null;
  const continentCode = inferContinentCode(countryCode, info.continent || null, info.timezone || null);
  const currency = countryCode ? countryToCurrency[countryCode] || null : null;
  const phonePrefix = getPhonePrefix(countryCode);

  return {
    provider: "geoip-lite",
    ip,
    type: "IPv4",
    continent: continentCode ? CONTINENT_NAMES[continentCode] || continentCode : null,
    continentCode,
    country: getCountryName(countryCode),
    countryCode,
    region: info.region || null,
    city: info.city || null,
    latitude,
    longitude,
    postal: info.zip || null,
    capital: null,
    borders: null,
    flag: countryCode ? countryCodeToFlag(countryCode) : null,
    timezone: info.timezone || null,
    timezoneOffset: null,
    currency,
    currencyName: getCurrencyName(currency),
    phonePrefix,
    isp: normalizeIspLabel(info.org),
    organization: null,
    asn: null,
    domain: null,
    countryFlagImage: countryCode ? `https://flagcdn.com/w80/${countryCode.toLowerCase()}.png` : null,
  };
}

async function getGeoIpInfoMaxMindMmdb(ip) {
  const result = await getGeoIpInfoMaxMindMmdbWithMeta(ip);
  return result.geo;
}

async function getGeoIpInfoMaxMindMmdbWithMeta(ip) {
  try {
    const reader = await getMaxmindReader();
    if (!reader) {
      logGeoDataset(ip, "maxmind-mmdb", { reason: "mmdb_unavailable" });
      const fallback = withProviderFallback(getGeoIpInfoGeoIpLite(ip), "maxmind-mmdb");
      return fallback ? { geo: fallback, reason: null } : { geo: null, reason: "mmdb_unavailable" };
    }
    const data = reader.get(ip);
    logGeoDataset(ip, "maxmind-mmdb", data);
    const geo = normalizeGeoFromMmdb(data, ip, "maxmind-mmdb");
    if (!geo) {
      const fallback = withProviderFallback(getGeoIpInfoGeoIpLite(ip), "maxmind-mmdb");
      return fallback ? { geo: fallback, reason: null } : { geo: null, reason: "no_data" };
    }
    return {
      geo,
      reason: null,
    };
  } catch (error) {
    logGeoDataset(ip, "maxmind-mmdb", { reason: "request_failed", error: String(error?.message || error || "unknown") });
    const fallback = withProviderFallback(getGeoIpInfoGeoIpLite(ip), "maxmind-mmdb");
    return fallback ? { geo: fallback, reason: null } : { geo: null, reason: "request_failed" };
  }
}

async function getGeoIpInfoGeoIp2Node(ip) {
  const result = await getGeoIpInfoGeoIp2NodeWithMeta(ip);
  return result.geo;
}

async function getGeoIpInfoGeoIp2NodeWithMeta(ip) {
  try {
    const reader = await getGeoIp2Reader();
    if (!reader) {
      logGeoDataset(ip, "geoip2-node", { reason: "mmdb_unavailable" });
      const compatGeo = await getGeoFromMaxmindReader(ip, "geoip2-node (compat)");
      if (compatGeo) {
        return { geo: compatGeo, reason: null };
      }
      const fallback = withProviderFallback(getGeoIpInfoGeoIpLite(ip), "geoip2-node");
      return fallback ? { geo: fallback, reason: null } : { geo: null, reason: "mmdb_unavailable" };
    }
    const data = typeof reader.get === "function" ? reader.get(ip) : reader.city(ip);
    logGeoDataset(ip, "geoip2-node", data);
    const geo = normalizeGeoFromMmdb(data, ip, "geoip2-node");
    if (!geo) {
      const compatGeo = await getGeoFromMaxmindReader(ip, "geoip2-node (compat)");
      if (compatGeo) {
        return { geo: compatGeo, reason: null };
      }
      const fallback = withProviderFallback(getGeoIpInfoGeoIpLite(ip), "geoip2-node");
      return fallback ? { geo: fallback, reason: null } : { geo: null, reason: "no_data" };
    }
    return {
      geo,
      reason: null,
    };
  } catch (error) {
    logGeoDataset(ip, "geoip2-node", { reason: "request_failed", error: String(error?.message || error || "unknown") });
    const compatGeo = await getGeoFromMaxmindReader(ip, "geoip2-node (compat)");
    if (compatGeo) {
      return { geo: compatGeo, reason: null };
    }
    const fallback = withProviderFallback(getGeoIpInfoGeoIpLite(ip), "geoip2-node");
    return fallback ? { geo: fallback, reason: null } : { geo: null, reason: "request_failed" };
  }
}

async function getGeoFromMaxmindReader(ip, providerName) {
  try {
    const reader = await getMaxmindReader();
    if (!reader) {
      return null;
    }
    const data = reader.get(ip);
    return normalizeGeoFromMmdb(data, ip, providerName);
  } catch (error) {
    return null;
  }
}

function withProviderFallback(geo, providerName) {
  if (!geo) {
    return null;
  }
  return {
    ...geo,
    provider: `${providerName} (fallback: geoip-lite)`,
  };
}

function normalizeGeoFromMmdb(record, ip, providerName) {
  if (!record || typeof record !== "object") {
    return null;
  }

  const countryCode = mmdbValue(record, "country.iso_code", "country.isoCode", "country_code") || null;
  const timezone = mmdbValue(record, "location.time_zone", "location.timeZone", "timezone") || null;
  const continentCode = inferContinentCode(countryCode, mmdbValue(record, "continent.code") || null, timezone);
  const latitude = toNullableNumber(mmdbValue(record, "location.latitude", "latitude"));
  const longitude = toNullableNumber(mmdbValue(record, "location.longitude", "longitude"));
  const currency = countryCode ? countryToCurrency[countryCode] || null : null;
  const autonomousSystemNumber = mmdbValue(record, "traits.autonomous_system_number", "traits.autonomousSystemNumber", "asn");
  const autonomousSystemOrg = mmdbValue(
    record,
    "traits.autonomous_system_organization",
    "traits.autonomousSystemOrganization",
    "autonomous_system_organization",
    "isp",
    "internet_provider",
    "provider",
    "network.organization"
  );
  const organizationName = mmdbValue(
    record,
    "traits.organization",
    "traits.company",
    "organization",
    "company",
    "enterprise.name"
  );
  const liteInfo = geoip.lookup(ip) || null;
  const phonePrefix = getPhonePrefix(countryCode);
  const liteIsp = normalizeIspLabel(liteInfo?.org);
  const resolvedIsp = normalizeIspLabel(autonomousSystemOrg) || liteIsp || null;

  return {
    provider: providerName,
    ip,
    type: String(ip).includes(":") ? "IPv6" : "IPv4",
    continent: continentCode ? CONTINENT_NAMES[continentCode] || continentCode : null,
    continentCode,
    country: mmdbValue(record, "country.names.en", "country.name") || getCountryName(countryCode),
    countryCode,
    region: mmdbValue(record, "subdivisions.0.names.en", "subdivisions.0.name", "subdivisions.0.iso_code", "state1", "state2") || null,
    city: mmdbValue(record, "city.names.en", "city.name", "city") || null,
    latitude,
    longitude,
    postal: mmdbValue(record, "postal.code", "postcode") || liteInfo?.zip || null,
    capital: null,
    borders: null,
    flag: countryCode ? countryCodeToFlag(countryCode) : null,
    timezone,
    timezoneOffset: null,
    currency,
    currencyName: getCurrencyName(currency),
    phonePrefix,
    isp: resolvedIsp,
    organization: organizationName || null,
    asn: autonomousSystemNumber ? `AS${autonomousSystemNumber}` : null,
    domain: null,
    countryFlagImage: countryCode ? `https://flagcdn.com/w80/${countryCode.toLowerCase()}.png` : null,
  };
}

async function getMaxmindReader() {
  if (!maxmind || typeof maxmind.open !== "function") {
    return null;
  }
  if (!maxmindCityReaderPromise) {
    maxmindCityReaderPromise = (async () => {
      for (const mmdbPath of GEOIP_CITY_MMDB_CANDIDATE_FILES) {
        if (!mmdbPath || !fs.existsSync(mmdbPath)) {
          continue;
        }
        try {
          const reader = await maxmind.open(mmdbPath);
          resolvedGeoCityMmdbPath = mmdbPath;
          return reader;
        } catch (error) {
          /* try next candidate */
        }
      }
      resolvedGeoCityMmdbPath = null;
      return null;
    })();
  }
  return maxmindCityReaderPromise;
}

async function getGeoIp2Reader() {
  const Reader = geoip2Node?.Reader;
  if (!Reader || typeof Reader.open !== "function") {
    return null;
  }
  if (!geoip2CityReaderPromise) {
    geoip2CityReaderPromise = (async () => {
      for (const mmdbPath of GEOIP_CITY_MMDB_CANDIDATE_FILES) {
        if (!mmdbPath || !fs.existsSync(mmdbPath)) {
          continue;
        }
        try {
          const reader = await Reader.open(mmdbPath);
          resolvedGeoCityMmdbPath = mmdbPath;
          return reader;
        } catch (error) {
          /* try next candidate */
        }
      }
      resolvedGeoCityMmdbPath = null;
      return null;
    })();
  }
  return geoip2CityReaderPromise;
}

async function getMaxmindAsnReader() {
  if (!maxmind || typeof maxmind.open !== "function") {
    return null;
  }
  if (!maxmindAsnReaderPromise) {
    maxmindAsnReaderPromise = (async () => {
      for (const mmdbPath of GEOIP_ASN_MMDB_CANDIDATE_FILES) {
        if (!mmdbPath || !fs.existsSync(mmdbPath)) {
          continue;
        }
        try {
          const reader = await maxmind.open(mmdbPath);
          resolvedGeoAsnMmdbPath = mmdbPath;
          return reader;
        } catch (error) {
          /* try next candidate */
        }
      }
      resolvedGeoAsnMmdbPath = null;
      return null;
    })();
  }
  return maxmindAsnReaderPromise;
}

function isPrivateOrReservedIPv4(ip) {
  if (!isValidIPv4(ip)) {
    return false;
  }
  const [a, b, c] = ip.split(".").map((part) => Number(part));
  if (a === 10 || a === 127 || a === 0) {
    return true;
  }
  if (a === 192 && b === 168) {
    return true;
  }
  if (a === 172 && b >= 16 && b <= 31) {
    return true;
  }
  if (a === 169 && b === 254) {
    return true;
  }
  if (a === 100 && b >= 64 && b <= 127) {
    return true;
  }
  if (a === 192 && b === 0 && (c === 0 || c === 2)) {
    return true;
  }
  if (a === 198 && (b === 18 || b === 19)) {
    return true;
  }
  if (a === 198 && b === 51 && c === 100) {
    return true;
  }
  if (a === 203 && b === 0 && c === 113) {
    return true;
  }
  if (a >= 224) {
    return true;
  }
  return false;
}

function mmdbValue(obj, ...paths) {
  for (const keyPath of paths) {
    const value = keyPath
      .split(".")
      .reduce((acc, segment) => {
        if (acc === null || acc === undefined) {
          return undefined;
        }
        if (/^\d+$/.test(segment)) {
          return Array.isArray(acc) ? acc[Number(segment)] : undefined;
        }
        return acc[segment];
      }, obj);
    if (value !== undefined && value !== null && value !== "") {
      return value;
    }
  }
  return null;
}

function toNullableNumber(value) {
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
}

function normalizeIspLabel(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return null;
  }
  return raw.replace(/^AS\d+\s+/i, "").trim() || raw;
}

function getPhonePrefix(countryCode) {
  if (!countryCode) {
    return null;
  }
  return COUNTRY_CALLING_CODES[String(countryCode).toUpperCase()] || null;
}

function inferContinentCode(countryCode, explicitContinentCode, timezone) {
  if (explicitContinentCode) {
    return String(explicitContinentCode).toUpperCase();
  }

  const tz = String(timezone || "");
  if (tz.startsWith("Europe/")) return "EU";
  if (tz.startsWith("Asia/")) return "AS";
  if (tz.startsWith("Africa/")) return "AF";
  if (tz.startsWith("America/") || tz.startsWith("US/")) return "NA";
  if (tz.startsWith("Australia/") || tz.startsWith("Pacific/")) return "OC";

  const cc = String(countryCode || "").toUpperCase();
  if (!cc) {
    return null;
  }

  const europe = new Set(["DE", "FR", "NL", "BE", "AT", "CH", "IT", "ES", "PT", "GB", "IE", "NO", "SE", "FI", "DK", "PL", "CZ", "SK", "HU", "RO", "BG", "HR", "SI", "RS", "UA", "RU", "IS", "GR", "TR"]);
  const asia = new Set(["CN", "JP", "KR", "IN", "PK", "TH", "VN", "ID", "MY", "SG", "PH", "AE", "SA", "IL", "QA", "KW"]);
  const africa = new Set(["ZA", "EG", "MA", "TN", "DZ", "NG", "KE", "GH", "ET"]);
  const northAmerica = new Set(["US", "CA", "MX"]);
  const southAmerica = new Set(["BR", "AR", "CL", "CO", "PE", "UY", "PY", "BO", "EC", "VE"]);
  const oceania = new Set(["AU", "NZ", "FJ", "PG"]);

  if (europe.has(cc)) return "EU";
  if (asia.has(cc)) return "AS";
  if (africa.has(cc)) return "AF";
  if (northAmerica.has(cc)) return "NA";
  if (southAmerica.has(cc)) return "SA";
  if (oceania.has(cc)) return "OC";
  return null;
}

function safeDisplayNames(type) {
  try {
    return new Intl.DisplayNames(["de"], { type });
  } catch (error) {
    return null;
  }
}

function getCountryName(countryCode) {
  if (!countryCode) {
    return null;
  }
  return COUNTRY_NAMES?.of(countryCode) || countryCode;
}

function getCurrencyName(currencyCode) {
  if (!currencyCode) {
    return null;
  }
  return CURRENCY_NAMES?.of(currencyCode) || currencyCode;
}

function countryCodeToFlag(countryCode) {
  if (!countryCode || countryCode.length !== 2) {
    return null;
  }
  return countryCode
    .toUpperCase()
    .split("")
    .map((char) => String.fromCodePoint(char.charCodeAt(0) + 127397))
    .join("");
}

function lookupWhois(domain) {
  return new Promise((resolve, reject) => {
    whois.lookup(
      domain,
      {
        follow: 2,
        timeout: 12000,
      },
      (error, data) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(data || "");
      }
    );
  });
}

async function lookupWhoisCached(domain) {
  const key = `whois:${domain}`;
  const cached = getCached(whoisCache, key);
  if (cached) {
    return cached;
  }
  const result = await lookupWhois(domain);
  setCached(whoisCache, key, result, CACHE_TTL_WHOIS_MS);
  return result;
}

function parseWhois(rawText, domain) {
  const text = String(rawText || "");

  return {
    source: `https://www.whois.com/whois/${domain}`,
    registrar: findWhoisValue(text, ["Registrar", "Sponsoring Registrar"]),
    registrantName: findWhoisValue(text, ["Registrant Name", "registrant-name", "Owner Name"]),
    registrantOrg: findWhoisValue(text, ["Registrant Organization", "Registrant Org", "org"]),
    registrantCountry: findWhoisValue(text, ["Registrant Country", "country"]),
    createdAt: findWhoisValue(text, ["Creation Date", "Created On", "Registered On"]),
    updatedAt: findWhoisValue(text, ["Updated Date", "Last Updated On"]),
    expiresAt: findWhoisValue(text, ["Registry Expiry Date", "Registrar Registration Expiration Date", "Expiry Date"]),
    status: findWhoisValue(text, ["Domain Status", "Status"]),
    nameServers: findWhoisValues(text, ["Name Server", "nserver"]),
    rawPreview: text.slice(0, 2200),
  };
}

function findWhoisValue(text, keys) {
  for (const key of keys) {
    const regex = new RegExp(`^${escapeRegex(key)}\\s*:\\s*(.+)$`, "gim");
    const match = regex.exec(text);
    if (match?.[1]) {
      return match[1].trim();
    }
  }
  return null;
}

function findWhoisValues(text, keys) {
  const values = new Set();

  for (const key of keys) {
    const regex = new RegExp(`^${escapeRegex(key)}\\s*:\\s*(.+)$`, "gim");
    for (const match of text.matchAll(regex)) {
      const value = (match[1] || "").trim();
      if (value) {
        values.add(value);
      }
    }
  }

  return Array.from(values);
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function scanSinglePort(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = new net.Socket();

    const finalize = (isOpen) => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve(
        isOpen
          ? {
              port,
              service: PORT_LABELS[port] || "Unbekannt",
            }
          : null
      );
    };

    socket.setTimeout(timeoutMs);

    socket.once("connect", () => finalize(true));
    socket.once("timeout", () => finalize(false));
    socket.once("error", () => finalize(false));

    socket.connect(port, ip);
  });
}

async function scanPorts(ip, ports, options = {}) {
  const timeoutMs = options.timeoutMs || 300;
  const concurrency = options.concurrency || 200;
  const openPorts = [];
  let cursor = 0;

  const workers = Array.from({ length: concurrency }, async () => {
    while (true) {
      const currentIndex = cursor;
      cursor += 1;

      if (currentIndex >= ports.length) {
        return;
      }

      const port = ports[currentIndex];
      const result = await scanSinglePort(ip, port, timeoutMs);
      if (result) {
        openPorts.push(result);
      }
    }
  });

  await Promise.all(workers);

  return openPorts.sort((a, b) => a.port - b.port);
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function logGeoDataset(ip, source, payload) {
  try {
    const serialized = safeJson(payload);
    console.log(`[GeoIP debug] ip=${ip} source=${source} payload=${serialized}`);
  } catch (error) {
    console.log(`[GeoIP debug] ip=${ip} source=${source} payload_unserializable`);
  }
}

function safeJson(value) {
  try {
    const raw = JSON.stringify(value, (_, v) => (typeof v === "bigint" ? String(v) : v));
    if (!raw) {
      return "null";
    }
    return raw.length > 6000 ? `${raw.slice(0, 6000)}...<truncated>` : raw;
  } catch (error) {
    return String(value);
  }
}
