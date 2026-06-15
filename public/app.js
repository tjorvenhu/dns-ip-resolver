const form = document.getElementById("ip-form");
const ipInput = document.getElementById("ip-input");
const analyzeButton = document.getElementById("analyze-button");
const geoSourceSelect = document.getElementById("geo-source");
const statusEl = document.getElementById("status");
const toastStack = document.getElementById("toast-stack");

const geoResult = document.getElementById("geo-result");
const geoGrid = document.getElementById("geo-grid");
const geoProvider = document.getElementById("geo-provider");
const flagImage = document.getElementById("flag");
const geoMapWrap = document.getElementById("geo-map-wrap");
const geoMap = document.getElementById("geo-map");

const reputationResult = document.getElementById("reputation-result");
const reputationBadge = document.getElementById("reputation-badge");
const reputationSummary = document.getElementById("reputation-summary");
const reputationGrid = document.getElementById("reputation-grid");
const crowdsecLimitAlert = document.getElementById("crowdsec-limit-alert");
const startReputationButton = document.getElementById("start-reputation");
const reputationSourceSelect = document.getElementById("reputation-source");

const whoisResult = document.getElementById("whois-result");
const whoisGrid = document.getElementById("whois-grid");
const whoisRaw = document.getElementById("whois-raw");
const whoisLink = document.getElementById("whois-link");

const dnsResult = document.getElementById("dns-result");
const subdomainsCount = document.getElementById("subdomains-count");
const subdomainsList = document.getElementById("subdomains-list");
const resolveVisibleButton = document.getElementById("resolve-visible");
const resolveProgress = document.getElementById("resolve-progress");
const resolveProgressFill = document.getElementById("resolve-progress-fill");
const resolveProgressText = document.getElementById("resolve-progress-text");
const resolveTableWrap = document.getElementById("resolve-table-wrap");
const resolveTableBody = document.getElementById("resolve-table-body");
const resolveDetail = document.getElementById("resolve-detail");
const riskFilter = document.getElementById("risk-filter");
const resolveShowAllButton = document.getElementById("resolve-show-all");

const scanResult = document.getElementById("scan-result");
const scanPhase = document.getElementById("scan-phase");
const scanSummary = document.getElementById("scan-summary");
const knownPortsInfo = document.getElementById("known-ports-info");
const knownPortsCount = document.getElementById("known-ports-count");
const knownPortsList = document.getElementById("known-ports-list");
const toggleKnownPortsButton = document.getElementById("toggle-known-ports");
const openPortsEl = document.getElementById("open-ports");
const continueArea = document.getElementById("continue-area");
const continueButton = document.getElementById("continue-scan");
const abortContinueButton = document.getElementById("abort-continue-scan");
const restProgress = document.getElementById("rest-progress");
const restProgressFill = document.getElementById("rest-progress-fill");
const restProgressText = document.getElementById("rest-progress-text");
const startKnownButton = document.getElementById("start-known-scan");
const loadGeoButton = document.getElementById("load-geo");

const singlePortCheck = document.getElementById("single-port-check");
const singlePortLabel = document.getElementById("single-port-label");
const singlePortInput = document.getElementById("single-port-input");
const singlePortButton = document.getElementById("single-port-button");
const singlePortResult = document.getElementById("single-port-result");
const exportJsonButton = document.getElementById("export-json");
const openConfigButton = document.getElementById("open-config");
const newAnalysisButton = document.getElementById("new-analysis");
const historyList = document.getElementById("history-list");
const historyEmpty = document.getElementById("history-empty");
const readonlyBanner = document.getElementById("readonly-banner");
const centerContent = document.querySelector(".center-content");
const startPanel = document.getElementById("start-panel");
const historyScanColumns = document.getElementById("history-scan-columns");
const languageToggle = document.getElementById("language-toggle");
const configPanel = document.getElementById("config-panel");
const debugPanel = document.getElementById("debug-panel");
const configLock = document.getElementById("config-lock");
const configForm = document.getElementById("config-form");
const unlockConfigButton = document.getElementById("unlock-config");
const saveConfigButton = document.getElementById("save-config");
const configPasswordInput = document.getElementById("config-password");
const configSiteTitleInput = document.getElementById("config-site-title");
const configCrowdsecInput = document.getElementById("config-crowdsec");
const configCrowdsecState = document.getElementById("config-crowdsec-state");
const configHistoryLimitInput = document.getElementById("config-history-limit");
const configRestRateInput = document.getElementById("config-rest-rate");
const configAccessPasswordInput = document.getElementById("config-access-password");
const configGeoGeoipLiteInput = document.getElementById("config-geo-geoiplite");
const configGeoMaxmindInput = document.getElementById("config-geo-maxmind");
const configGeoGeoip2NodeInput = document.getElementById("config-geo-geoip2node");
const configRepDnsblInput = document.getElementById("config-rep-dnsbl");
const configRepPrivacyInput = document.getElementById("config-rep-privacy");
const configRepCommunityInput = document.getElementById("config-rep-community");
const configRepCrowdsecInput = document.getElementById("config-rep-crowdsec");
const configAccessState = document.getElementById("config-access-state");
const configClearAccessButton = document.getElementById("config-clear-access");
const debugRunButton = document.getElementById("debug-run");
const debugTestIpInput = document.getElementById("debug-test-ip");
const debugTestDomainInput = document.getElementById("debug-test-domain");
const debugResults = document.getElementById("debug-results");
const configLogoFileInput = document.getElementById("config-logo-file");
const configFaviconFileInput = document.getElementById("config-favicon-file");
const configLogoName = document.getElementById("config-logo-name");
const configFaviconName = document.getElementById("config-favicon-name");
const geoActions = document.getElementById("geo-actions");
const dnsActions = document.querySelector(".dns-actions");
const reputationActions = document.querySelector("#reputation-result .geo-actions");
const scanActions = document.getElementById("port-scan-actions");
const continueActions = document.querySelector(".continue-actions");
const singlePortRow = document.querySelector(".single-port-row");
const knownPortsTopButton = document.querySelector(".known-ports-top button");

const readonlyActionElements = [
  geoActions,
  dnsActions,
  reputationActions,
  scanActions,
  continueActions,
  singlePortRow,
  knownPortsTopButton,
].filter(Boolean);

let activeIp = "";
let knownOpenPorts = [];
let lastKnownScannedPorts = [];
let lastAnalysis = null;
let knownPortsCatalog = [];
let selectedKnownPorts = new Set();
let activeRootDomain = "";
let selectedSubdomain = "";
let lastGeoData = null;
let lastGeoMeta = null;
let lastKnownScanData = null;
let lastFullScanData = null;
let lastSinglePortChecks = [];
let lastReputationData = null;
let subdomainResolutionMap = {};
let selectedResolveRow = "";
let lastResolveRows = [];
let focusedResolveSubdomain = "";
let subdomainStatusMap = {};
let pendingSubdomainListRender = false;
let continueScanController = null;
let restScanTotalPorts = 0;
let lastRestEstimatedDone = 0;
let scannedRestPorts = [];
let openRestPorts = [];
let scanHistory = [];
let activeScanHistoryId = null;
const HISTORY_STORAGE_KEY = "huether_scan_history_v2";
const HISTORY_RETENTION_MS = 14 * 24 * 60 * 60 * 1000;
let historyMaxItems = 10;
let historyPersistTimer = null;
let historyPersistInFlight = false;
let historyPersistQueued = false;
let isHistoryReadonly = false;
let currentLanguage = localStorage.getItem("huether_lang") || "de";
let pendingLogoDataUrl = "";
let pendingFaviconDataUrl = "";
let hasCrowdSecKey = false;
let configUnlocked = false;
let configUnlockPassword = "";
let localesRegistry = {};
let restPortsPerSecond = 2;
let clearAccessPasswordRequested = false;
let hasSavedAccessPassword = false;

const I18N = {
  de: {
    actions: "Aktionen",
    language: "Sprache",
    history: "Historie",
    latestScans: "Letzte Scans",
    noScans: "Noch keine Scans vorhanden.",
    heroTitle: "GeoIP, WHOIS, Reputation und optionaler Portscan bis 6500",
    heroSubline:
      "Trage eine IPv4-Adresse oder Domain ein und erhalte nach kurzer Ladezeit Standortdaten, Provider-Infos, WHOIS-Auszug, Reputation und auf Wunsch einen mehrstufigen Portscan.",
    heroHint: "Hinweis: Portscans nur auf Systemen durchführen, für die du berechtigt bist.",
    analyzeStart: "Analyse starten",
    whoisTitle: "WHOIS & Domain-Daten",
    dnsTitle: "DNS & Subdomains",
    geoTitle: "GeoIP Ergebnis",
    reputationTitle: "Reputation",
    scanTitle: "Portscan",
    filter: "Filter:",
    resolveAll: "Alle sichtbaren auflösen",
    showAllHosts: "Alle Hosts zeigen",
    startKnown: "Bekannte Ports scannen",
    continueScan: "Ja, restliche Ports scannen",
    abortScan: "Restscan abbrechen",
    loadGeo: "GeoIP jetzt laden",
    checkPorts: "Port(s) prüfen",
    config: "Config",
    configTitle: "Konfiguration",
    configHint: "Passe Branding und Integrationen an. Änderungen werden verschlüsselt gespeichert.",
    saveConfig: "Config speichern",
    unlockConfig: "Entsperren",
    configPassword: "Passwort",
    configHistoryLimit: "Gespeicherte Scans (max)",
    configRestRate: "Restscan Geschwindigkeit (Ports/Sek)",
    configGeoSources: "GeoIP Quellen erlauben",
    configAccessPassword: "Seiten-Passwort (optional)",
    configLogo: "Logo Upload",
    configFavicon: "Favicon Upload",
    noFile: "Keine Datei ausgewählt.",
    manualChecked: "Manuell geprufte Ports aus diesem Scan",
    readonlyTitle: "Historischer Scan",
    readonlyNote: "Read-Only Modus aktiv. Interaktionen sind deaktiviert. Nutze \"Neue Analyse\" für Live-Daten.",
    siteTitleLabel: "Seitentitel",
    crowdsecTokenLabel: "CrowdSec API-Token",
    debugTitle: "Debug",
    debugHint: "Teste GeoIP, WHOIS und Reputation-Provider in einem Lauf.",
    debugIpLabel: "Test-IP",
    debugDomainLabel: "Test-Domain",
    debugRun: "Provider testen",
    newAnalysis: "Neue Analyse",
    exportJson: "Export JSON",
    whoisOpen: "whois.com öffnen",
    riskAll: "Alle",
    riskHighOnly: "Nur High Risk",
    riskMediumPlus: "Ab Medium",
    riskWithoutTls: "Ohne TLS",
    repDnsblFocus: "DNSBL Fokus",
    repPrivacyFocus: "VPN/Proxy Fokus",
    repCommunityFocus: "Community Fokus",
    repCrowdsecFocus: "CrowdSec Fokus",
    resolveTableHistory: "Historie",
    knownPortsIntro: "Diese bekannten Ports werden in Stufe 1 geprüft:",
    continuePrompt: "Die bekannten Ports wurden gescannt. Soll jetzt der Rest bis Port 6500 geprüft werden?",
    singlePortHint: "Einzelne Ports prüfen (z. B. 22 oder 80,443,8080)",
    singlePortInputPlaceholder: "22 oder 80,443,8080",
    accessPlaceholder: "leer = deaktiviert",
    clearLater: "Wird beim Speichern entfernt",
    stateNew: "neu",
    stateSaved: "gespeichert",
    stateNotSet: "Nicht gesetzt.",
    closeNotification: "Benachrichtigung schließen",
    crowdsecLimitReached: "CrowdSec API-Limit erreicht. Bitte später erneut versuchen oder API-Plan/Limit prüfen.",
    ispUnavailable: "Nicht verfügbar",
  },
  en: {
    actions: "Actions",
    language: "Language",
    history: "History",
    latestScans: "Recent Scans",
    noScans: "No scans yet.",
    heroTitle: "GeoIP, WHOIS, reputation and optional port scan up to 6500",
    heroSubline:
      "Enter an IPv4 address or domain and get location data, provider info, WHOIS details, reputation, and optional staged port scan results.",
    heroHint: "Note: Only scan systems you are authorized to test.",
    analyzeStart: "Start Analysis",
    whoisTitle: "WHOIS & Domain Data",
    dnsTitle: "DNS & Subdomains",
    geoTitle: "GeoIP Result",
    reputationTitle: "Reputation",
    scanTitle: "Port Scan",
    filter: "Filter:",
    resolveAll: "Resolve visible hosts",
    showAllHosts: "Show all hosts",
    startKnown: "Scan known ports",
    continueScan: "Yes, scan remaining ports",
    abortScan: "Abort remaining scan",
    loadGeo: "Load GeoIP now",
    checkPorts: "Check port(s)",
    config: "Config",
    configTitle: "Configuration",
    configHint: "Adjust branding and integrations. Changes are stored encrypted.",
    saveConfig: "Save config",
    unlockConfig: "Unlock",
    configPassword: "Password",
    configHistoryLimit: "Stored scans (max)",
    configRestRate: "Remaining scan speed (ports/sec)",
    configGeoSources: "Allowed GeoIP sources",
    configAccessPassword: "Site password (optional)",
    configLogo: "Logo upload",
    configFavicon: "Favicon upload",
    noFile: "No file selected.",
    manualChecked: "Manually checked ports from this scan",
    readonlyTitle: "Historical Scan",
    readonlyNote: "Read-only mode active. Interactions are disabled. Use \"New Analysis\" for live data.",
    siteTitleLabel: "Site title",
    crowdsecTokenLabel: "CrowdSec API token",
    debugTitle: "Debug",
    debugHint: "Run one test for GeoIP, WHOIS and reputation providers.",
    debugIpLabel: "Test IP",
    debugDomainLabel: "Test domain",
    debugRun: "Run provider test",
    newAnalysis: "New Analysis",
    exportJson: "Export JSON",
    whoisOpen: "open whois.com",
    riskAll: "All",
    riskHighOnly: "High risk only",
    riskMediumPlus: "Medium and above",
    riskWithoutTls: "Without TLS",
    repDnsblFocus: "DNSBL focus",
    repPrivacyFocus: "VPN/Proxy focus",
    repCommunityFocus: "Community focus",
    repCrowdsecFocus: "CrowdSec focus",
    resolveTableHistory: "History",
    knownPortsIntro: "These known ports are checked in stage 1:",
    continuePrompt: "Known ports were scanned. Do you want to scan the rest up to port 6500 now?",
    singlePortHint: "Check individual ports (e.g. 22 or 80,443,8080)",
    singlePortInputPlaceholder: "22 or 80,443,8080",
    accessPlaceholder: "empty = disabled",
    clearLater: "Will be removed on save",
    stateNew: "new",
    stateSaved: "saved",
    stateNotSet: "Not set.",
    closeNotification: "Close notification",
    crowdsecLimitReached: "CrowdSec API limit reached. Please try again later or check your API plan/limits.",
    ispUnavailable: "Unavailable",
  },
};

I18N.nl = { ...I18N.en };
I18N.fr = { ...I18N.en };

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const target = ipInput.value.trim();
  if (!target) {
    showStatus("Bitte eine IPv4-Adresse oder Domain eingeben.", true);
    return;
  }

  setHistoryQueryParam("");
  setHistoryReadOnly(false);
  resetView();
  setAnalyzeLoading(true);

  try {
    showStatus("Analysiere Ziel ...");
    const [analysis] = await Promise.all([postJson("/api/analyze", { target }), delay(700)]);

    lastAnalysis = analysis;
    activeIp = analysis.ip;
    activeRootDomain = analysis.domain || "";

    renderWhois(analysis);
    renderDomainDns(analysis);
    prepareManualActions(analysis);
    setStartPanelVisible(false);

    if (analysis.targetType === "ip") {
      await loadGeoData(false);
      showStatus(currentLanguage === "en" ? "GeoIP loaded. You can now start port scans manually." : "GeoIP geladen. Portscan kann jetzt manuell gestartet werden.");
    } else {
      showStatus(currentLanguage === "en" ? "WHOIS loaded. You can now manually start GeoIP and port scans." : "WHOIS geladen. Optional kannst du jetzt GeoIP und Portscans manuell starten.");
    }

    startScanHistoryRecord(analysis);
    addHistoryEntry(`Analyse gestartet: ${analysis.input}`);
  } catch (error) {
    showStatus(error.message || "Fehler bei der Analyse.", true);
  } finally {
    setAnalyzeLoading(false);
  }
});

languageToggle.addEventListener("change", () => {
  const selected = String(languageToggle.value || "de").trim().toLowerCase();
  currentLanguage = selected || "de";
  localStorage.setItem("huether_lang", currentLanguage);
  applyLanguage();
  renderHistoryList();
});

openConfigButton.addEventListener("click", async () => {
  setHistoryReadOnly(false);
  resetView();
  setStartPanelVisible(false);
  configPanel.classList.remove("hidden");
  debugPanel.classList.remove("hidden");
  configUnlocked = false;
  configUnlockPassword = "";
  clearAccessPasswordRequested = false;
  configPasswordInput.value = "";
  configLock.classList.remove("hidden");
  configForm.classList.add("hidden");
  await loadConfigPublic();
  showStatus(currentLanguage === "en" ? "Configuration panel opened." : "Konfigurationsbereich geöffnet.");
});

unlockConfigButton.addEventListener("click", async () => {
  const password = configPasswordInput.value.trim();
  if (!password) {
    showStatus(currentLanguage === "en" ? "Please enter the resolver password." : "Bitte Resolver-Passwort eingeben.", true);
    return;
  }

  unlockConfigButton.disabled = true;
  unlockConfigButton.classList.add("is-loading");
  try {
    const payload = await postJson("/api/config/open", { password });
    configUnlocked = true;
    configUnlockPassword = password;
    configLock.classList.add("hidden");
    configForm.classList.remove("hidden");
    configSiteTitleInput.value = payload?.config?.title || configSiteTitleInput.value;
    autoSizeTitleInput();
    const unlockedLimit = Math.max(1, Math.min(200, Number(payload?.config?.historyMaxEntries) || 10));
    historyMaxItems = unlockedLimit;
    configHistoryLimitInput.value = String(unlockedLimit);
    const unlockedRate = Math.max(1, Math.min(2000, Number(payload?.config?.restPortsPerSecond) || 2));
    restPortsPerSecond = unlockedRate;
    configRestRateInput.value = String(unlockedRate);
    const unlockedGeo = Array.isArray(payload?.config?.allowedGeoSources)
      ? payload.config.allowedGeoSources
      : ["geoiplite", "maxmind", "geoip2node"];
    configGeoGeoipLiteInput.checked = unlockedGeo.includes("geoiplite");
    configGeoMaxmindInput.checked = unlockedGeo.includes("maxmind");
    configGeoGeoip2NodeInput.checked = unlockedGeo.includes("geoip2node");
    if (!configGeoGeoipLiteInput.checked && !configGeoMaxmindInput.checked && !configGeoGeoip2NodeInput.checked) {
      configGeoGeoipLiteInput.checked = true;
    }
    applyGeoSourceVisibility(unlockedGeo);
    const unlockedRep = Array.isArray(payload?.config?.allowedReputationSources)
      ? payload.config.allowedReputationSources
      : ["dnsbl", "privacy", "community", "crowdsec"];
    applyReputationSourceChecks(unlockedRep);
    applyReputationSourceVisibility(getSelectedReputationSources());
    hasSavedAccessPassword = Boolean(payload?.config?.hasAccessPassword);
    updateAccessPasswordState(hasSavedAccessPassword);
    hasCrowdSecKey = Boolean(payload?.config?.hasCrowdSecKey);
    updateCrowdSecMaskState();
    showStatus(currentLanguage === "en" ? "Configuration unlocked." : "Konfiguration entsperrt.");
  } catch (error) {
    showStatus(error.message || (currentLanguage === "en" ? "Unlock failed." : "Entsperren fehlgeschlagen."), true);
  } finally {
    unlockConfigButton.disabled = false;
    unlockConfigButton.classList.remove("is-loading");
  }
});

saveConfigButton.addEventListener("click", async () => {
  if (!configUnlocked || !configUnlockPassword) {
    showStatus(currentLanguage === "en" ? "Please unlock config first." : "Bitte zuerst die Konfiguration entsperren.", true);
    return;
  }

  saveConfigButton.disabled = true;
  saveConfigButton.classList.add("is-loading");
  saveConfigButton.textContent = currentLanguage === "en" ? "Saving ..." : "Speichere ...";

  try {
    const payload = {
      password: configUnlockPassword,
      title: configSiteTitleInput.value.trim(),
      crowdsecApiKey: configCrowdsecInput.value.trim(),
      historyMaxEntries: Number(configHistoryLimitInput.value || 10),
      restPortsPerSecond: Number(configRestRateInput.value || 2),
      allowedGeoSources: [
        ...(configGeoGeoipLiteInput.checked ? ["geoiplite"] : []),
        ...(configGeoMaxmindInput.checked ? ["maxmind"] : []),
        ...(configGeoGeoip2NodeInput.checked ? ["geoip2node"] : []),
      ],
      allowedReputationSources: getSelectedReputationSources(),
      accessPassword: configAccessPasswordInput.value,
      clearAccessPassword: clearAccessPasswordRequested,
      logoDataUrl: pendingLogoDataUrl,
      faviconDataUrl: pendingFaviconDataUrl,
    };

    await postJson("/api/config/save", payload);
    await loadBranding();
    await loadConfigPublic();
    showStatus(currentLanguage === "en" ? "Configuration saved." : "Konfiguration gespeichert.");
    pendingLogoDataUrl = "";
    pendingFaviconDataUrl = "";
    configLogoFileInput.value = "";
    configFaviconFileInput.value = "";
    clearAccessPasswordRequested = false;
  } catch (error) {
    showStatus(error.message || (currentLanguage === "en" ? "Configuration save failed." : "Konfiguration konnte nicht gespeichert werden."), true);
  } finally {
    saveConfigButton.disabled = false;
    saveConfigButton.classList.remove("is-loading");
    saveConfigButton.textContent = t("saveConfig");
  }
});

configLogoFileInput.addEventListener("change", async () => {
  const file = configLogoFileInput.files?.[0] || null;
  pendingLogoDataUrl = await readFileAsDataUrl(file);
  configLogoName.textContent = file ? file.name : t("noFile");
});

configFaviconFileInput.addEventListener("change", async () => {
  const file = configFaviconFileInput.files?.[0] || null;
  pendingFaviconDataUrl = await readFileAsDataUrl(file);
  configFaviconName.textContent = file ? file.name : t("noFile");
});

configSiteTitleInput.addEventListener("input", () => {
  autoSizeTitleInput();
});

configCrowdsecInput.addEventListener("input", () => {
  updateCrowdSecMaskState();
});

configAccessPasswordInput.addEventListener("input", () => {
  clearAccessPasswordRequested = false;
  const typed = String(configAccessPasswordInput.value || "").trim();
  if (!typed) {
    return;
  }
  const stars = "*".repeat(Math.max(6, Math.min(18, typed.length)));
  configAccessState.textContent = `${stars} (${t("stateNew")})`;
  if (hasSavedAccessPassword) {
    configClearAccessButton.classList.remove("hidden");
  }
});

configClearAccessButton.addEventListener("click", () => {
  clearAccessPasswordRequested = true;
  hasSavedAccessPassword = false;
  configAccessPasswordInput.value = "";
  configAccessState.textContent = t("clearLater");
  configClearAccessButton.classList.add("hidden");
});

debugRunButton.addEventListener("click", async () => {
  const ip = String(debugTestIpInput.value || "").trim();
  const domain = String(debugTestDomainInput.value || "").trim();
  if (!ip || !domain) {
    showStatus(currentLanguage === "en" ? "Please enter test IP and domain." : "Bitte Test-IP und Test-Domain eingeben.", true);
    return;
  }

  debugRunButton.disabled = true;
  debugRunButton.classList.add("is-loading");
  try {
    const payload = await postJson("/api/config/debug/test", { ip, domain });
    const rows = [];
    const add = (name, ok, reason = "") => {
      const label = reason ? debugReasonText(reason, ok) : (ok ? "OK" : (currentLanguage === "de" ? "Fehler" : currentLanguage === "fr" ? "Échec" : currentLanguage === "nl" ? "Mislukt" : "Fail"));
      rows.push(`<article class="cell"><span class="label">${escapeHtml(name)}</span><span class="value">${ok ? "✓" : "✕"} ${escapeHtml(label)}</span></article>`);
    };

    (payload.geoip || []).forEach((entry) => {
      const reason = [entry.enabled === false ? "disabled_in_config" : "", entry.reason || ""].filter(Boolean).join(" | ");
      add(`GeoIP: ${entry.source}`, entry.ok, reason);
    });
    (payload.whois || []).forEach((entry) => add(`WHOIS: ${entry.provider}`, entry.ok, entry.reason || ""));
    (payload.reputation || []).forEach((entry) => add(`Reputation: ${entry.provider}`, entry.ok, entry.reason || ""));
    debugResults.innerHTML = rows.join("");
  } catch (error) {
    showStatus(error.message || "Debug-Test fehlgeschlagen.", true);
  } finally {
    debugRunButton.disabled = false;
    debugRunButton.classList.remove("is-loading");
  }
});

newAnalysisButton.addEventListener("click", () => {
  setHistoryReadOnly(false);
  resetView();
  setStartPanelVisible(true);
  activeScanHistoryId = null;
  setHistoryQueryParam("");
  renderHistoryList();
  ipInput.focus();
  window.scrollTo({ top: 0, behavior: "smooth" });
});

historyList.addEventListener("click", (event) => {
  const viewButton = event.target.closest("button[data-view-id]");
  if (viewButton) {
    const id = viewButton.dataset.viewId;
    if (!id) {
      return;
    }
    loadHistoryScan(id);
    return;
  }

  const downloadButton = event.target.closest("button[data-download-id]");
  if (downloadButton) {
    const id = downloadButton.dataset.downloadId;
    if (!id) {
      return;
    }
    downloadHistoryScan(id);
    return;
  }

  const shareButton = event.target.closest("button[data-share-id]");
  if (!shareButton) {
    return;
  }

  const id = shareButton.dataset.shareId;
  if (!id) {
    return;
  }
  shareHistoryScan(id);
});

subdomainsList.addEventListener("click", async (event) => {
  const trigger = event.target.closest("button[data-subdomain]");
  if (!trigger || !activeRootDomain) {
    return;
  }

  const subdomain = trigger.dataset.subdomain;
  selectedSubdomain = subdomain;
  subdomainStatusMap[subdomain] = "loading";
  renderSubdomainList(lastAnalysis?.domainIntel?.subdomains || []);
  focusedResolveSubdomain = "";
  resolveShowAllButton.classList.add("hidden");
  subdomainResolutionMap = {};
  lastResolveRows = [];
  selectedResolveRow = "";
  renderResolveTable([]);
  renderResolveDetail(null);
  showStatus(`Löse ${subdomain} auf ...`);

  try {
    const response = await postJson("/api/subdomain/resolve", {
      subdomain,
      rootDomain: activeRootDomain,
    });
    subdomainResolutionMap = { [subdomain]: response };
    const hasRecords = hasAddressRecord(response.records);
    subdomainStatusMap[subdomain] = hasRecords ? "success" : "no-record";
    selectedResolveRow = "";
    lastResolveRows = [response];
    if (hasRecords) {
      renderResolveTable(lastResolveRows);
      renderResolveDetail(null);
      showStatus(`${subdomain} erfolgreich aufgelöst.`);
      addHistoryEntry(`Subdomain geprüft: ${subdomain}`);
    } else {
      renderResolveTable([]);
      renderResolveError(
        `${subdomain} konnte nicht verwertbar aufgelöst werden, weil kein A-, AAAA- oder CNAME-Record gefunden wurde.`
      );
      showStatus(
        `${subdomain} konnte nicht verwertbar aufgelöst werden (kein A/AAAA/CNAME-Record).`,
        true
      );
      addHistoryEntry(`Subdomain ohne Records: ${subdomain}`);
    }
    renderSubdomainList(lastAnalysis?.domainIntel?.subdomains || []);
  } catch (error) {
    subdomainStatusMap[subdomain] = "error";
    renderResolveTable([]);
    renderResolveError(
      `${subdomain} konnte nicht aufgelöst werden. Grund: ${error.message || "Unbekannter Fehler"}`
    );
    renderSubdomainList(lastAnalysis?.domainIntel?.subdomains || []);
    showStatus(error.message || (currentLanguage === "en" ? "Resolution failed." : "Auflösung fehlgeschlagen."), true);
    addHistoryEntry(`Subdomain-Fehler: ${subdomain}`);
  }
});

resolveVisibleButton.addEventListener("click", async () => {
  const subdomains = lastAnalysis?.domainIntel?.subdomains || [];
  if (!subdomains.length || !activeRootDomain) {
    setResolveProgressVisible(false);
    showStatus(currentLanguage === "en" ? "No subdomains available to resolve." : "Keine Subdomains zum Auflösen vorhanden.", true);
    return;
  }

  resolveVisibleButton.disabled = true;
  resolveVisibleButton.textContent = currentLanguage === "en" ? "Resolving ..." : "Auflösung läuft ...";
  subdomainResolutionMap = {};
  selectedResolveRow = "";
  lastResolveRows = [];
  focusedResolveSubdomain = "";
  resolveShowAllButton.classList.add("hidden");
  subdomainStatusMap = Object.fromEntries(subdomains.map((name) => [name, "loading"]));
  scheduleSubdomainListRender();
  renderResolveTable([]);
  renderResolveDetail(null);
  setResolveProgressVisible(true);
  setResolveProgress(0, subdomains.length);

  let completed = 0;
  const results = await Promise.all(
    subdomains.map(async (subdomain) => {
      try {
        const response = await postJson("/api/subdomain/resolve", {
          subdomain,
          rootDomain: activeRootDomain,
        });
        subdomainResolutionMap[subdomain] = response;
        subdomainStatusMap[subdomain] = hasAddressRecord(response.records) ? "success" : "no-record";
        completed += 1;
        setResolveProgress(completed, subdomains.length);
        scheduleSubdomainListRender();
        return { subdomain, ok: true, data: response };
      } catch (error) {
        subdomainStatusMap[subdomain] = "error";
        completed += 1;
        setResolveProgress(completed, subdomains.length);
        scheduleSubdomainListRender();
        return { subdomain, ok: false };
      }
    })
  );

  const successful = results.filter((entry) => entry.ok);
  const withRecords = successful.filter((entry) => {
    const records = entry.data?.records || {};
    return (records.A || []).length || (records.AAAA || []).length || (records.CNAME || []).length;
  });

  lastResolveRows = successful.map((entry) => entry.data);
  scheduleSubdomainListRender();
  renderResolveTable(lastResolveRows);
  renderResolveDetail(null);
  showStatus(`${withRecords.length} erfolgreiche Auflösungen werden in der Tabelle angezeigt.`);
  addHistoryEntry(`Subdomains Batch: ${withRecords.length} mit Records`);

  const unresolvedHosts = [
    ...results.filter((entry) => !entry.ok).map((entry) => entry.subdomain),
    ...successful
      .filter((entry) => !hasAddressRecord(entry.data?.records))
      .map((entry) => entry.subdomain),
  ];

  if (unresolvedHosts.length) {
    const sample = unresolvedHosts.slice(0, 6).join(", ");
    const suffix = unresolvedHosts.length > 6 ? ` (+${unresolvedHosts.length - 6} weitere)` : "";
    showStatus(
      `${unresolvedHosts.length} Hosts konnten nicht verwertbar aufgelöst werden: ${sample}${suffix}`,
      true
    );
  }

  resolveVisibleButton.disabled = false;
  resolveVisibleButton.textContent = t("resolveAll");
  setResolveProgressVisible(false);
});

riskFilter.addEventListener("change", () => {
  focusedResolveSubdomain = "";
  resolveShowAllButton.classList.add("hidden");
  renderResolveTable(lastResolveRows);
  const visibleRows = applyRiskFilter(lastResolveRows, riskFilter.value);
  const stillVisible = visibleRows.some((row) => row?.subdomain === selectedResolveRow);
  if (selectedResolveRow && stillVisible) {
    renderResolveDetail(subdomainResolutionMap[selectedResolveRow] || null);
  } else {
    renderResolveDetail(null);
  }
});

resolveTableBody.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-detail-subdomain]");
  if (!button) {
    return;
  }

  const subdomain = button.dataset.detailSubdomain;
  const entry = subdomainResolutionMap[subdomain];
  if (!entry) {
    return;
  }

  selectedResolveRow = subdomain;
  focusedResolveSubdomain = subdomain;
  resolveShowAllButton.classList.remove("hidden");
  renderResolveTable(lastResolveRows);
  renderResolveDetail(entry);
});

resolveShowAllButton.addEventListener("click", () => {
  focusedResolveSubdomain = "";
  selectedResolveRow = "";
  resolveShowAllButton.classList.add("hidden");
  renderResolveTable(lastResolveRows);
  renderResolveDetail(null);
});

if (exportJsonButton) {
  exportJsonButton.addEventListener("click", () => {
    if (!lastAnalysis) {
      showStatus("Noch keine Analyse zum Export vorhanden.", true);
      return;
    }

    const payload = {
      exportedAt: new Date().toISOString(),
      source: "DNS / IP-Resolver",
      input: lastAnalysis.input,
      targetType: lastAnalysis.targetType,
      domain: lastAnalysis.domain,
      ip: lastAnalysis.ip,
      resolvedIps: lastAnalysis.resolvedIps,
      geo: lastGeoData,
      whois: lastAnalysis.whois,
      subdomains: lastAnalysis.domainIntel?.subdomains || [],
      subdomainResolutions: subdomainResolutionMap,
      reputation: lastReputationData,
      selectedKnownPorts: Array.from(selectedKnownPorts).sort((a, b) => a - b),
      knownScan: lastKnownScanData,
      fullScan: lastFullScanData,
      singlePortChecks: lastSinglePortChecks,
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `huether-scan-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);

    showStatus("JSON-Export erstellt.");
    addHistoryEntry("Export: JSON");
  });
}

startReputationButton.addEventListener("click", async () => {
  if (!activeIp) {
    showStatus("Bitte zuerst ein Ziel analysieren.", true);
    return;
  }

  startReputationButton.disabled = true;
  startReputationButton.classList.add("is-loading");
  startReputationButton.textContent = currentLanguage === "en" ? "Checking ..." : "Prüfe ...";
  reputationBadge.textContent = currentLanguage === "en" ? "Loading" : "Lädt";
  reputationBadge.className = "phase-badge";

  try {
    const report = await postJson("/api/reputation", {
      ip: activeIp,
      domain: lastAnalysis?.domain || null,
      source: reputationSourceSelect.value,
    });
    lastReputationData = report;
    renderReputation(report);
    showStatus(currentLanguage === "en" ? "Reputation loaded successfully." : "Reputation erfolgreich geladen.");
    addHistoryEntry(`Reputation: ${reputationModeLabel(report.mode)}`);
  } catch (error) {
    showStatus(error.message || (currentLanguage === "en" ? "Reputation check failed." : "Reputation-Prüfung fehlgeschlagen."), true);
  } finally {
    startReputationButton.disabled = false;
    startReputationButton.classList.remove("is-loading");
    startReputationButton.textContent = currentLanguage === "en" ? "Check reputation" : "Reputation prüfen";
  }
});

reputationSourceSelect.addEventListener("change", () => {
  if (!activeIp || !lastAnalysis) {
    return;
  }
  startReputationButton.click();
});

loadGeoButton.addEventListener("click", async () => {
  await loadGeoData(true);
});

geoSourceSelect.addEventListener("change", async () => {
  if (!lastAnalysis || lastAnalysis.targetType !== "ip") {
    return;
  }
  await loadGeoData(true);
});

startKnownButton.addEventListener("click", async () => {
  if (!activeIp) {
    showStatus("Bitte zuerst ein Ziel analysieren.", true);
    return;
  }

  const selectedPorts = Array.from(selectedKnownPorts).sort((a, b) => a - b);
  if (!selectedPorts.length) {
    showStatus(currentLanguage === "en" ? "Please select at least one known port." : "Bitte mindestens einen bekannten Port auswählen.", true);
    return;
  }

  scannedRestPorts = [];
  openRestPorts = [];
  lastFullScanData = null;

  startKnownButton.disabled = true;
  startKnownButton.textContent = currentLanguage === "en" ? "Scanning ..." : "Scan läuft ...";
  startKnownButton.classList.add("is-loading");
  scanPhase.textContent = "Stufe 1: Bekannte Ports";

  try {
    showStatus(currentLanguage === "en" ? "Scanning known ports ..." : "Scanne bekannte Ports ...");
    const scanData = await postJson("/api/scan/start", { ip: activeIp, ports: selectedPorts });
    knownOpenPorts = scanData.openPorts || [];
    lastKnownScannedPorts = scanData.selectedKnownPorts || selectedPorts;
    renderKnownScan(scanData);
    showStatus("Bekannte Ports gescannt. Optional: Rest bis Port 6500 scannen.");
    addHistoryEntry("Portscan: bekannte Ports");
  } catch (error) {
    showStatus(error.message || "Fehler beim Portscan.", true);
  } finally {
    startKnownButton.disabled = false;
    startKnownButton.textContent = t("startKnown");
    startKnownButton.classList.remove("is-loading");
  }
});

continueButton.addEventListener("click", async () => {
  if (!activeIp) {
    return;
  }

  continueButton.disabled = true;
  continueButton.textContent = currentLanguage === "en" ? "Scanning ..." : "Scan läuft ...";
  continueButton.classList.add("is-loading");
  abortContinueButton.classList.remove("hidden");
  abortContinueButton.disabled = false;
  continueScanController = new AbortController();
  const totalRestPorts = Math.max(0, 6500 - (lastKnownScannedPorts?.length || 0));
  const alreadyScanned = new Set([...(lastKnownScannedPorts || []), ...scannedRestPorts]);
  const skipPorts = Array.from(alreadyScanned).sort((a, b) => a - b);
  const remainingPorts = Array.from({ length: 6500 }, (_, idx) => idx + 1).filter((port) => !alreadyScanned.has(port));
  const chunkSize = Math.max(1, Math.min(200, Math.floor(restPortsPerSecond || 2)));
  let abortedByUser = false;
  startRestScanProgress(totalRestPorts, scannedRestPorts.length);

  try {
    showStatus(currentLanguage === "en" ? "Scanning remaining ports up to 6500 ..." : "Scanne restliche Ports bis 6500 ...");

    for (let offset = 0; offset < remainingPorts.length; offset += chunkSize) {
      if (continueScanController.signal.aborted) {
        abortedByUser = true;
        break;
      }

      const chunk = remainingPorts.slice(offset, offset + chunkSize);
      const response = await postJson(
        "/api/scan/continue",
        { ip: activeIp, skipPorts, ports: chunk },
        { signal: continueScanController.signal }
      );

      scannedRestPorts = mergeScannedPortLists(scannedRestPorts, response?.scannedPorts || chunk);
      openRestPorts = mergePorts(openRestPorts, response?.openPorts || []);
      updateRestScanProgress(scannedRestPorts.length, totalRestPorts);
    }

    const merged = mergePorts(knownOpenPorts, openRestPorts);

    if (continueScanController.signal.aborted || abortedByUser) {
      lastFullScanData = null;
      scanResult.classList.remove("hidden");
      scanPhase.textContent = currentLanguage === "en" ? "Stage 2: Partial scan (aborted)" : "Stufe 2: Teilscan (abgebrochen)";
      scanSummary.textContent =
        currentLanguage === "en"
          ? `Remaining scan aborted. Already checked: ${scannedRestPorts.length}/${totalRestPorts} ports. Open found: ${merged.length}.`
          : `Restscan abgebrochen. Bereits geprüft: ${scannedRestPorts.length}/${totalRestPorts} Ports. Offen gefunden: ${merged.length}.`;
      renderPorts(merged);
      continueArea.classList.remove("hidden");
      showStatus(currentLanguage === "en" ? "Remaining port scan aborted." : "Restlicher Portscan wurde abgebrochen.", true);
      addHistoryEntry("Portscan: Rest abgebrochen");
    } else {
      lastFullScanData = {
        scanned: scannedRestPorts.length,
        openPorts: [...openRestPorts],
      };
      scanResult.classList.remove("hidden");
      scanPhase.textContent = currentLanguage === "en" ? "Stage 2: Full scan up to 6500" : "Stufe 2: Vollscan bis 6500";
      scanSummary.textContent =
        currentLanguage === "en"
          ? `${scannedRestPorts.length}/${totalRestPorts} remaining ports checked. ${merged.length} open ports found up to 6500.`
          : `${scannedRestPorts.length}/${totalRestPorts} restliche Ports geprüft. Insgesamt ${merged.length} offene Ports bis 6500.`;
      renderPorts(merged);
      continueArea.classList.add("hidden");
      showStatus(currentLanguage === "en" ? "Full port scan completed." : "Vollständiger Portscan abgeschlossen.");
      addHistoryEntry("Portscan: Rest vollständig");
    }
  } catch (error) {
    if (error?.name === "AbortError") {
      lastFullScanData = null;
      const merged = mergePorts(knownOpenPorts, openRestPorts);
      scanResult.classList.remove("hidden");
      scanPhase.textContent = currentLanguage === "en" ? "Stage 2: Partial scan (aborted)" : "Stufe 2: Teilscan (abgebrochen)";
      scanSummary.textContent =
        currentLanguage === "en"
          ? `Remaining scan aborted. Already checked: ${scannedRestPorts.length}/${restScanTotalPorts || "?"} ports. Open found: ${merged.length}.`
          : `Restscan abgebrochen. Bereits geprüft: ${scannedRestPorts.length}/${restScanTotalPorts || "?"} Ports. Offen gefunden: ${merged.length}.`;
      renderPorts(merged);
      continueArea.classList.remove("hidden");
      showStatus(currentLanguage === "en" ? "Remaining port scan aborted." : "Restlicher Portscan wurde abgebrochen.", true);
      addHistoryEntry("Portscan: Rest abgebrochen");
    } else {
      showStatus(error.message || "Fehler beim Vollscan.", true);
    }
  } finally {
    stopRestScanProgress();
    continueScanController = null;
    continueButton.disabled = false;
    continueButton.textContent = t("continueScan");
    continueButton.classList.remove("is-loading");
    abortContinueButton.classList.add("hidden");
  }
});

abortContinueButton.addEventListener("click", () => {
  if (continueScanController) {
    abortContinueButton.disabled = true;
    continueScanController.abort();
  }
});

knownPortsList.addEventListener("click", (event) => {
  const trigger = event.target.closest("button[data-port]");
  if (!trigger) {
    return;
  }

  const port = Number(trigger.dataset.port);
  if (!Number.isInteger(port)) {
    return;
  }

  if (selectedKnownPorts.has(port)) {
    selectedKnownPorts.delete(port);
  } else {
    selectedKnownPorts.add(port);
  }

  renderKnownPortsInfo();
});

toggleKnownPortsButton.addEventListener("click", () => {
  if (!knownPortsCatalog.length) {
    return;
  }

  if (selectedKnownPorts.size === knownPortsCatalog.length) {
    selectedKnownPorts.clear();
  } else {
    selectedKnownPorts = new Set(knownPortsCatalog.map((entry) => entry.port));
  }

  renderKnownPortsInfo();
});

singlePortButton.addEventListener("click", async () => {
  if (!activeIp) {
    singlePortFeedback("Bitte zuerst eine Analyse starten.", true);
    return;
  }

  const ports = parsePorts(singlePortInput.value);
  if (!ports.length) {
    singlePortFeedback("Bitte mindestens einen gültigen Port angeben.", true);
    return;
  }

  singlePortButton.disabled = true;
  singlePortButton.textContent = "Prüfung läuft ...";
  singlePortButton.classList.add("is-loading");
  singlePortFeedback("Prüfe angegebene Ports ...", false);

  try {
    const checks = await Promise.all(
      ports.map((port) => postJson("/api/scan/port", { ip: activeIp, port }))
    );
    lastSinglePortChecks = checks;

    const open = checks.filter((entry) => entry.open);
    const closed = checks.filter((entry) => !entry.open);
    renderSinglePortResults(checks);
    showStatus(
      `Einzelport-Prüfung: ${open.length} offen, ${closed.length} geschlossen.`
    );
    addHistoryEntry(`Portcheck: ${ports.join(",")}`);
  } catch (error) {
    singlePortFeedback(error.message || "Einzelport-Prüfung fehlgeschlagen.", true);
    showStatus(error.message || "Einzelport-Prüfung fehlgeschlagen.", true);
  } finally {
    singlePortButton.disabled = false;
    singlePortButton.textContent = "Port(s) prüfen";
    singlePortButton.classList.remove("is-loading");
  }
});

async function loadGeoData(isManual) {
  if (!activeIp || !lastAnalysis) {
    showStatus("Bitte zuerst ein Ziel analysieren.", true);
    return;
  }

  loadGeoButton.disabled = true;
  loadGeoButton.textContent = "GeoIP lädt ...";
  loadGeoButton.classList.add("is-loading");

  try {
    const source = geoSourceSelect.value;
    showStatus(`Lade GeoIP von ${geoSourceLabel(source)} ...`);
    const geoResponse = await postJson("/api/geoip", { ip: activeIp, source });
    lastGeoData = geoResponse.geo;
    lastGeoMeta = {
      requestedSource: geoResponse.requestedSource,
      usedSource: geoResponse.source,
      fallbackUsed: Boolean(geoResponse.fallbackUsed),
      attempts: geoResponse.attempts || [],
    };
    renderGeoData(lastAnalysis, geoResponse.geo);

    const limitedAttempt = Array.isArray(geoResponse.attempts)
      ? geoResponse.attempts.find((entry) => entry.reason === "rate_limited")
      : null;
    if (isManual) {
      const firstAttempt = Array.isArray(geoResponse.attempts) ? geoResponse.attempts[0] : null;
      const remoteUnsupported = firstAttempt?.reason === "remote_lookup_not_supported";
      if (limitedAttempt) {
        showStatus(
          currentLanguage === "en"
            ? `GeoIP updated (${geoResponse.geo.provider}). ${geoSourceLabel(limitedAttempt.source)} is rate-limited.`
            : `GeoIP erfolgreich aktualisiert (${geoResponse.geo.provider}). ${geoSourceLabel(limitedAttempt.source)} ist limitiert.`
          , true
        );
      } else if (remoteUnsupported) {
        showStatus(
          currentLanguage === "en"
            ? `GeoIP updated (${geoResponse.geo.provider}). GeoAPI currently supports requester IP only.`
            : `GeoIP erfolgreich aktualisiert (${geoResponse.geo.provider}). GeoAPI unterstutzt derzeit nur die anfragende IP.`
          , true
        );
      } else if (geoResponse.fallbackUsed) {
        showStatus(
          currentLanguage === "en"
            ? `GeoIP fallback used: requested ${geoSourceLabel(geoResponse.requestedSource)}, used ${geoSourceLabel(geoResponse.source)}.`
            : `GeoIP Fallback aktiv: angefordert ${geoSourceLabel(geoResponse.requestedSource)}, genutzt ${geoSourceLabel(geoResponse.source)}.`
          , true
        );
      } else {
        showStatus(`GeoIP erfolgreich aktualisiert (${geoResponse.geo.provider}).`);
      }
      addHistoryEntry(`GeoIP: ${geoResponse.geo.provider}`);
    }
  } catch (error) {
    geoProvider.textContent = `${geoSourceLabel(geoSourceSelect.value)} (${currentLanguage === "en" ? "error" : "Fehler"})`;
    geoGrid.innerHTML = createCell("Status", error.message || "GeoIP konnte nicht geladen werden.");
    geoMapWrap.classList.add("hidden");
    geoMap.removeAttribute("src");
    geoResult.classList.remove("hidden");
    showStatus(error.message || "GeoIP konnte nicht geladen werden.", true);
  } finally {
    loadGeoButton.disabled = false;
    loadGeoButton.textContent = t("loadGeo");
    loadGeoButton.classList.remove("is-loading");
  }
}

function prepareManualActions(analysis) {
  scanResult.classList.remove("hidden");
  scanPhase.textContent = currentLanguage === "en" ? "Ready" : "Bereit";
  scanSummary.textContent =
    currentLanguage === "en"
      ? `Active target IP: ${activeIp}. Start port scans manually via the button.`
      : `Aktive Ziel-IP: ${activeIp}. Portscan startest du manuell über den Button.`;

  knownPortsCatalog = analysis.knownPorts || [];
  selectedKnownPorts = new Set(knownPortsCatalog.map((entry) => entry.port));
  renderKnownPortsInfo();

  openPortsEl.innerHTML = "";
  openPortsEl.classList.add("hidden");
  continueArea.classList.add("hidden");
  singlePortCheck.classList.remove("hidden");
  lastKnownScannedPorts = [];

  if (analysis.targetType === "domain") {
    geoProvider.textContent = `${geoSourceLabel(geoSourceSelect.value)} (${currentLanguage === "en" ? "ready" : "bereit"})`;
    geoGrid.innerHTML = createCell("Status", currentLanguage === "en" ? "GeoIP not loaded yet. Please start manually." : "GeoIP noch nicht geladen. Bitte manuell starten.");
    geoResult.classList.remove("hidden");
  } else {
    geoProvider.textContent = `${geoSourceLabel(geoSourceSelect.value)} (${currentLanguage === "en" ? "loading" : "lädt"})`;
    geoGrid.innerHTML = createCell(
      "Status",
      currentLanguage === "en" ? "GeoIP loading automatically ..." : "GeoIP wird automatisch geladen ..."
    );
    geoResult.classList.remove("hidden");
  }

  loadGeoButton.classList.remove("hidden");

  reputationResult.classList.remove("hidden");
  reputationBadge.textContent = currentLanguage === "en" ? "Ready" : "Bereit";
  reputationBadge.className = "phase-badge";
  reputationSummary.textContent =
    currentLanguage === "en"
      ? `Active target IP: ${activeIp}. Run reputation checks manually via the button.`
      : `Aktive Ziel-IP: ${activeIp}. Reputation prüfst du manuell über den Button.`;
  reputationGrid.innerHTML = "";
}

function renderKnownPortsInfo() {
  if (!knownPortsCatalog.length) {
    knownPortsInfo.classList.add("hidden");
    knownPortsCount.textContent = "";
    knownPortsList.innerHTML = "";
    return;
  }

  const selectedCount = selectedKnownPorts.size;
  knownPortsCount.textContent =
    currentLanguage === "en"
      ? `${selectedCount} of ${knownPortsCatalog.length} selected`
      : `${selectedCount} von ${knownPortsCatalog.length} ausgewählt`;
  toggleKnownPortsButton.textContent =
    selectedCount === knownPortsCatalog.length
      ? currentLanguage === "en"
        ? "Deselect all"
        : "Alle abwählen"
      : currentLanguage === "en"
        ? "Select all"
        : "Alle auswählen";

  knownPortsList.innerHTML = knownPortsCatalog
    .map((entry) => {
      const enabled = selectedKnownPorts.has(entry.port);
      return `
        <button
          type="button"
          class="known-port-item ${enabled ? "selected" : "excluded"}"
          data-port="${entry.port}"
          aria-pressed="${enabled ? "true" : "false"}"
          title="${enabled ? "Wird gescannt" : "Vom Scan ausgeschlossen"}"
        >
          <span>${entry.port} (${escapeHtml(entry.service)})</span>
          <strong>${enabled ? "✓" : "✕"}</strong>
        </button>
      `;
    })
    .join("");

  knownPortsInfo.classList.remove("hidden");
}

function renderGeoData(analysis, data) {
  const resolvedIsp = data.isp || t("ispUnavailable");
  const fields = [
    ["Quelle", data.provider],
    ["Eingabe", analysis.input],
    ["Typ", analysis.targetType === "domain" ? "Domain" : "IPv4"],
    ["Primäre IP", analysis.ip],
    ["Aufgelöste IPv4", analysis.resolvedIps?.join(", ")],
    ["Kontinent", valueWithCode(data.continent, data.continentCode)],
    ["Land", valueWithCode(data.country, data.countryCode)],
    ["Region", data.region],
    ["Stadt", data.city],
    ["Postleitzahl", data.postal],
    ["Breitengrad", formatNumber(data.latitude)],
    ["Längengrad", formatNumber(data.longitude)],
    ["Zeitzone", data.timezone],
    ["Währung", valueWithCode(data.currencyName, data.currency)],
    ["ISP / ASN", valueWithCode(resolvedIsp, data.asn)],
    ["Organisation", data.organization],
    ["Domain", data.domain],
    ["Telefonvorwahl", data.phonePrefix],
    ["Flagge", data.flag],
  ];

  const fallbackBadge = lastGeoMeta?.fallbackUsed ? (currentLanguage === "en" ? " (Fallback)" : " (Fallback)") : "";
  geoProvider.textContent = `${data.provider || "GeoIP"}${fallbackBadge}`;
  geoGrid.innerHTML = fields
    .map(([label, value]) => createCell(label, value || "-"))
    .join("");

  if (data.countryFlagImage) {
    flagImage.src = data.countryFlagImage;
    flagImage.style.display = "block";
  } else {
    flagImage.style.display = "none";
  }

  renderGeoMap(data);

  geoResult.classList.remove("hidden");
}

function renderGeoMap(data) {
  const lat = Number(data?.latitude);
  const lon = Number(data?.longitude);
  const valid = Number.isFinite(lat) && Number.isFinite(lon);
  if (!valid) {
    geoMapWrap.classList.add("hidden");
    geoMap.removeAttribute("src");
    return;
  }

  geoMap.src = `https://maps.google.com/maps?q=${encodeURIComponent(`${lat},${lon}`)}&z=9&output=embed`;
  geoMapWrap.classList.remove("hidden");
}

function renderReputation(report) {
  const score = report?.score || {};
  const reasons = Array.isArray(score.reasons) ? score.reasons : [];
  const signals = report?.signals || {};
  const crowdSec = report?.sources?.crowdSec || null;
  const crowdSecRateLimited = crowdSec?.reason === "http_429" || crowdSec?.reason === "rate_limited";

  if (crowdsecLimitAlert) {
    if (crowdSecRateLimited) {
      crowdsecLimitAlert.textContent = t("crowdsecLimitReached");
      crowdsecLimitAlert.classList.remove("hidden");
      showStatus(t("crowdsecLimitReached"), true);
    } else {
      crowdsecLimitAlert.classList.add("hidden");
      crowdsecLimitAlert.textContent = "";
    }
  }

  if (crowdSecRateLimited) {
    reputationGrid.classList.add("hidden");
    reputationGrid.innerHTML = "";
    return;
  }
  reputationGrid.classList.remove("hidden");

  const badgeClass = score.level === "hoch" ? "bad" : score.level === "mittel" ? "warn" : "good";
  reputationBadge.textContent = `Risk ${score.value ?? 0}/100 (${score.level || "niedrig"})`;
  reputationBadge.className = `phase-badge ${badgeClass}`;

  reputationSummary.textContent =
    `${report.target?.ip || activeIp} geprüft · Modus: ${reputationModeLabel(report.mode)} · Quellen: ${report.sourceSummary || "-"}.` +
    (report.cached ? " (Cache)" : " (Live)");

  const fields = [
    ["IP", report.target?.ip],
    ["Domain", report.target?.domain],
    ["Score", `${score.value ?? 0}/100`],
    ["Level", score.level || "niedrig"],
    ["Gründe", reasons.length ? reasons.join("; ") : "Keine Auffälligkeiten"],
  ];

  if (signals.dnsblListed !== null && signals.dnsblChecked !== null) {
    fields.push(["DNSBL Listings", `${signals.dnsblListed}/${signals.dnsblChecked}`]);
  }
  if (signals.torExit !== null && typeof signals.torExit !== "undefined") {
    fields.push(["Tor Exit Node", signals.torExit ? "Ja" : "Nein"]);
  }
  if (signals.stopForumSpamAppears !== null && typeof signals.stopForumSpamAppears !== "undefined") {
    fields.push(["StopForumSpam", signals.stopForumSpamAppears ? "Treffer" : "Kein Treffer"]);
  }
  if (signals.crowdsecLocation) {
    fields.push(["CrowdSec Location", String(signals.crowdsecLocation)]);
  }
  if (signals.crowdsecReputation) {
    fields.push(["CrowdSec Reputation", String(signals.crowdsecReputation)]);
  }
  if (signals.crowdsecAggressive !== null && typeof signals.crowdsecAggressive !== "undefined") {
    fields.push(["CrowdSec Aggressive", signals.crowdsecAggressive ? "Ja" : "Nein"]);
  }
  if (signals.crowdsecMalicious !== null && typeof signals.crowdsecMalicious !== "undefined") {
    fields.push(["CrowdSec", signals.crowdsecMalicious ? "Malicious" : "Kein Malicious-Treffer"]);
  }
  if (signals.crowdsecConfidence !== null && typeof signals.crowdsecConfidence !== "undefined") {
    fields.push(["CrowdSec Confidence", String(signals.crowdsecConfidence)]);
  }
  if (crowdSec && (hasCrowdSecKey || crowdSec.queried)) {
    const status = crowdSec.queried
      ? (currentLanguage === "de" ? "Abfrage erfolgreich" : currentLanguage === "fr" ? "Requête réussie" : currentLanguage === "nl" ? "Opvraging geslaagd" : "Query successful")
      : crowdSec.reason === "missing_api_key"
        ? (currentLanguage === "de" ? "API-Key fehlt" : currentLanguage === "fr" ? "Clé API manquante" : currentLanguage === "nl" ? "API-sleutel ontbreekt" : "API key missing")
        : `${currentLanguage === "de" ? "Abfrage fehlgeschlagen" : currentLanguage === "fr" ? "Échec de la requête" : currentLanguage === "nl" ? "Opvraging mislukt" : "Query failed"} (${crowdSec.reason || "unknown"})`;
    fields.push(["CrowdSec Status", status]);
  }
  if (crowdSec?.reputation) {
    fields.push(["CrowdSec Reputation", String(crowdSec.reputation)]);
  }
  if (crowdSec?.references !== null && typeof crowdSec?.references !== "undefined") {
    fields.push(["CrowdSec References", String(crowdSec.references)]);
  }

  reputationGrid.innerHTML = fields
    .map(([label, value]) => createCell(label, value || "-"))
    .join("");
}

function renderWhois(analysis) {
  const whois = analysis.whois;

  if (analysis.targetType !== "domain" || !whois) {
    whoisResult.classList.add("hidden");
    return;
  }

  whoisLink.href = whois.source || `https://www.whois.com/whois/${analysis.domain}`;
  const fields = [
    ["Domain", analysis.domain],
    ["Primäre IP", analysis.ip],
    ["Aufgelöste IPv4", analysis.resolvedIps?.join(", ")],
    ["Registrar", whois.registrar],
    ["Besitzer (Name)", whois.registrantName],
    ["Besitzer (Organisation)", whois.registrantOrg],
    ["Besitzer (Land)", whois.registrantCountry],
    ["Erstellt am", whois.createdAt],
    ["Aktualisiert am", whois.updatedAt],
    ["Läuft ab am", whois.expiresAt],
    ["Status", whois.status],
    ["Nameserver", (whois.nameServers || []).join(", ")],
  ];

  if (whois.error) {
    fields.push(["Hinweis", whois.error]);
  }

  whoisGrid.innerHTML = fields
    .map(([label, value]) => createCell(label, value || "-"))
    .join("");

  if (whois.rawPreview) {
    whoisRaw.textContent = whois.rawPreview;
    whoisRaw.classList.remove("hidden");
  } else {
    whoisRaw.classList.add("hidden");
  }

  whoisResult.classList.remove("hidden");
}

function renderDomainDns(analysis) {
  const intel = analysis.domainIntel;

  if (analysis.targetType !== "domain" || !intel) {
    dnsResult.classList.add("hidden");
    return;
  }

  const subdomains = intel.subdomains || [];
  selectedSubdomain = "";
  selectedResolveRow = "";
  subdomainResolutionMap = {};
  subdomainStatusMap = Object.fromEntries(subdomains.map((name) => [name, "idle"]));
  resolveVisibleButton.disabled = false;
  resolveVisibleButton.textContent = t("resolveAll");
  setResolveProgressVisible(false);
  resolveTableWrap.classList.add("hidden");
  resolveTableBody.innerHTML = "";
  resolveDetail.classList.add("hidden");
  resolveDetail.textContent = "";
  resolveShowAllButton.classList.add("hidden");
  riskFilter.value = "all";
  subdomainsCount.textContent =
    subdomains.length > 0
      ? currentLanguage === "en"
        ? `${subdomains.length} discovered subdomains (CT logs, best effort)`
        : `${subdomains.length} gefundene Subdomains (CT-Logs, Best-Effort)`
      : currentLanguage === "en"
        ? "No subdomains found or source unavailable."
        : "Keine Subdomains gefunden oder Quelle nicht verfügbar.";

  renderSubdomainList(subdomains);

  dnsResult.classList.remove("hidden");
}

function renderKnownScan(scanData) {
  scanResult.classList.remove("hidden");
  scanPhase.textContent = "Stufe 1: Bekannte Ports";

  scanSummary.textContent =
    `${scanData.scanned} bekannte Ports geprüft. ` +
    `${scanData.openPorts.length} offen gefunden.`;

  lastKnownScanData = scanData;

  renderPorts(scanData.openPorts);
  continueArea.classList.remove("hidden");
}

function renderFullScan(scanData) {
  scanResult.classList.remove("hidden");
  scanPhase.textContent = currentLanguage === "en" ? "Stage 2: Full scan up to 6500" : "Stufe 2: Vollscan bis 6500";

  const merged = mergePorts(knownOpenPorts, scanData.openPorts || []);
  scanSummary.textContent =
    `${scanData.scanned} weitere Ports geprüft. ` +
    `Insgesamt ${merged.length} offene Ports bis 6500.`;

  lastFullScanData = scanData;

  renderPorts(merged);
  continueArea.classList.add("hidden");
}

function renderPorts(ports) {
  openPortsEl.classList.remove("hidden");

  if (!ports.length) {
    openPortsEl.innerHTML = '<span class="port-pill headline">Offene Ports: keine</span>';
    return;
  }

  openPortsEl.innerHTML = [
    `<span class="port-pill headline">Offene Ports: ${ports.length}</span>`,
    ...ports.map((entry) => `<span class="port-pill">${entry.port} (${entry.service})</span>`),
  ]
    .join("");
}

function createCell(label, value) {
  return `
    <article class="cell">
      <span class="label">${escapeHtml(label)}</span>
      <span class="value">${escapeHtml(String(value))}</span>
    </article>
  `;
}

function mergePorts(first, second) {
  const map = new Map();
  [...first, ...second].forEach((entry) => {
    map.set(entry.port, entry);
  });
  return Array.from(map.values()).sort((a, b) => a.port - b.port);
}

function mergeScannedPortLists(first, second) {
  const set = new Set([...(first || []), ...(second || [])].map((p) => Number(p)).filter((p) => Number.isInteger(p)));
  return Array.from(set).sort((a, b) => a - b);
}

function showStatus(message, isError = false) {
  message = localizeMessage(message);
  statusEl.textContent = "";
  statusEl.classList.toggle("error", false);
  if (!message) {
    return;
  }

  const toast = document.createElement("div");
  toast.className = `toast ${isError ? "error" : ""}`;

  const text = document.createElement("div");
  text.className = "toast-main";
  text.textContent = message;

  const close = document.createElement("button");
  close.type = "button";
  close.className = "toast-close";
  close.setAttribute("aria-label", t("closeNotification"));
  close.textContent = "x";

  close.addEventListener("click", () => {
    clearTimeout(removeTimer);
    toast.remove();
  });

  toast.append(text, close);
  toastStack.appendChild(toast);

  const removeTimer = setTimeout(() => {
    toast.remove();
  }, 10000);
}

function singlePortFeedback(message, isError) {
  message = localizeMessage(message);
  singlePortResult.innerHTML = "";
  singlePortResult.textContent = message;
  singlePortResult.classList.toggle("error", Boolean(isError));
}

function renderSinglePortResults(entries) {
  if (!entries.length) {
    singlePortResult.textContent = "Keine Ergebnisse";
    singlePortResult.classList.remove("error");
    return;
  }

  singlePortResult.classList.remove("error");
  singlePortResult.innerHTML = entries
    .map((entry) => {
      const stateClass = entry.open ? "ok" : "bad";
      const stateText = entry.open ? "Offen" : "Geschlossen";
      return `<span class="single-port-pill ${stateClass}">${escapeHtml(`${entry.port} (${entry.service})`)} - ${stateText}</span>`;
    })
    .join("");
}

function resetView() {
  if (continueScanController) {
    continueScanController.abort();
  }
  stopRestScanProgress();

  geoResult.classList.add("hidden");
  reputationResult.classList.add("hidden");
  whoisResult.classList.add("hidden");
  dnsResult.classList.add("hidden");
  scanResult.classList.add("hidden");
  configPanel.classList.add("hidden");
  debugPanel.classList.add("hidden");
  continueArea.classList.add("hidden");
  abortContinueButton.classList.add("hidden");
  abortContinueButton.disabled = false;
  continueButton.classList.remove("is-loading");
  continueButton.textContent = t("continueScan");
  restProgress.classList.add("hidden");
  restProgressText.classList.add("hidden");
  restProgressFill.style.width = "0%";
  restProgressText.textContent = "";
  singlePortCheck.classList.add("hidden");
  loadGeoButton.classList.add("hidden");

  geoGrid.innerHTML = "";
  geoProvider.textContent = "";
  reputationBadge.textContent = "Bereit";
  reputationBadge.className = "phase-badge";
  reputationSummary.textContent = "";
  reputationGrid.innerHTML = "";
  crowdsecLimitAlert.classList.add("hidden");
  crowdsecLimitAlert.textContent = "";
  whoisGrid.innerHTML = "";
  whoisRaw.classList.add("hidden");
  whoisRaw.textContent = "";
  subdomainsCount.textContent = "";
  subdomainsList.innerHTML = "";
  resolveVisibleButton.disabled = false;
  resolveVisibleButton.textContent = t("resolveAll");
  setResolveProgressVisible(false);
  resolveTableWrap.classList.add("hidden");
  resolveTableBody.innerHTML = "";
  resolveDetail.classList.add("hidden");
  resolveDetail.textContent = "";
  resolveShowAllButton.classList.add("hidden");
  knownPortsInfo.classList.add("hidden");
  knownPortsCount.textContent = "";
  toggleKnownPortsButton.textContent = currentLanguage === "en" ? "Deselect all" : "Alle abwählen";
  knownPortsList.innerHTML = "";
  openPortsEl.innerHTML = "";
  openPortsEl.classList.add("hidden");
  historyScanColumns.innerHTML = "";
  historyScanColumns.classList.add("hidden");
  singlePortResult.textContent = "";
  singlePortInput.value = "";
  flagImage.style.display = "none";
  geoMapWrap.classList.add("hidden");
  geoMap.removeAttribute("src");

  activeIp = "";
  knownOpenPorts = [];
  lastKnownScannedPorts = [];
  lastAnalysis = null;
  knownPortsCatalog = [];
  selectedKnownPorts = new Set();
  activeRootDomain = "";
  selectedSubdomain = "";
  lastGeoData = null;
  lastGeoMeta = null;
  lastKnownScanData = null;
  lastFullScanData = null;
  lastSinglePortChecks = [];
  lastReputationData = null;
  subdomainResolutionMap = {};
  subdomainStatusMap = {};
  pendingSubdomainListRender = false;
  continueScanController = null;
  selectedResolveRow = "";
  lastResolveRows = [];
  focusedResolveSubdomain = "";
}

function renderSubdomainList(subdomains) {
  subdomainsList.innerHTML = subdomains.length
    ? subdomains
        .map((name) => {
          const active = selectedSubdomain === name;
          const state = subdomainStatusMap[name] || "idle";
          return `<button type="button" class="subdomain-pill ${active ? "selected" : ""}" data-subdomain="${escapeHtml(name)}"><span>${escapeHtml(name)}</span>${renderSubdomainStateIcon(state)}</button>`;
        })
        .join("")
    : `<span class="port-pill">${currentLanguage === "en" ? "No entries" : "Keine Einträge"}</span>`;
}

function scheduleSubdomainListRender() {
  if (pendingSubdomainListRender) {
    return;
  }
  pendingSubdomainListRender = true;
  requestAnimationFrame(() => {
    pendingSubdomainListRender = false;
    renderSubdomainList(lastAnalysis?.domainIntel?.subdomains || []);
  });
}

function renderSubdomainStateIcon(state) {
  if (state === "loading") {
    return '<span class="subdomain-state subdomain-state-loading" aria-label="Lädt"></span>';
  }
  if (state === "success") {
    return '<span class="subdomain-state subdomain-state-success" aria-label="Aufgelöst">✓</span>';
  }
  if (state === "no-record" || state === "error") {
    return '<span class="subdomain-state subdomain-state-error" aria-label="Keine Records">✕</span>';
  }
  return '<span class="subdomain-state subdomain-state-idle" aria-label="Nicht geprüft">•</span>';
}

function hasAddressRecord(records) {
  const source = records || {};
  return (source.A || []).length > 0 || (source.AAAA || []).length > 0 || (source.CNAME || []).length > 0;
}

async function postJson(url, body, options = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    signal: options.signal,
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || "Unbekannter Serverfehler");
  }

  return data;
}

async function getJson(url) {
  const response = await fetch(url);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || "Unbekannter Serverfehler");
  }
  return data;
}

async function loadConfigPublic() {
  try {
    const data = await getJson("/api/config/public");
    configSiteTitleInput.value = data.title || "";
    autoSizeTitleInput();
    const publicLimit = Math.max(1, Math.min(200, Number(data.historyMaxEntries) || 10));
    historyMaxItems = publicLimit;
    configHistoryLimitInput.value = String(publicLimit);
    const publicRate = Math.max(1, Math.min(2000, Number(data.restPortsPerSecond) || 2));
    restPortsPerSecond = publicRate;
    configRestRateInput.value = String(publicRate);
    const allowedGeo = Array.isArray(data.allowedGeoSources)
      ? data.allowedGeoSources
      : ["geoiplite", "maxmind", "geoip2node"];
    configGeoGeoipLiteInput.checked = allowedGeo.includes("geoiplite");
    configGeoMaxmindInput.checked = allowedGeo.includes("maxmind");
    configGeoGeoip2NodeInput.checked = allowedGeo.includes("geoip2node");
    if (!configGeoGeoipLiteInput.checked && !configGeoMaxmindInput.checked && !configGeoGeoip2NodeInput.checked) {
      configGeoGeoipLiteInput.checked = true;
    }
    applyGeoSourceVisibility(allowedGeo);
    const allowedRep = Array.isArray(data.allowedReputationSources)
      ? data.allowedReputationSources
      : ["dnsbl", "privacy", "community", "crowdsec"];
    applyReputationSourceChecks(allowedRep);
    hasSavedAccessPassword = Boolean(data.hasAccessPassword);
    updateAccessPasswordState(hasSavedAccessPassword);
    configCrowdsecInput.value = "";
    configAccessPasswordInput.value = "";
    clearAccessPasswordRequested = false;
    hasCrowdSecKey = Boolean(data.hasCrowdSecKey);
    applyCrowdSecVisibility();
    updateCrowdSecMaskState();
    pendingLogoDataUrl = "";
    pendingFaviconDataUrl = "";
    configLogoName.textContent = t("noFile");
    configFaviconName.textContent = t("noFile");
  } catch (error) {
    showStatus(error.message || "Konfiguration konnte nicht geladen werden.", true);
  }
}

function applyGeoSourceVisibility(allowed) {
  const allowedSet = new Set(Array.isArray(allowed) ? allowed : ["geoiplite", "maxmind", "geoip2node"]);
  Array.from(geoSourceSelect.options).forEach((opt) => {
    const enabled = allowedSet.has(opt.value);
    opt.hidden = !enabled;
    opt.disabled = !enabled;
  });
  if (!allowedSet.has(geoSourceSelect.value)) {
    geoSourceSelect.value =
      allowedSet.has("geoiplite")
        ? "geoiplite"
        : allowedSet.has("maxmind")
          ? "maxmind"
          : "geoip2node";
  }
}

function getSelectedReputationSources() {
  const values = [
    ...(configRepDnsblInput.checked ? ["dnsbl"] : []),
    ...(configRepPrivacyInput.checked ? ["privacy"] : []),
    ...(configRepCommunityInput.checked ? ["community"] : []),
    ...(configRepCrowdsecInput.checked ? ["crowdsec"] : []),
  ];
  return values.length ? values : ["community"];
}

function applyReputationSourceChecks(sources) {
  const set = new Set(Array.isArray(sources) ? sources : []);
  configRepDnsblInput.checked = set.has("dnsbl");
  configRepPrivacyInput.checked = set.has("privacy");
  configRepCommunityInput.checked = set.has("community");
  configRepCrowdsecInput.checked = set.has("crowdsec");
  if (!getSelectedReputationSources().length) {
    configRepCommunityInput.checked = true;
  }
  applyReputationSourceVisibility(getSelectedReputationSources());
}

function applyReputationSourceVisibility(allowed) {
  const set = new Set(allowed);
  Array.from(reputationSourceSelect.options).forEach((opt) => {
    const enabled = set.has(opt.value) && (opt.value !== "crowdsec" || hasCrowdSecKey);
    opt.hidden = !enabled;
    opt.disabled = !enabled;
  });
  if (
    !Array.from(reputationSourceSelect.options).some((opt) => opt.value === reputationSourceSelect.value && !opt.disabled) ||
    (reputationSourceSelect.value === "crowdsec" && !hasCrowdSecKey)
  ) {
    reputationSourceSelect.value = set.has("community") ? "community" : Array.from(set)[0] || "community";
  }
}

async function loadBranding() {
  try {
    const data = await getJson("/api/config/public");
    hasCrowdSecKey = Boolean(data.hasCrowdSecKey);
    applyCrowdSecVisibility();
    updateCrowdSecMaskState();
    const title = data.title || "DNS / IP-Resolver";
    document.title = title;

    const icon = document.querySelector('link[rel="icon"]');
    if (icon) {
      icon.href = data.faviconDataUrl || "";
    }

    const shortcut = document.querySelector('link[rel="shortcut icon"]');
    if (shortcut) {
      shortcut.href = data.faviconDataUrl || "";
    }

    const logoImg = document.querySelector(".brand img");
    if (logoImg) {
      if (data.logoDataUrl) {
        logoImg.src = data.logoDataUrl;
        logoImg.style.display = "block";
      } else {
        logoImg.removeAttribute("src");
        logoImg.style.display = "none";
      }
    }
  } catch (error) {
    /* ignore */
  }
}

function applyCrowdSecVisibility() {
  applyReputationSourceVisibility(getSelectedReputationSources());
}

async function loadLocales() {
  try {
    const payload = await getJson("/api/locales");
    const locales = Array.isArray(payload.locales) ? payload.locales : [];
    const loaded = {};
    const jobs = locales
      .map((locale) => String(locale.code || "").trim())
      .filter(Boolean)
      .map((code) =>
        getJson(`/api/locales/${encodeURIComponent(code)}`)
          .then((data) => ({ code, data }))
          .catch(() => null)
      );
    const results = await Promise.all(jobs);
    results.forEach((entry) => {
      if (entry?.code && entry?.data) {
        loaded[entry.code] = entry.data;
      }
    });

    localesRegistry = loaded;
    renderLanguageOptions(locales);
  } catch (error) {
    renderLanguageOptions([]);
  }
}

function renderLanguageOptions(locales) {
  const fallback = [
    { code: "de", name: "Deutsch", flag: "🇩🇪" },
    { code: "en", name: "English", flag: "🇬🇧" },
    { code: "nl", name: "Nederlands", flag: "🇳🇱" },
    { code: "fr", name: "Français", flag: "🇫🇷" },
  ];
  const source = locales.length ? locales : fallback;
  languageToggle.innerHTML = source
    .map((locale) => {
      const code = String(locale.code || "");
      const name = String(locale.name || code);
      const flag = String(locale.flag || "").trim();
      return `<option value="${escapeHtml(code)}">${escapeHtml(`${flag ? `${flag} ` : ""}${name}`)}</option>`;
    })
    .join("");

  if (!Array.from(languageToggle.options).some((o) => o.value === currentLanguage)) {
    currentLanguage = "de";
  }
  languageToggle.value = currentLanguage;
}

async function readFileAsDataUrl(file) {
  if (!file) {
    return "";
  }
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => resolve("");
    reader.readAsDataURL(file);
  });
}

function autoSizeTitleInput() {
  const text = configSiteTitleInput.value || "";
  const size = Math.max(8, Math.min(120, text.length + 1));
  configSiteTitleInput.style.width = `${size}ch`;
}

function updateCrowdSecMaskState() {
  if (!configCrowdsecState) {
    return;
  }

  const typed = String(configCrowdsecInput.value || "").trim();
  if (typed) {
    const stars = "*".repeat(Math.max(6, Math.min(18, typed.length)));
    configCrowdsecState.textContent = `${stars} (${t("stateNew")})`;
    return;
  }

  if (hasCrowdSecKey) {
    configCrowdsecState.textContent = `******** (${t("stateSaved")})`;
  } else {
    configCrowdsecState.textContent = t("stateNotSet");
  }
}

function updateAccessPasswordState(hasSaved) {
  configClearAccessButton.classList.toggle("hidden", !hasSaved);
  if (hasSaved) {
    configAccessState.textContent = `******** (${t("stateSaved")})`;
  } else if (!String(configAccessPasswordInput.value || "").trim()) {
    configAccessState.textContent = t("stateNotSet");
  }
}

async function checkResolverStatus() {
  try {
    const status = await getJson("/api/config/status");
    if (status?.missingResolverPassword) {
      const missingTitle = currentLanguage === "fr" ? "Configuration manquante" : currentLanguage === "nl" ? "Configuratie ontbreekt" : currentLanguage === "en" ? "Configuration missing" : "Konfiguration fehlt";
      const missingText = currentLanguage === "fr"
        ? "La variable d'environnement <code>RESOLVER_PASSWORD</code> n'est pas définie. Veuillez la définir puis redémarrer le conteneur."
        : currentLanguage === "nl"
          ? "De omgevingsvariabele <code>RESOLVER_PASSWORD</code> is niet ingesteld. Stel deze in en start de container opnieuw."
          : currentLanguage === "en"
            ? "The <code>RESOLVER_PASSWORD</code> environment variable is not set. Please set it and restart the container."
            : "Die Umgebungsvariable <code>RESOLVER_PASSWORD</code> ist nicht gesetzt. Bitte setze sie und starte den Container neu.";
      document.body.innerHTML = `<main style="max-width:760px;margin:10vh auto;padding:1rem;color:#ffd8a8;font-family:'Space Grotesk',sans-serif;"><section style="border:1px solid #f0bb6d66;background:#3f2b12b0;border-radius:12px;padding:1rem;"><h1 style="margin-top:0;">${missingTitle}</h1><p>${missingText}</p></section></main>`;
      return false;
    }
    return true;
  } catch (error) {
    const readyTitle = currentLanguage === "fr" ? "Serveur indisponible" : currentLanguage === "nl" ? "Server niet klaar" : currentLanguage === "en" ? "Server not ready" : "Server nicht bereit";
    const readyText = currentLanguage === "fr" ? "La page ne peut pas être démarrée." : currentLanguage === "nl" ? "De pagina kan niet worden gestart." : currentLanguage === "en" ? "The page could not be started." : "Die Seite kann nicht gestartet werden.";
    document.body.innerHTML = `<main style="max-width:760px;margin:10vh auto;padding:1rem;color:#ffd8a8;font-family:'Space Grotesk',sans-serif;"><section style="border:1px solid #f0bb6d66;background:#3f2b12b0;border-radius:12px;padding:1rem;"><h1 style="margin-top:0;">${readyTitle}</h1><p>${readyText}</p></section></main>`;
    return false;
  }
}

function parsePorts(value) {
  const raw = String(value || "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);

  const unique = new Set();
  for (const entry of raw) {
    if (!/^\d+$/.test(entry)) {
      continue;
    }
    const port = Number(entry);
    if (port >= 1 && port <= 65535) {
      unique.add(port);
    }
  }

  return Array.from(unique).sort((a, b) => a - b);
}

function formatPortList(entries) {
  if (!entries.length) {
    return "keine";
  }
  return entries.map((entry) => `${entry.port} (${entry.service})`).join(", ");
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function valueWithCode(value, code) {
  if (!value && !code) {
    return "-";
  }
  if (value && code) {
    return `${value} (${code})`;
  }
  return value || code;
}

function formatNumber(value) {
  if (typeof value !== "number") {
    return "-";
  }
  return value.toFixed(4);
}

function renderResolveTable(rows) {
  const withRecordsOnly = rows.filter((row) => hasAddressRecord(row?.records));
  const byRisk = applyRiskFilter(withRecordsOnly, riskFilter.value);
  const filteredRows = focusedResolveSubdomain
    ? byRisk.filter((row) => row?.subdomain === focusedResolveSubdomain)
    : byRisk;

  if (!withRecordsOnly.length) {
    resolveTableWrap.classList.add("hidden");
    resolveTableBody.innerHTML = "";
    resolveDetail.classList.add("hidden");
    resolveDetail.textContent = "";
    return;
  }

  resolveTableBody.innerHTML = filteredRows
    .map((entry) => {
      const records = entry.records || {};
      const tls = entry.tls || {};
      const history = entry.history || [];
      const risk = entry.risk || {};

      const a = (records.A || []).join(", ") || "-";
      const cname = (records.CNAME || []).join(", ") || "-";
      const tlsText = tls.available
        ? `${tls.subjectCn || "CN ?"} | bis ${tls.validTo || "-"}`
        : "nicht verfügbar";
      const historyText = history.length
        ? `${history.length} Einträge, zuletzt ${history[0].loggedAt || "-"}`
        : "keine";
      const riskLevel = String(risk.level || "niedrig");
      const riskClass = riskLevel === "hoch" ? "risk-high" : riskLevel === "mittel" ? "risk-medium" : "risk-low";
      const isActive = selectedResolveRow && selectedResolveRow === entry.subdomain;

      return `
        <tr${isActive ? ' class="row-active"' : ""}>
          <td>${escapeHtml(entry.subdomain || "-")}</td>
          <td>${escapeHtml(a)}</td>
          <td>${escapeHtml(cname)}</td>
          <td>${escapeHtml(tlsText)}</td>
          <td>${escapeHtml(historyText)}</td>
          <td><span class="risk-chip ${riskClass}">${escapeHtml(`${risk.score ?? 0}/100 ${riskLevel}`)}</span></td>
          <td><button type="button" class="table-detail-btn readonly-allow" data-detail-subdomain="${escapeHtml(entry.subdomain || "")}">Details</button></td>
        </tr>
      `;
    })
    .join("");

  resolveTableWrap.classList.remove("hidden");

  if (!filteredRows.length) {
    resolveTableBody.innerHTML = `<tr><td colspan="7">${currentLanguage === "en" ? "No entries for the selected filter." : "Keine Einträge für den gewählten Filter."}</td></tr>`;
  }
}

function applyRiskFilter(rows, mode) {
  if (!Array.isArray(rows)) {
    return [];
  }

  if (mode === "high") {
    return rows.filter((row) => row?.risk?.level === "hoch");
  }
  if (mode === "medium") {
    return rows.filter((row) => {
      const level = row?.risk?.level;
      return level === "hoch" || level === "mittel";
    });
  }
  if (mode === "tls-missing") {
    return rows.filter((row) => !row?.tls?.available);
  }
  return rows;
}

function renderResolveDetail(entry) {
  if (!entry) {
    resolveDetail.classList.add("hidden");
    resolveDetail.classList.remove("error");
    resolveDetail.textContent = "";
    return;
  }

  resolveDetail.classList.remove("error");

  const records = entry.records || {};
  const tls = entry.tls || {};
  const history = entry.history || [];
  const ipv4History = entry.ipv4History || [];
  const risk = entry.risk || {};

  const riskReasons = Array.isArray(risk.reasons) && risk.reasons.length
    ? `<ul>${risk.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>`
    : "Keine Auffälligkeiten";

  const historyRows = history.length
    ? history
        .slice(0, 8)
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.loggedAt || "-")}</td><td>${escapeHtml(item.issuer || "-")}</td><td>${escapeHtml(item.notBefore || "-")}</td><td>${escapeHtml(item.notAfter || "-")}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">${currentLanguage === "en" ? "No entries" : "Keine Einträge"}</td></tr>`;

  const ipv4Rows = ipv4History.length
    ? ipv4History
        .slice(0, 10)
        .map(
          (item) =>
            `<tr><td>${escapeHtml(item.observedAt || "-")}</td><td>${escapeHtml((item.ipv4 || []).join(", ") || "-")}</td><td>${escapeHtml(item.tlsCn || "-")}</td><td>${escapeHtml(String(item.riskScore ?? "-"))}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4">${currentLanguage === "en" ? "No observations yet" : "Noch keine Beobachtungen"}</td></tr>`;

  resolveDetail.innerHTML = `
    <h3>${currentLanguage === "en" ? "Details" : "Details"}: ${escapeHtml(entry.subdomain || "-")}</h3>
    <table class="detail-table">
      <tr><th>${currentLanguage === "en" ? "Current A" : "Aktuelle A"}</th><td>${escapeHtml((records.A || []).join(", ") || "-")}</td></tr>
      <tr><th>${currentLanguage === "en" ? "Current AAAA" : "Aktuelle AAAA"}</th><td>${escapeHtml((records.AAAA || []).join(", ") || "-")}</td></tr>
      <tr><th>${currentLanguage === "en" ? "Current CNAME" : "Aktuelle CNAME"}</th><td>${escapeHtml((records.CNAME || []).join(", ") || "-")}</td></tr>
      <tr><th>Risk Score</th><td>${escapeHtml(`${risk.score ?? 0}/100 (${risk.level || (currentLanguage === "en" ? "low" : "niedrig")})`)}</td></tr>
      <tr><th>${currentLanguage === "en" ? "Why this score?" : "Warum dieser Score?"}</th><td>${riskReasons}</td></tr>
      <tr><th>TLS ${currentLanguage === "en" ? "Status" : "Status"}</th><td>${tls.available ? (currentLanguage === "en" ? "Active" : "Aktiv") : (currentLanguage === "en" ? "Unavailable" : "Nicht verfügbar")}</td></tr>
      <tr><th>TLS CN</th><td>${escapeHtml(tls.subjectCn || "-")}</td></tr>
      <tr><th>TLS Issuer</th><td>${escapeHtml(tls.issuerCn || "-")}</td></tr>
      <tr><th>${currentLanguage === "en" ? "Valid from" : "Gültig von"}</th><td>${escapeHtml(tls.validFrom || "-")}</td></tr>
      <tr><th>${currentLanguage === "en" ? "Valid until" : "Gültig bis"}</th><td>${escapeHtml(tls.validTo || "-")}</td></tr>
    </table>

    <h3>${currentLanguage === "en" ? "IPv4 History" : "IPv4 Verlauf"}</h3>
    <table class="detail-table">
      <thead><tr><th>${currentLanguage === "en" ? "Time" : "Zeitpunkt"}</th><th>IPv4</th><th>TLS-CN</th><th>Risk</th></tr></thead>
      <tbody>${ipv4Rows}</tbody>
    </table>

    <h3>${currentLanguage === "en" ? "TLS/CT History" : "TLS/CT Historie"}</h3>
    <table class="detail-table">
      <thead><tr><th>${currentLanguage === "en" ? "Logged" : "Geloggt"}</th><th>Issuer</th><th>Not Before</th><th>Not After</th></tr></thead>
      <tbody>${historyRows}</tbody>
    </table>
  `;
  resolveDetail.classList.remove("hidden");
}

function renderResolveError(message) {
  resolveDetail.innerHTML = `<h3>Keine Daten verfügbar</h3><p>${escapeHtml(message)}</p>`;
  resolveDetail.classList.add("error");
  resolveDetail.classList.remove("hidden");
}

function geoSourceLabel(source) {
  if (source === "geoiplite") {
    return "geoip-lite";
  }
  if (source === "maxmind") {
    return "maxmind-mmdb";
  }
  if (source === "geoip2node") {
    return "geoip2-node";
  }
  return source;
}

function reputationModeLabel(mode) {
  if (mode === "dnsbl") {
    return "DNSBL Fokus";
  }
  if (mode === "privacy") {
    return "VPN/Proxy Fokus";
  }
  if (mode === "community") {
    return "Community Fokus";
  }
  if (mode === "crowdsec") {
    return "CrowdSec Fokus";
  }
  return "Auto";
}

function setResolveProgress(done, total) {
  const safeTotal = total > 0 ? total : 1;
  const percent = Math.round((done / safeTotal) * 100);
  resolveProgressFill.style.width = `${percent}%`;
  resolveProgressText.textContent = `${done}/${total} aufgelöst`;
}

function setResolveProgressVisible(visible) {
  resolveProgress.classList.toggle("hidden", !visible);
  resolveProgressText.classList.toggle("hidden", !visible);
  if (!visible) {
    resolveProgressFill.style.width = "0%";
    resolveProgressText.textContent = "";
  }
}

function startRestScanProgress(totalPorts, initialDone = 0) {
  stopRestScanProgress();

  const total = Math.max(1, Number(totalPorts) || 1);
  restScanTotalPorts = total;
  lastRestEstimatedDone = Math.max(0, Math.min(total, Number(initialDone) || 0));
  restProgress.classList.remove("hidden");
  restProgressText.classList.remove("hidden");
  updateRestScanProgress(lastRestEstimatedDone, total);
}

function updateRestScanProgress(done, total) {
  const safeTotal = Math.max(1, Number(total) || 1);
  const safeDone = Math.max(0, Math.min(safeTotal, Number(done) || 0));
  lastRestEstimatedDone = safeDone;

  const percent = Math.round((safeDone / safeTotal) * 100);
  restProgressFill.style.width = `${percent}%`;

  const remaining = Math.max(0, safeTotal - safeDone);
  const msPerPort = Math.max(1, Math.floor(1000 / Math.max(1, restPortsPerSecond || 2)));
  const etaMinutes = Math.round((remaining * msPerPort) / 60000);
  const etaLabel = etaMinutes < 1 ? "unter 1 min" : `${etaMinutes} min`;
  restProgressText.textContent = `${safeDone}/${safeTotal} Ports geprüft · ca. ${etaLabel} verbleibend`;
}

function stopRestScanProgress() {
  restScanTotalPorts = 0;
  lastRestEstimatedDone = 0;
  restProgress.classList.add("hidden");
  restProgressText.classList.add("hidden");
  restProgressFill.style.width = "0%";
  restProgressText.textContent = "";
}

function setAnalyzeLoading(isLoading) {
  analyzeButton.disabled = Boolean(isLoading);
  analyzeButton.classList.toggle("is-loading", Boolean(isLoading));
  analyzeButton.textContent = isLoading
    ? currentLanguage === "en"
      ? "Analyzing ..."
      : "Analysiere ..."
    : t("analyzeStart");
}

function addHistoryEntry(text) {
  if (!text || !activeScanHistoryId) {
    return;
  }

  const record = scanHistory.find((entry) => entry.id === activeScanHistoryId);
  if (!record) {
    return;
  }

  record.updatedAt = new Date().toISOString();
  record.lastAction = text;
  record.snapshot = buildCurrentSnapshot();

  queueHistoryPersist();
  renderHistoryList();
}

function startScanHistoryRecord(analysis) {
  const now = new Date().toISOString();
  const id = createHistoryId();
  activeScanHistoryId = id;

  scanHistory.unshift({
    id,
    input: analysis?.input || "-",
    targetType: analysis?.targetType || "-",
    createdAt: now,
    updatedAt: now,
    lastAction: "Analyse gestartet",
    snapshot: buildCurrentSnapshot(),
  });

  pruneHistory();
  queueHistoryPersist();
  renderHistoryList();
}

function buildCurrentSnapshot() {
  return {
    analysis: lastAnalysis,
    geo: lastGeoData,
    geoMeta: lastGeoMeta,
    geoSource: geoSourceSelect.value,
    reputation: lastReputationData,
    reputationSource: reputationSourceSelect.value,
    knownScan: lastKnownScanData,
    fullScan: lastFullScanData,
    singlePortChecks: lastSinglePortChecks,
    subdomainResolutions: subdomainResolutionMap,
    knownOpenPorts,
    lastKnownScannedPorts,
    scannedRestPorts,
    openRestPorts,
    selectedKnownPorts: Array.from(selectedKnownPorts),
    subdomainStatusMap,
    lastResolveRows,
    selectedSubdomain,
    selectedResolveRow,
    focusedResolveSubdomain,
    riskFilter: riskFilter.value,
  };
}

function renderHistoryList() {
  historyEmpty.classList.toggle("hidden", scanHistory.length > 0);
  historyList.innerHTML = scanHistory
    .map((entry) => {
      const time = new Date(entry.updatedAt || entry.createdAt).toLocaleString("de-DE", {
        day: "2-digit",
        month: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      });
      const activeClass = activeScanHistoryId === entry.id ? " active" : "";
      return `
        <article class="history-item${activeClass}">
          <div class="history-row">
            <span class="history-time">${escapeHtml(time)}</span>
            <div class="history-controls">
              <button class="history-view-btn" type="button" data-view-id="${escapeHtml(entry.id)}" title="${currentLanguage === "en" ? "View" : "Ansehen"}">👁</button>
              <button class="history-view-btn" type="button" data-share-id="${escapeHtml(entry.id)}" title="${currentLanguage === "en" ? "Copy link" : "Link kopieren"}">🔗</button>
              <button class="history-view-btn" type="button" data-download-id="${escapeHtml(entry.id)}" title="${currentLanguage === "en" ? "Download JSON" : "JSON herunterladen"}">⬇</button>
            </div>
          </div>
          <span class="history-text">${escapeHtml(entry.input || "-")}</span>
          <span class="history-time">${escapeHtml(entry.lastAction || "-")}</span>
        </article>
      `;
    })
    .join("");
}

function loadHistoryScan(id) {
  const record = scanHistory.find((entry) => entry.id === id);
  if (!record?.snapshot?.analysis) {
    showStatus(currentLanguage === "en" ? "Historical scan could not be loaded." : "Historischer Scan konnte nicht geladen werden.", true);
    return;
  }

  resetView();
  setStartPanelVisible(false);
  activeScanHistoryId = record.id;
  setHistoryQueryParam(record.id);
  setHistoryReadOnly(true, record);
  renderHistoryList();

  const snapshot = record.snapshot;
  lastAnalysis = snapshot.analysis;
  activeIp = lastAnalysis.ip;
  activeRootDomain = lastAnalysis.domain || "";
  if (snapshot.geoSource) {
    geoSourceSelect.value = snapshot.geoSource;
  }
  if (snapshot.reputationSource) {
    reputationSourceSelect.value = snapshot.reputationSource;
  }
  renderWhois(lastAnalysis);
  renderDomainDns(lastAnalysis);
  prepareManualActions(lastAnalysis);

  lastGeoData = snapshot.geo || null;
  lastGeoMeta = snapshot.geoMeta || null;
  lastReputationData = snapshot.reputation || null;
  lastKnownScanData = snapshot.knownScan || null;
  lastFullScanData = snapshot.fullScan || null;
  lastSinglePortChecks = snapshot.singlePortChecks || [];
  subdomainResolutionMap = snapshot.subdomainResolutions || {};
  knownOpenPorts = snapshot.knownOpenPorts || [];
  lastKnownScannedPorts = snapshot.lastKnownScannedPorts || [];
  scannedRestPorts = snapshot.scannedRestPorts || [];
  openRestPorts = snapshot.openRestPorts || [];
  selectedKnownPorts = new Set(snapshot.selectedKnownPorts || []);
  subdomainStatusMap = snapshot.subdomainStatusMap || {};
  lastResolveRows = snapshot.lastResolveRows || [];
  selectedSubdomain = snapshot.selectedSubdomain || "";
  selectedResolveRow = snapshot.selectedResolveRow || "";
  focusedResolveSubdomain = snapshot.focusedResolveSubdomain || "";
  riskFilter.value = snapshot.riskFilter || "all";

  renderKnownPortsInfo();
  renderSubdomainList(lastAnalysis.domainIntel?.subdomains || []);
  renderResolveTable(lastResolveRows);
  if (selectedResolveRow && subdomainResolutionMap[selectedResolveRow]) {
    renderResolveDetail(subdomainResolutionMap[selectedResolveRow]);
    if (focusedResolveSubdomain) {
      resolveShowAllButton.classList.remove("hidden");
    }
  }

  if (lastGeoData) {
    renderGeoData(lastAnalysis, lastGeoData);
  }
  if (lastReputationData) {
    renderReputation(lastReputationData);
  }
  if (lastKnownScanData) {
    knownOpenPorts = lastKnownScanData.openPorts || [];
    lastKnownScannedPorts = lastKnownScanData.selectedKnownPorts || [];
    renderKnownScan(lastKnownScanData);
  }
  if (lastFullScanData) {
    renderFullScan(lastFullScanData);
  } else if (scannedRestPorts.length) {
    renderRestScanSnapshot();
  }
  if (lastSinglePortChecks.length) {
    renderSinglePortResults(lastSinglePortChecks);
  }

  applyHistoryVisibility(snapshot);

  showStatus(
    currentLanguage === "en"
      ? `Loaded historical scan (read-only): ${record.input}`
      : `Historischen Scan geladen (Read-Only): ${record.input}`
  );
}

function pruneHistory() {
  const cutoff = Date.now() - HISTORY_RETENTION_MS;
  scanHistory = scanHistory
    .filter((entry) => Date.parse(entry.updatedAt || entry.createdAt || 0) >= cutoff)
    .slice(0, historyMaxItems);
}

function downloadHistoryScan(id) {
  const safeId = encodeURIComponent(String(id || ""));
  if (!safeId) {
    return;
  }
  window.location.href = `/api/history/${safeId}/download`;
}

async function shareHistoryScan(id) {
  const url = `${window.location.origin}${window.location.pathname}?history=${encodeURIComponent(String(id || ""))}`;
  try {
    await navigator.clipboard.writeText(url);
    showStatus(currentLanguage === "en" ? "History link copied." : "History-Link kopiert.");
  } catch (error) {
    showStatus(url);
  }
}

function setHistoryQueryParam(id) {
  const url = new URL(window.location.href);
  if (id) {
    url.searchParams.set("history", id);
  } else {
    url.searchParams.delete("history");
  }
  window.history.replaceState({}, "", url.toString());
}

function loadHistoryFromUrl() {
  const url = new URL(window.location.href);
  const id = String(url.searchParams.get("history") || "").trim();
  if (!id) {
    return;
  }
  loadHistoryScan(id);
}

function setHistoryReadOnly(enabled, record = null) {
  isHistoryReadonly = Boolean(enabled);
  document.body.classList.toggle("history-readonly", isHistoryReadonly);
  readonlyBanner.classList.toggle("hidden", !isHistoryReadonly);

  if (isHistoryReadonly && record) {
    renderReadonlyBanner(record);
  }

  const disable = isHistoryReadonly;
  ipInput.disabled = disable;
  analyzeButton.disabled = disable;
  if (exportJsonButton) {
    exportJsonButton.disabled = disable;
  }
  resolveVisibleButton.disabled = disable;
  riskFilter.disabled = false;
  resolveShowAllButton.disabled = false;
  geoSourceSelect.disabled = disable;
  loadGeoButton.disabled = disable;
  reputationSourceSelect.disabled = disable;
  startReputationButton.disabled = disable;
  startKnownButton.disabled = disable;
  continueButton.disabled = disable;
  abortContinueButton.disabled = disable;
  toggleKnownPortsButton.disabled = disable;
  singlePortInput.disabled = disable;
  singlePortButton.disabled = disable;
  whoisLink.tabIndex = 0;
  whoisLink.setAttribute("aria-disabled", "false");

  readonlyActionElements.forEach((element) => {
    element.classList.toggle("readonly-action", disable);
  });

  if (centerContent) {
    centerContent.classList.toggle("readonly-content", disable);
  }
}

function renderReadonlyBanner(record) {
  const updatedAt = formatHistoryDate(record.updatedAt || record.createdAt);
  const createdAt = formatHistoryDate(record.createdAt);
  readonlyBanner.innerHTML = `
    <div class="readonly-title">${escapeHtml(t("readonlyTitle"))}</div>
    <div class="readonly-meta">
      <span class="readonly-chip">🆔 ${escapeHtml(currentLanguage === "en" ? "Scan ID" : "Scan-ID")}: ${escapeHtml(record.id || "-")}</span>
      <span class="readonly-chip">🎯 ${escapeHtml(currentLanguage === "en" ? "Input" : "Eingabe")}: ${escapeHtml(record.input || "-")}</span>
      <span class="readonly-chip">🧭 ${escapeHtml(currentLanguage === "en" ? "Type" : "Typ")}: ${escapeHtml(record.targetType || "-")}</span>
      <span class="readonly-chip">🕒 ${escapeHtml(currentLanguage === "en" ? "Created" : "Erstellt")}: ${escapeHtml(createdAt)}</span>
      <span class="readonly-chip">♻ ${escapeHtml(currentLanguage === "en" ? "Updated" : "Aktualisiert")}: ${escapeHtml(updatedAt)}</span>
    </div>
    <p class="readonly-note">🔒 ${escapeHtml(t("readonlyNote"))}</p>
  `;
}

function formatHistoryDate(value) {
  const date = new Date(value || "");
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  const localeMap = {
    de: "de-DE",
    en: "en-GB",
    nl: "nl-NL",
    fr: "fr-FR",
  };
  return date.toLocaleString(localeMap[currentLanguage] || "de-DE", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function t(key) {
  const external = localesRegistry?.[currentLanguage]?.messages || {};
  if (typeof external[key] !== "undefined") {
    return external[key];
  }
  const lang = I18N[currentLanguage] || I18N.de;
  return lang[key] || I18N.de[key] || key;
}

function applyLanguage() {
  document.documentElement.lang = currentLanguage;
  languageToggle.value = currentLanguage;

  const map = {
    "actions-label": t("actions"),
    "lang-label": t("language"),
    "history-label": t("history"),
    "history-title": t("latestScans"),
    "history-empty": t("noScans"),
    "hero-title": t("heroTitle"),
    "hero-subline": t("heroSubline"),
    "hero-hint": t("heroHint"),
    "analyze-button": t("analyzeStart"),
    "whois-title": t("whoisTitle"),
    "dns-title": t("dnsTitle"),
    "geo-title": t("geoTitle"),
    "reputation-title": t("reputationTitle"),
    "scan-title": t("scanTitle"),
    "config-title": t("configTitle"),
    "config-hint": t("configHint"),
    "config-password-label": t("configPassword"),
    "unlock-config": t("unlockConfig"),
    "config-site-title-label": t("siteTitleLabel"),
    "config-crowdsec-label": t("crowdsecTokenLabel"),
    "config-history-limit-label": t("configHistoryLimit"),
    "config-rest-rate-label": t("configRestRate"),
    "config-geo-sources-label": t("configGeoSources"),
    "config-geo-editor-label": t("configGeoEditor"),
    "config-reputation-sources-label": t("configReputationSources"),
    "config-access-password-label": t("configAccessPassword"),
    "config-logo-label": t("configLogo"),
    "config-favicon-label": t("configFavicon"),
    "config-clear-access": `✕ ${t("clear")}`,
    "debug-title": t("debugTitle"),
    "debug-hint": t("debugHint"),
    "debug-ip-label": t("debugIpLabel"),
    "debug-domain-label": t("debugDomainLabel"),
    "debug-run": t("debugRun"),
    "open-config": t("config"),
    "save-config": t("saveConfig"),
    "risk-filter-label": t("filter"),
    "resolve-visible": t("resolveAll"),
    "resolve-show-all": t("showAllHosts"),
    "start-known-scan": t("startKnown"),
    "continue-scan": t("continueScan"),
    "abort-continue-scan": t("abortScan"),
    "load-geo": t("loadGeo"),
    "single-port-button": t("checkPorts"),
  };

  Object.entries(map).forEach(([id, value]) => {
    const node = document.getElementById(id);
    if (node) {
      node.textContent = value;
    }
  });

  if (singlePortLabel && !isHistoryReadonly) {
    singlePortLabel.textContent = t("singlePortHint");
  }

  const riskHelp = document.getElementById("risk-help");
  if (riskHelp) {
    riskHelp.textContent = currentLanguage === "en"
      ? "Risk score (0-100) is based on live signals: DNS availability, TLS state (missing/expired/expiring soon), certificate change frequency (CT history), and CNAME chains."
      : "Risk-Score (0-100) basiert auf Live-Signalen: DNS-Verfügbarkeit, TLS-Zustand (fehlt/abgelaufen/läuft bald ab), Zertifikatswechsel-Häufigkeit (CT-Historie) und CNAME-Ketten.";
  }

  const newAnalysisLabel = document.getElementById("new-analysis");
  if (newAnalysisLabel) {
    newAnalysisLabel.textContent = t("newAnalysis");
  }

  const exportJsonLabel = document.getElementById("export-json");
  if (exportJsonLabel) {
    exportJsonLabel.textContent = t("exportJson");
  }

  const whoisLinkLabel = document.getElementById("whois-link");
  if (whoisLinkLabel) {
    whoisLinkLabel.textContent = t("whoisOpen");
  }

  const options = riskFilter?.options || [];
  if (options.length >= 4) {
    options[0].text = t("riskAll");
    options[1].text = t("riskHighOnly");
    options[2].text = t("riskMediumPlus");
    options[3].text = t("riskWithoutTls");
  }

  const repOptions = reputationSourceSelect?.options || [];
  if (repOptions.length >= 4) {
    repOptions[0].text = t("repDnsblFocus");
    repOptions[1].text = t("repPrivacyFocus");
    repOptions[2].text = t("repCommunityFocus");
    repOptions[3].text = t("repCrowdsecFocus");
  }


  const repCheckLabels = [
    ["config-rep-dnsbl", "DNSBL"],
    ["config-rep-privacy", currentLanguage === "en" ? "Privacy" : "Privacy"],
    ["config-rep-community", currentLanguage === "en" ? "Community" : "Community"],
    ["config-rep-crowdsec", "CrowdSec"],
  ];
  repCheckLabels.forEach(([id, label]) => {
    const input = document.getElementById(id);
    if (input?.parentElement) {
      input.parentElement.lastChild.textContent = ` ${label}`;
    }
  });

  const scanHeaders = document.querySelectorAll("#resolve-table th");
  if (scanHeaders.length >= 7) {
    const labels = ["Subdomain", "A", "CNAME", "TLS", t("resolveTableHistory"), "Risk", "Details"];
    labels.forEach((text, idx) => {
      scanHeaders[idx].textContent = text;
    });
  }

  const knownIntro = document.querySelector(".known-ports-top p");
  if (knownIntro) {
    knownIntro.textContent = t("knownPortsIntro");
  }

  const continueText = document.querySelector("#continue-area p");
  if (continueText) {
    continueText.textContent = t("continuePrompt");
  }

  configPasswordInput.placeholder = "RESOLVER_PASSWORD";
  configSiteTitleInput.placeholder = "DNS / IP-Resolver";
  configCrowdsecInput.placeholder = "xxx";
  configAccessPasswordInput.placeholder = t("accessPlaceholder");
  debugTestIpInput.placeholder = "8.8.8.8";
  debugTestDomainInput.placeholder = currentLanguage === "en" ? "example.com" : "example.com";
  singlePortInput.placeholder = t("singlePortInputPlaceholder") || "22 oder 80,443,8080";
  configLogoName.textContent = configLogoFileInput.files?.[0]?.name || t("noFile");
  configFaviconName.textContent = configFaviconFileInput.files?.[0]?.name || t("noFile");
  updateAccessPasswordState(hasSavedAccessPassword);
  updateCrowdSecMaskState();

  if (activeIp && !lastKnownScanData && !lastFullScanData && (!lastSinglePortChecks || !lastSinglePortChecks.length)) {
    scanSummary.textContent =
      currentLanguage === "en"
        ? `Active target IP: ${activeIp}. Start port scans manually via the button.`
        : `Aktive Ziel-IP: ${activeIp}. Portscan startest du manuell über den Button.`;
    reputationSummary.textContent =
      currentLanguage === "en"
        ? `Active target IP: ${activeIp}. Run reputation checks manually via the button.`
        : `Aktive Ziel-IP: ${activeIp}. Reputation prüfst du manuell über den Button.`;
  }

  if (lastAnalysis?.targetType === "domain" && lastAnalysis?.domainIntel) {
    const count = (lastAnalysis.domainIntel.subdomains || []).length;
    subdomainsCount.textContent =
      count > 0
        ? currentLanguage === "en"
          ? `${count} discovered subdomains (CT logs, best effort)`
          : `${count} gefundene Subdomains (CT-Logs, Best-Effort)`
        : currentLanguage === "en"
          ? "No subdomains found or source unavailable."
          : "Keine Subdomains gefunden oder Quelle nicht verfügbar.";
  }
}

function applyHistoryVisibility(snapshot) {
  const hasGeo = Boolean(snapshot?.geo);
  const hasReputation = Boolean(snapshot?.reputation);
  const hasManualChecks = Array.isArray(snapshot?.singlePortChecks) && snapshot.singlePortChecks.length > 0;
  const hasScan = Boolean(
    snapshot?.knownScan ||
      snapshot?.fullScan ||
      hasManualChecks
  );

  geoResult.classList.toggle("hidden", !hasGeo);
  reputationResult.classList.toggle("hidden", !hasReputation);
  scanResult.classList.toggle("hidden", !hasScan);

  knownPortsInfo.classList.add("hidden");
  singlePortCheck.classList.add("hidden");
  continueArea.classList.add("hidden");

  if (hasScan) {
    renderHistoryPortColumns(snapshot);
    openPortsEl.classList.add("hidden");
  } else {
    historyScanColumns.classList.add("hidden");
    historyScanColumns.innerHTML = "";
  }

  if (!hasScan) {
    openPortsEl.classList.add("hidden");
  }
}

function renderHistoryPortColumns(snapshot) {
  const manualChecks = Array.isArray(snapshot?.singlePortChecks) ? snapshot.singlePortChecks : [];
  const known = snapshot?.knownScan || null;
  const restScanned = Array.isArray(snapshot?.scannedRestPorts) ? snapshot.scannedRestPorts : [];
  const restOpen = Array.isArray(snapshot?.openRestPorts) ? snapshot.openRestPorts : [];

  const columns = [];

  const openLabel = currentLanguage === "en" ? "open" : "offen";
  const closedLabel = currentLanguage === "en" ? "closed" : "geschlossen";

  if (manualChecks.length) {
    const entries = manualChecks
      .slice(0, 120)
      .map((entry) => ({
        label: `${entry.port} (${entry.service || "?"}) ${entry.open ? openLabel : closedLabel}`,
        open: Boolean(entry.open),
        sortPort: Number(entry.port) || 0,
      }));
    columns.push(createHistoryPortColumn(t("manualChecked"), entries, manualChecks.length));
  }

  if (known) {
    const knownCatalog = Array.isArray(snapshot?.analysis?.knownPorts) ? snapshot.analysis.knownPorts : [];
    const knownServiceByPort = new Map(knownCatalog.map((entry) => [Number(entry.port), entry.service || "?"]));
    const selected = Array.isArray(known.selectedKnownPorts)
      ? known.selectedKnownPorts
      : Array.isArray(snapshot?.lastKnownScannedPorts)
        ? snapshot.lastKnownScannedPorts
        : [];
    const openSet = new Set((known.openPorts || []).map((entry) => entry.port));
    const entries = selected
      .slice(0, 160)
      .map((port) => ({
        label: `${port} (${knownServiceByPort.get(Number(port)) || inferServiceForPort(Number(port))}) ${openSet.has(port) ? openLabel : closedLabel}`,
        open: openSet.has(port),
        sortPort: Number(port) || 0,
      }));
    columns.push(
      createHistoryPortColumn(
        currentLanguage === "en" ? "Known ports scan" : "Bekannte Ports geprüft",
        entries,
        selected.length
      )
    );
  }

  if (restScanned.length) {
    const openSet = new Set(restOpen.map((entry) => entry.port));
    const restServiceByPort = new Map(restOpen.map((entry) => [Number(entry.port), entry.service || "?"]));
    const entries = restScanned
      .slice(0, 220)
      .map((port) => ({
        label: `${port} (${restServiceByPort.get(Number(port)) || inferServiceForPort(Number(port))}) ${openSet.has(port) ? openLabel : closedLabel}`,
        open: openSet.has(port),
        sortPort: Number(port) || 0,
      }));
    columns.push(
      createHistoryPortColumn(
        currentLanguage === "en" ? "Remaining ports scan" : "Weitere Ports geprüft",
        entries,
        restScanned.length
      )
    );
  }

  historyScanColumns.innerHTML = columns.join("");
  historyScanColumns.classList.toggle("hidden", columns.length === 0);
}

function createHistoryPortColumn(title, entries, totalCount) {
  const items = entries
    .sort((a, b) => {
      if (a.open !== b.open) {
        return a.open ? -1 : 1;
      }
      return (a.sortPort || 0) - (b.sortPort || 0);
    })
    .map((entry) => {
      return `<span class="history-port-item ${entry.open ? "open" : "closed"}">${escapeHtml(entry.label)}</span>`;
    })
    .join("");

  const more = totalCount > entries.length
    ? `<span class="history-port-item closed">+${totalCount - entries.length} ${currentLanguage === "en" ? "more" : "weitere"}</span>`
    : "";

  return `
    <article class="history-port-column">
      <h4>${escapeHtml(title)}</h4>
      <div class="history-port-list">${items}${more}</div>
    </article>
  `;
}

function setStartPanelVisible(visible) {
  startPanel.classList.toggle("hidden", !visible);
}

function renderRestScanSnapshot() {
  const totalRestPorts = Math.max(0, 6500 - (lastKnownScannedPorts?.length || 0));
  const merged = mergePorts(knownOpenPorts, openRestPorts);
  const isComplete = totalRestPorts > 0 && scannedRestPorts.length >= totalRestPorts;

  scanResult.classList.remove("hidden");
  scanPhase.textContent = isComplete
    ? (currentLanguage === "en" ? "Stage 2: Full scan up to 6500" : "Stufe 2: Vollscan bis 6500")
    : (currentLanguage === "en" ? "Stage 2: Partial scan" : "Stufe 2: Teilscan");
  scanSummary.textContent =
    `${scannedRestPorts.length}/${totalRestPorts} restliche Ports geprüft. ` +
    `Insgesamt ${merged.length} offene Ports bis 6500.`;
  renderPorts(merged);
  continueArea.classList.toggle("hidden", isComplete);
}

function persistHistoryStore() {
  try {
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(scanHistory));
  } catch (error) {
    /* ignore */
  }
}

function queueHistoryPersist() {
  if (historyPersistTimer) {
    clearTimeout(historyPersistTimer);
  }

  historyPersistTimer = setTimeout(() => {
    historyPersistTimer = null;
    persistHistoryStore();
    void pushHistoryToServer();
  }, 220);
}

async function pushHistoryToServer() {
  if (historyPersistInFlight) {
    historyPersistQueued = true;
    return;
  }

  historyPersistInFlight = true;
  try {
    const response = await fetch("/api/history", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ items: scanHistory }),
    });

    if (!response.ok) {
      return;
    }
  } catch (error) {
    /* ignore */
  } finally {
    historyPersistInFlight = false;
    if (historyPersistQueued) {
      historyPersistQueued = false;
      void pushHistoryToServer();
    }
  }
}

async function pullHistoryFromServer() {
  try {
    const response = await fetch("/api/history");
    if (!response.ok) {
      return null;
    }

    const payload = await response.json().catch(() => null);
    if (!payload || !Array.isArray(payload.items)) {
      return null;
    }

    return payload.items;
  } catch (error) {
    return null;
  }
}

async function initHistoryStore() {
  const serverItems = await pullHistoryFromServer();
  if (Array.isArray(serverItems)) {
    scanHistory = serverItems;
  } else {
    try {
      const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      scanHistory = Array.isArray(parsed) ? parsed : [];
    } catch (error) {
      scanHistory = [];
    }
  }

  pruneHistory();
  persistHistoryStore();
  void pushHistoryToServer();
  renderHistoryList();
  loadHistoryFromUrl();
}

function createHistoryId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `scan_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

void bootApp();

async function bootApp() {
  const ready = await checkResolverStatus();
  if (!ready) {
    return;
  }

  await loadLocales();
  applyLanguage();
  await loadBranding();
  await loadConfigPublic();
  await initHistoryStore();
}

function delay(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function localizeMessage(message) {
  if (!message) {
    return message;
  }

  const maps = {
    en: {
      "Bitte eine IPv4-Adresse oder Domain eingeben.": "Please enter an IPv4 address or domain.",
      "Bitte zuerst ein Ziel analysieren.": "Please analyze a target first.",
      "Bitte zuerst eine Analyse starten.": "Please start an analysis first.",
      "Bitte mindestens einen gültigen Port angeben.": "Please enter at least one valid port.",
      "Bitte Resolver-Passwort eingeben.": "Please enter the resolver password.",
      "Bitte zuerst die Konfiguration entsperren.": "Please unlock the configuration first.",
      "Noch keine Analyse zum Export vorhanden.": "No analysis available for export yet.",
      "JSON-Export erstellt.": "JSON export created.",
      "Konfigurationsbereich geöffnet.": "Configuration panel opened.",
      "Konfiguration entsperrt.": "Configuration unlocked.",
      "Konfiguration gespeichert.": "Configuration saved.",
      "Konfiguration konnte nicht gespeichert werden.": "Configuration could not be saved.",
      "Konfiguration konnte nicht geladen werden.": "Configuration could not be loaded.",
      "Reputation erfolgreich geladen.": "Reputation loaded successfully.",
      "Reputation-Prüfung fehlgeschlagen.": "Reputation check failed.",
      "Scanne bekannte Ports ...": "Scanning known ports ...",
      "Prüfe angegebene Ports ...": "Checking selected ports ...",
      "Vollständiger Portscan abgeschlossen.": "Full port scan completed.",
      "Restlicher Portscan wurde abgebrochen.": "Remaining port scan was aborted.",
      "Auflösung läuft ...": "Resolving ...",
      "Keine Subdomains zum Auflösen vorhanden.": "No subdomains available to resolve.",
      "Auflösung fehlgeschlagen.": "Resolution failed.",
      "GeoIP lädt ...": "Loading GeoIP ...",
      "Analysiere ...": "Analyzing ...",
      "GeoIP jetzt laden": "Load GeoIP now",
    },
    nl: {
      "Bitte eine IPv4-Adresse oder Domain eingeben.": "Voer een IPv4-adres of domein in.",
      "Bitte zuerst ein Ziel analysieren.": "Analyseer eerst een doel.",
      "Bitte zuerst eine Analyse starten.": "Start eerst een analyse.",
      "Bitte mindestens einen gültigen Port angeben.": "Voer minstens een geldige poort in.",
      "Bitte Resolver-Passwort eingeben.": "Voer het resolver-wachtwoord in.",
      "Bitte zuerst die Konfiguration entsperren.": "Ontgrendel eerst de configuratie.",
      "Noch keine Analyse zum Export vorhanden.": "Nog geen analyse beschikbaar voor export.",
      "JSON-Export erstellt.": "JSON-export aangemaakt.",
      "Konfigurationsbereich geöffnet.": "Configuratiepaneel geopend.",
      "Konfiguration entsperrt.": "Configuratie ontgrendeld.",
      "Konfiguration gespeichert.": "Configuratie opgeslagen.",
      "Konfiguration konnte nicht gespeichert werden.": "Configuratie kon niet worden opgeslagen.",
      "Konfiguration konnte nicht geladen werden.": "Configuratie kon niet worden geladen.",
      "Reputation erfolgreich geladen.": "Reputatie succesvol geladen.",
      "Reputation-Prüfung fehlgeschlagen.": "Reputatiecontrole mislukt.",
      "Scanne bekannte Ports ...": "Bekende poorten worden gescand ...",
      "Prüfe angegebene Ports ...": "Geselecteerde poorten worden gecontroleerd ...",
      "Vollständiger Portscan abgeschlossen.": "Volledige poortscan voltooid.",
      "Restlicher Portscan wurde abgebrochen.": "Resterende poortscan is afgebroken.",
      "Auflösung läuft ...": "Resolutie bezig ...",
      "Keine Subdomains zum Auflösen vorhanden.": "Geen subdomeinen om op te lossen.",
      "Auflösung fehlgeschlagen.": "Resolutie mislukt.",
      "GeoIP lädt ...": "GeoIP wordt geladen ...",
      "Analysiere ...": "Analyseren ...",
      "GeoIP jetzt laden": "GeoIP nu laden",
    },
    fr: {
      "Bitte eine IPv4-Adresse oder Domain eingeben.": "Veuillez saisir une adresse IPv4 ou un domaine.",
      "Bitte zuerst ein Ziel analysieren.": "Analysez d'abord une cible.",
      "Bitte zuerst eine Analyse starten.": "Démarrez d'abord une analyse.",
      "Bitte mindestens einen gültigen Port angeben.": "Veuillez saisir au moins un port valide.",
      "Bitte Resolver-Passwort eingeben.": "Veuillez saisir le mot de passe du résolveur.",
      "Bitte zuerst die Konfiguration entsperren.": "Déverrouillez d'abord la configuration.",
      "Noch keine Analyse zum Export vorhanden.": "Aucune analyse à exporter pour le moment.",
      "JSON-Export erstellt.": "Export JSON créé.",
      "Konfigurationsbereich geöffnet.": "Panneau de configuration ouvert.",
      "Konfiguration entsperrt.": "Configuration déverrouillée.",
      "Konfiguration gespeichert.": "Configuration enregistrée.",
      "Konfiguration konnte nicht gespeichert werden.": "Impossible d'enregistrer la configuration.",
      "Konfiguration konnte nicht geladen werden.": "Impossible de charger la configuration.",
      "Reputation erfolgreich geladen.": "Réputation chargée avec succès.",
      "Reputation-Prüfung fehlgeschlagen.": "Échec de la vérification de réputation.",
      "Scanne bekannte Ports ...": "Analyse des ports connus ...",
      "Prüfe angegebene Ports ...": "Vérification des ports sélectionnés ...",
      "Vollständiger Portscan abgeschlossen.": "Analyse complète des ports terminée.",
      "Restlicher Portscan wurde abgebrochen.": "L'analyse des ports restants a été interrompue.",
      "Auflösung läuft ...": "Résolution en cours ...",
      "Keine Subdomains zum Auflösen vorhanden.": "Aucun sous-domaine à résoudre.",
      "Auflösung fehlgeschlagen.": "Échec de la résolution.",
      "GeoIP lädt ...": "Chargement GeoIP ...",
      "Analysiere ...": "Analyse en cours ...",
      "GeoIP jetzt laden": "Charger GeoIP",
    },
  };

  const activeMap = maps[currentLanguage] || null;
  return activeMap?.[message] || message;
}

function debugReasonText(reason, ok) {
  const value = String(reason || "").trim();
  if (!value) {
    return ok ? "OK" : (currentLanguage === "de" ? "Fehler" : currentLanguage === "fr" ? "Échec" : currentLanguage === "nl" ? "Mislukt" : "Fail");
  }

  const dictionary = {
    rate_limited: currentLanguage === "de" ? "Verbindung OK / Rate-Limited" : currentLanguage === "fr" ? "Connexion OK / Limite atteinte" : currentLanguage === "nl" ? "Verbinding OK / Rate-limited" : "Connection OK / Rate-limited",
    http_429: currentLanguage === "de" ? "Verbindung OK / API-Limit erreicht" : currentLanguage === "fr" ? "Connexion OK / Limite API atteinte" : currentLanguage === "nl" ? "Verbinding OK / API-limiet bereikt" : "Connection OK / API limit reached",
    request_failed: currentLanguage === "de" ? "Anfrage fehlgeschlagen" : currentLanguage === "fr" ? "Requête échouée" : currentLanguage === "nl" ? "Aanvraag mislukt" : "Request failed",
    mmdb_unavailable: currentLanguage === "de" ? "MMDB nicht verfügbar" : currentLanguage === "fr" ? "MMDB indisponible" : currentLanguage === "nl" ? "MMDB niet beschikbaar" : "MMDB unavailable",
    no_data: currentLanguage === "de" ? "Keine Daten" : currentLanguage === "fr" ? "Aucune donnée" : currentLanguage === "nl" ? "Geen gegevens" : "No data",
    disabled_in_config: currentLanguage === "de" ? "In Config deaktiviert" : currentLanguage === "fr" ? "Désactivé dans la config" : currentLanguage === "nl" ? "Uitgeschakeld in config" : "Disabled in config",
  };

  if (value.includes("|")) {
    return value.split("|").map((part) => debugReasonText(part.trim(), ok)).join(" | ");
  }
  if (/^http_\d+$/.test(value)) {
    const code = value.replace("http_", "");
    return currentLanguage === "de"
      ? `Verbindung OK / HTTP ${code}`
      : currentLanguage === "fr"
        ? `Connexion OK / HTTP ${code}`
        : currentLanguage === "nl"
          ? `Verbinding OK / HTTP ${code}`
          : `Connection OK / HTTP ${code}`;
  }
  return dictionary[value] || value;
}

function inferServiceForPort(port) {
  const map = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
  };
  return map[Number(port)] || "?";
}
