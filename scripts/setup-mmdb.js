const fs = require("fs");
const path = require("path");

const projectRoot = path.resolve(__dirname, "..");
const targetDir = path.join(projectRoot, "data");
const cityTargetFromEnv = String(process.env.GEOIP_MMDB_PATH || process.env.GEOIP_CITY_MMDB_PATH || "").trim();
const asnTargetFromEnv = String(process.env.GEOIP_ASN_MMDB_PATH || "").trim();

const datasets = [
  {
    label: "city",
    targetFile: cityTargetFromEnv || path.join(targetDir, "GeoLite2-City.mmdb"),
    sources: [
      "@ip-location-db/geolite2-city-mmdb/geolite2-city-ipv4.mmdb",
      "@ip-location-db/geolite2-city-mmdb/geolite2-city-ipv6.mmdb",
    ],
  },
  {
    label: "asn",
    targetFile: asnTargetFromEnv || path.join(targetDir, "GeoLite2-ASN.mmdb"),
    sources: [
      "@ip-location-db/geolite2-asn-mmdb/geolite2-asn-ipv4.mmdb",
      "@ip-location-db/geolite2-asn-mmdb/geolite2-asn-ipv6.mmdb",
    ],
  },
];

function resolveFirstExistingSource(candidates) {
  for (const modPath of candidates) {
    try {
      const resolved = require.resolve(modPath, { paths: [projectRoot] });
      if (fs.existsSync(resolved)) {
        return resolved;
      }
    } catch (error) {
      /* ignore */
    }
  }
  return null;
}

function ensureDataDir() {
  fs.mkdirSync(targetDir, { recursive: true });
}

function ensureParentDir(filePath) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
}

function copyDatasetIfNeeded(dataset) {
  const sourceFile = resolveFirstExistingSource(dataset.sources);
  if (!sourceFile) {
    console.log(`[mmdb] ${dataset.label}: source package not found, skipping.`);
    return;
  }

  ensureDataDir();
  ensureParentDir(dataset.targetFile);

  if (fs.existsSync(dataset.targetFile)) {
    const targetStat = fs.statSync(dataset.targetFile);
    const sourceStat = fs.statSync(sourceFile);
    if (targetStat.size === sourceStat.size && targetStat.mtimeMs >= sourceStat.mtimeMs) {
      console.log(`[mmdb] ${dataset.label}: existing ${dataset.targetFile} is up to date.`);
      return;
    }
  }

  fs.copyFileSync(sourceFile, dataset.targetFile);
  console.log(`[mmdb] ${dataset.label}: copied ${path.basename(sourceFile)} -> ${dataset.targetFile}`);
}

datasets.forEach(copyDatasetIfNeeded);
