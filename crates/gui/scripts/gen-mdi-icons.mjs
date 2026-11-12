// Generate MDI SVG files from the iconify JSON shipped with the Tauri client.
// Usage (from ssl-proxy-gui): node scripts/gen-mdi-icons.mjs
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const source =
  process.env.MDI_ICONS_JSON ??
  join(root, "..", "ssl-proxy-client-tauri", "node_modules", "@iconify-json", "mdi", "icons.json");

const names = [
  // Vue UI used
  "add",
  "alert",
  "alert-circle-outline",
  "arrow-down-thin",
  "arrow-up-thin",
  "certificate-outline",
  "check",
  "chevron-down",
  "clock-outline",
  "close",
  "close-circle",
  "cloud-download-outline",
  "cog-outline",
  "content-save-outline",
  "delete-outline",
  "earth",
  "exit-to-app",
  "eye-off-outline",
  "eye-outline",
  "file-document-outline",
  "filter-variant",
  "flag-outline",
  "flask-outline",
  "history",
  "information-outline",
  "ip-outline",
  "lan-connect",
  "lan-disconnect",
  "link",
  "loading",
  "math-log",
  "minus",
  "moon-waning-crescent",
  "pencil-outline",
  "pencil-ruler-outline",
  "plus",
  "proxy-outline",
  "refresh",
  "regex",
  "restart",
  "serial-port",
  "shield-alert-outline",
  "shield-link-variant-outline",
  "swap-calls",
  "text-box-outline",
  "translate",
  "undo",
  "update",
  "view-dashboard-outline",
  "virtual-private-network",
  "web",
  "white-balance-sunny",
  // Extra icons used by the GPUI layout
  "chevron-right",
];

const data = JSON.parse(readFileSync(source, "utf8"));
const outputDir = join(root, "assets", "mdi");
mkdirSync(outputDir, { recursive: true });

function resolveIcon(name) {
  if (data.icons[name]) {
    return data.icons[name];
  }
  const alias = data.aliases?.[name];
  if (alias?.parent && data.icons[alias.parent]) {
    return { ...data.icons[alias.parent], ...alias };
  }
  throw new Error(`MDI icon not found: ${name}`);
}

for (const name of names) {
  const icon = resolveIcon(name);
  const left = icon.left ?? 0;
  const top = icon.top ?? 0;
  const width = icon.width ?? data.width ?? 24;
  const height = icon.height ?? data.height ?? 24;
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" ` +
    `viewBox="${left} ${top} ${width} ${height}">${icon.body}</svg>\n`;

  writeFileSync(join(outputDir, `${name}.svg`), svg, "utf8");
}

console.log(`Generated ${names.length} MDI icons into assets/mdi`);
