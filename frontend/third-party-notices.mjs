import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const OWNED = ['THIRD_PARTY_NOTICES.txt', 'inventory.json', 'UI-LICENSE', 'UI-THIRD_PARTY.md'];

// Conservative inventory of every locked production dependency, including
// dependencies tree-shaken from the bundle. Build tools marked dev are omitted.
// Read actual upstream license/notice files, never synthesize license text from
// SPDX metadata. npm ci must have installed the exact lock before this runs.
export function writeThirdPartyNotices(root, output, { ui = false } = {}) {
  const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
  if (lock.lockfileVersion < 2 || !lock.packages) throw new Error('Notice generation requires a v2/v3 npm lockfile');
  const inventory = [];
  const sections = [];
  let uiFiles;
  for (const [path, entry] of Object.entries(lock.packages).sort(([a], [b]) => a.localeCompare(b, 'en'))) {
    if (!path || entry.dev) continue;
    if (!/^node_modules\//.test(path) || path.split('/').includes('..') || entry.link) throw new Error(`Unsupported notice package path: ${path}`);
    const dir = join(root, path);
    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    if (pkg.version !== entry.version) throw new Error(`Notice version mismatch: ${path}; run npm ci`);
    const files = readdirSync(dir, { withFileTypes: true })
      .filter(f => f.isFile() && /^(licen[sc]e|copying|notice|copyright)([.-]|$)/i.test(f.name))
      .map(f => f.name).sort();
    const texts = files.map(file => ({ file, text: readFileSync(join(dir, file), 'utf8') }));
    let source, provenance;
    if (!files.some(f => /^(licen[sc]e|copying)([.-]|$)/i.test(f))) {
      const index = new URL('./notice-overrides/index.json', import.meta.url);
      const overrides = existsSync(index) ? JSON.parse(readFileSync(index, 'utf8')) : {};
      const override = overrides[`${pkg.name}@${pkg.version}`];
      if (!override || !entry.integrity || override.integrity !== entry.integrity) throw new Error(`Missing upstream license text: ${pkg.name}@${pkg.version}`);
      source = override.source;
      provenance = override.provenance;
      texts.push({file: 'LICENSE (pinned upstream source)', text: readFileSync(new URL(`./notice-overrides/${override.file}`, import.meta.url), 'utf8')});
      files.push(override.file);
    }
    // UI ships its own aggregate for fonts, icons and dependencies/assets.
    if (pkg.name === '@synopackageland/ui') {
      uiFiles = {
        'UI-LICENSE': readFileSync(join(dir, 'LICENSE'), 'utf8'),
        'UI-THIRD_PARTY.md': readFileSync(join(dir, 'LICENSES/THIRD_PARTY.md'), 'utf8'),
      };
    }
    inventory.push({ name: pkg.name, version: pkg.version, license: pkg.license ?? entry.license ?? 'unknown', integrity: entry.integrity, path, files, ...(source ? {source, provenance} : {}) });
    sections.push(`\n===== ${pkg.name}@${pkg.version} (${pkg.license ?? entry.license ?? 'unknown'}) =====\n` + (source ? `Source: ${source}\n${provenance}\n` : '') + texts.map(({ file, text }) => `\n--- ${file} ---\n${text}\n`).join(''));
  }
  if (ui && !uiFiles) throw new Error('UI dependency is missing from the locked production inventory');
  // Replace only the files this writer owns: the App may keep its own legal
  // texts in the same directory (ui/licenses is ui/LICENSES on macOS).
  mkdirSync(output, { recursive: true });
  for (const name of OWNED) rmSync(join(output, name), { force: true });
  writeFileSync(join(output, 'THIRD_PARTY_NOTICES.txt'), 'Locked production dependency notices (conservative superset of bundled code).\n' + sections.join(''));
  writeFileSync(join(output, 'inventory.json'), JSON.stringify(inventory, null, 2) + '\n');
  for (const [name, text] of Object.entries(uiFiles ?? {})) writeFileSync(join(output, name), text);
}
