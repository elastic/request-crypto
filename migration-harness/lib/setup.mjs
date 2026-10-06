import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export const LEGACY_VERSION = '2.0.4';

/**
 * Packs the working tree and provisions two throwaway consumers under .work/:
 *
 *   .work/next/   — the packed tarball, i.e. the artifact that would be published
 *   .work/legacy/ — @elastic/request-crypto 2.0.4 straight from the npm registry
 *
 * The consumer scripts are copied into each directory rather than imported from here, so every
 * `import '@elastic/request-crypto'` resolves through the installed package's exports map exactly
 * as a real dependent's would.
 */
export function setup({ repoRoot, harnessRoot, workDir, log, skipInstall }) {
  fs.mkdirSync(workDir, { recursive: true });

  // `npm pack` runs the package's own `prepare` script (clean, lint, test, build), so the tarball
  // is built from a clean tree with the suite passing — part of what P0 is checking.
  log('packing the working tree (runs clean + lint + test + build)…');
  const packOutput = execFileSync(
    'npm',
    ['pack', '--json', '--pack-destination', workDir],
    { cwd: repoRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }
  );
  const parsed = JSON.parse(packOutput.slice(packOutput.indexOf('[')));
  const tarball = path.join(workDir, parsed[0].filename);
  log(`packed ${parsed[0].filename} (${(parsed[0].size / 1024).toFixed(0)} KB)`);

  const nextDir = path.join(workDir, 'next');
  const legacyDir = path.join(workDir, 'legacy');

  provision({
    dir: nextDir,
    name: 'harness-consumer-next',
    type: 'module',
    dependency: `file:${tarball}`,
    harnessRoot,
    log,
    skipInstall,
    label: 'v3 candidate (packed tarball)',
  });
  provision({
    dir: legacyDir,
    name: 'harness-consumer-legacy',
    type: 'commonjs',
    dependency: LEGACY_VERSION,
    harnessRoot,
    log,
    skipInstall,
    label: `${LEGACY_VERSION} (npm registry)`,
  });

  return { tarball, nextDir, legacyDir, packed: parsed[0] };
}

function provision({ dir, name, type, dependency, harnessRoot, log, skipInstall, label }) {
  fs.mkdirSync(dir, { recursive: true });
  const manifest = {
    name,
    version: '1.0.0',
    private: true,
    type,
    dependencies: { '@elastic/request-crypto': dependency },
  };
  const manifestPath = path.join(dir, 'package.json');
  const previous = fs.existsSync(manifestPath) ? fs.readFileSync(manifestPath, 'utf8') : null;
  const next = `${JSON.stringify(manifest, null, 2)}\n`;
  fs.writeFileSync(manifestPath, next);

  const installed = fs.existsSync(path.join(dir, 'node_modules', '@elastic', 'request-crypto'));
  if (!skipInstall && (previous !== next || !installed)) {
    log(`installing ${label} into ${path.basename(dir)}/…`);
    execFileSync('npm', ['install', '--no-audit', '--no-fund', '--no-package-lock', '--silent'], {
      cwd: dir,
      encoding: 'utf8',
      stdio: ['ignore', 'inherit', 'inherit'],
    });
  }

  // Refresh the consumer scripts on every run so edits take effect.
  const consumers = path.join(harnessRoot, 'consumers');
  for (const file of fs.readdirSync(consumers)) {
    fs.copyFileSync(path.join(consumers, file), path.join(dir, file));
  }

  return dir;
}

/** Resolves the installed package version inside a provisioned consumer. */
export function installedVersion(dir) {
  const manifest = path.join(dir, 'node_modules', '@elastic', 'request-crypto', 'package.json');
  return JSON.parse(fs.readFileSync(manifest, 'utf8')).version;
}
