import { execFile, execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export class SkipError extends Error {}

export function skip(message) {
  throw new SkipError(message);
}

export function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) {
      continue;
    }
    const key = token.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) {
      args[key] = true;
    } else {
      args[key] = next;
      i++;
    }
  }
  return args;
}

/** Runs a command to completion, returning stdout. Throws with stderr attached on failure. */
export function run(command, argv, options = {}) {
  try {
    return execFileSync(command, argv, { encoding: 'utf8', ...options });
  } catch (err) {
    const detail = [err.stdout, err.stderr].filter(Boolean).join('\n').trim();
    throw new Error(`${command} ${argv.join(' ')} failed: ${detail || err.message}`);
  }
}

/** Runs a node script that prints one JSON line, and returns the parsed value. */
export function runJson(nodeBin, script, argv, options = {}) {
  const stdout = run(nodeBin, [script, ...argv], options);
  const line = stdout
    .trim()
    .split('\n')
    .filter(Boolean)
    .at(-1);
  if (!line) {
    throw new Error(`${path.basename(script)} produced no output`);
  }
  return JSON.parse(line);
}

/** Starts a long-lived process and resolves once it prints its `{"ready":true,...}` line. */
export function startProcess(nodeBin, script, argv, options = {}) {
  const child = spawn(nodeBin, [script, ...argv], { ...options, stdio: ['ignore', 'pipe', 'pipe'] });
  const stderr = [];
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', chunk => stderr.push(chunk));

  const ready = new Promise((resolve, reject) => {
    let buffered = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      buffered += chunk;
      const newline = buffered.indexOf('\n');
      if (newline !== -1) {
        try {
          resolve(JSON.parse(buffered.slice(0, newline)));
        } catch (err) {
          reject(new Error(`unparseable ready line: ${buffered.slice(0, newline)}`));
        }
      }
    });
    child.on('exit', code =>
      reject(new Error(`process exited early (${code}): ${stderr.join('').trim()}`))
    );
    child.on('error', reject);
  });

  return { child, ready, stderr };
}

export async function stopProcess(handle) {
  if (handle == null || handle.child.exitCode != null) {
    return;
  }
  handle.child.kill('SIGTERM');
  await new Promise(resolve => {
    handle.child.once('exit', resolve);
    setTimeout(() => {
      handle.child.kill('SIGKILL');
      resolve();
    }, 2000).unref();
  });
}

export async function fetchJson(url, timeoutMs = 5000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      throw new Error(`${url} responded ${response.status}`);
    }
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchText(url, timeoutMs = 5000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      throw new Error(`${url} responded ${response.status}`);
    }
    return await response.text();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Node binaries to run the artifact checks against: the current one, plus the lowest and highest
 * nvm-installed versions at or above the package's engines floor.
 *
 * The floor matters because `zip: DEF` needs `DecompressionStream` (Node 20.12) and `require(esm)`
 * lands at 20.19 / 22.12. The ceiling matters because Kibana — the sender — is on Node 24 (see its
 * `.node-version`), so the newest available runtime is not optional coverage.
 */
export function discoverNodeBinaries(floor = [20, 12, 0]) {
  const found = new Map();
  found.set(process.version, process.execPath);

  const nvmRoot = path.join(os.homedir(), '.nvm', 'versions', 'node');
  if (fs.existsSync(nvmRoot)) {
    const versions = fs
      .readdirSync(nvmRoot)
      .filter(name => /^v\d+\.\d+\.\d+$/.test(name))
      .map(name => ({ name, parts: name.slice(1).split('.').map(Number) }))
      .filter(({ parts }) => compare(parts, floor) >= 0)
      .sort((a, b) => compare(a.parts, b.parts));
    for (const candidate of [versions[0], versions[versions.length - 1]]) {
      if (candidate === undefined) {
        continue;
      }
      const bin = path.join(nvmRoot, candidate.name, 'bin', 'node');
      if (fs.existsSync(bin)) {
        found.set(candidate.name, bin);
      }
    }
  }
  return [...found.entries()]
    .map(([version, bin]) => ({ version, bin, parts: version.slice(1).split('.').map(Number) }))
    .sort((a, b) => compare(a.parts, b.parts))
    .map(({ version, bin }) => ({ version, bin }));
}

function compare(a, b) {
  for (let i = 0; i < 3; i++) {
    if ((a[i] || 0) !== (b[i] || 0)) {
      return (a[i] || 0) - (b[i] || 0);
    }
  }
  return 0;
}

export function percentiles(samples) {
  if (samples.length === 0) {
    return null;
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const at = q => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
  return { count: sorted.length, p50: at(0.5), p95: at(0.95), max: sorted[sorted.length - 1] };
}

export { execFile };
