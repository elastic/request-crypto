// Emulates phases P0-P2 of docs/rsa-oaep-256-migration.md on one machine, end to end:
//
//   P0  the artifact that would be published — packed, installed, imported, type-checked
//   P1  an upgraded receiver serving mixed traffic from a real 2.0.4 sender and a v3 sender
//   P2  a soak over that mix, checking integrity, hook accuracy, memory and latency
//
// Usage:  node run.mjs [--phase all|p0|p1|p2] [--duration-ms 20000] [--concurrency 8]
//                      [--ratio 0.5] [--payload large|small] [--rss-budget-mb 150]
//                      [--published-keys auto|<path>|off] [--skip-install] [--keep]

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { installedVersion, LEGACY_VERSION, setup } from './lib/setup.mjs';
import {
  discoverNodeBinaries,
  fetchText,
  parseArgs,
  run,
  runJson,
  SkipError,
  skip,
  startProcess,
  stopProcess,
} from './lib/util.mjs';

const HARNESS_ROOT = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HARNESS_ROOT, '..');
const WORK_DIR = path.join(HARNESS_ROOT, '.work');
const KEYS_DIR = path.join(WORK_DIR, 'keys');
const KIDS = ['kibana_local1', 'kibana_local_dev1'];
const PUBLISHED_KEYS_URL =
  'https://raw.githubusercontent.com/elastic/kibana/main/src/platform/plugins/shared/telemetry_collection_manager/server/encryption/telemetry_jwks.ts';

const args = parseArgs(process.argv.slice(2));
const phase = args.phase || 'all';
const wants = name => phase === 'all' || phase === name;
const durationMs = Number(args['duration-ms'] || 20000);
const concurrency = Number(args.concurrency || 8);
const ratio = Number(args.ratio || 0.5);
const rssBudgetMb = Number(args['rss-budget-mb'] || 150);
const payloadFile =
  args.payload === 'small' ? null : path.join(REPO_ROOT, 'test', 'fixture', 'large_payload.json');

const results = [];
let receiver = null;

async function check(phaseName, name, fn) {
  const started = Date.now();
  try {
    const detail = await fn();
    results.push({ phase: phaseName, name, status: 'PASS', detail, ms: Date.now() - started });
  } catch (err) {
    if (err instanceof SkipError) {
      results.push({ phase: phaseName, name, status: 'SKIP', detail: err.message });
    } else {
      results.push({
        phase: phaseName,
        name,
        status: 'FAIL',
        detail: err.message,
        ms: Date.now() - started,
      });
    }
  }
}

function log(message) {
  process.stdout.write(`  ${message}\n`);
}

try {
  log(`harness starting — phase=${phase}`);
  const { nextDir, legacyDir, packed, tarball } = setup({
    repoRoot: REPO_ROOT,
    harnessRoot: HARNESS_ROOT,
    workDir: WORK_DIR,
    log,
    skipInstall: Boolean(args['skip-install']),
  });
  const nextVersion = installedVersion(nextDir);
  const legacyVersion = installedVersion(legacyDir);
  log(`consumers ready — v3 candidate ${nextVersion}, legacy ${legacyVersion}`);

  // --keys <dir> points the harness at real key material: a private.json the receiver holds and a
  // sender-jwks.json as published to senders. Otherwise a throwaway pair is generated.
  const keysDir = args.keys ? path.resolve(String(args.keys)) : KEYS_DIR;
  const privateJwksPath = path.join(keysDir, 'private.json');
  const senderJwksPath = path.join(keysDir, 'sender-jwks.json');

  if (args.keys) {
    for (const required of [privateJwksPath, senderJwksPath]) {
      assert.ok(fs.existsSync(required), `--keys ${keysDir} is missing ${path.basename(required)}`);
    }
    log(`using supplied key material from ${keysDir}`);
  } else {
    log('generating key material…');
    const keyInfo = runJson(process.execPath, path.join(nextDir, 'gen-keys.mjs'), [
      '--out',
      keysDir,
      '--kids',
      KIDS.join(','),
    ]);
    log(
      `keys: ${keyInfo.kids.join(', ')} — receiver JWKS stamped ${keyInfo.privateAlgs.join('/')}, ` +
        `sender JWKS stamped ${keyInfo.senderAlgs.join('/')} (production shape)`
    );
  }

  // Take the kids from the JWKS itself, so supplied key material works unchanged.
  const kids = JSON.parse(fs.readFileSync(senderJwksPath, 'utf8')).keys.map(key => key.kid);
  const payloadArgs = payloadFile ? ['--payload-file', payloadFile] : [];

  // ---------------------------------------------------------------- P0: the published artifact
  if (wants('p0')) {
    await check('P0', 'tarball excludes tests, docs and the harness', async () => {
      const listing = run('tar', ['-tzf', tarball]).split('\n').filter(Boolean);
      const forbidden = listing.filter(entry =>
        /^package\/(test|docs|migration-harness|coverage)\//.test(entry)
      );
      assert.deepEqual(forbidden, [], `unexpected entries: ${forbidden.slice(0, 5).join(', ')}`);
      for (const required of ['package/lib/index.js', 'package/lib/index.d.ts', 'package/README.md']) {
        assert.ok(listing.includes(required), `missing ${required}`);
      }
      return `${listing.length} entries, ${(packed.size / 1024).toFixed(0)} KB`;
    });

    await check('P0', 'version is bumped for a breaking release', async () => {
      const { version } = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
      assert.ok(
        version.startsWith('3.'),
        `package version is still ${version}; ESM-only plus the key wrap change needs a major bump ` +
          `before publishing`
      );
      return version;
    });

    const nodes = discoverNodeBinaries();
    log(`artifact checks on ${nodes.map(n => n.version).join(', ')}`);

    const legacyBodyFile = path.join(WORK_DIR, 'legacy-body.json');
    await check('P0', `a ${LEGACY_VERSION} sender's body is decryptable by the artifact`, async () => {
      const emitted = runJson(
        process.execPath,
        path.join(legacyDir, 'legacy-sender.cjs'),
        ['--emit-only', '--jwks', senderJwksPath, '--kids', kids[0], ...payloadArgs]
      );
      assert.equal(emitted.alg, 'RSA-OAEP', 'the legacy sender should wrap with RSA-OAEP');
      fs.writeFileSync(legacyBodyFile, JSON.stringify(emitted));
      return `2.0.4 emitted ${emitted.alg}, ${emitted.body.length} chars`;
    });

    for (const node of nodes) {
      await check('P0', `ESM consumer on ${node.version}`, async () => {
        const probe = runJson(node.bin, path.join(nextDir, 'esm-probe.mjs'), [
          '--private-jwks',
          privateJwksPath,
          '--sender-jwks',
          senderJwksPath,
          '--legacy-body-file',
          legacyBodyFile,
          ...payloadArgs,
        ]);
        assert.equal(probe.emittedAlg, 'RSA-OAEP-256');
        assert.equal(probe.legacy?.decrypted, true);
        return `emits ${probe.emittedAlg}, accepts ${probe.supported.join(' + ')}, legacy body OK`;
      });

      await check('P0', `CommonJS consumer on ${node.version}`, async () => {
        const probe = runJson(node.bin, path.join(nextDir, 'cjs-probe.cjs'), [
          '--private-jwks',
          privateJwksPath,
          '--sender-jwks',
          senderJwksPath,
          ...payloadArgs,
        ]);
        assert.equal(probe.dynamicImport.ok, true, 'await import() must work for CJS consumers');
        return probe.require.ok
          ? 'require(esm) works; await import() works'
          : `require(esm) unavailable (${probe.require.code}); await import() works`;
      });
    }

    await check('P0', 'shipped types resolve under NodeNext', async () => {
      const tsc = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsc');
      if (!fs.existsSync(tsc)) {
        skip('typescript not installed in the repo');
      }
      run(tsc, [
        '--noEmit',
        '--strict',
        '--skipLibCheck',
        '--target',
        'es2022',
        '--module',
        'nodenext',
        '--moduleResolution',
        'nodenext',
        path.join(nextDir, 'types-probe.ts'),
      ]);
      return 'DecryptorOptions, KeyWrapInfo and the algorithm constants all type-check';
    });

    await check('P0', 'production public keys wrap with RSA-OAEP-256', async () => {
      const mode = args['published-keys'] || 'auto';
      if (mode === 'off') {
        skip('disabled with --published-keys off');
      }
      let jwksPath;
      if (mode !== 'auto' && mode !== true) {
        jwksPath = mode;
      } else {
        let source;
        try {
          source = await fetchText(PUBLISHED_KEYS_URL);
        } catch (err) {
          skip(`could not fetch Kibana's telemetry_jwks.ts (${err.message})`);
        }
        jwksPath = path.join(WORK_DIR, 'published-jwks.json');
        fs.writeFileSync(jwksPath, JSON.stringify(parseTsJwks(source), null, 2));
      }
      const probe = runJson(process.execPath, path.join(nextDir, 'published-keys-probe.mjs'), [
        '--jwks',
        jwksPath,
        ...payloadArgs,
      ]);
      const summary = Object.entries(probe.perKid)
        .map(([kid, info]) => `${kid}: published ${info.publishedAlg} → emitted ${info.emittedAlg}`)
        .join('; ');
      return summary;
    });
  }

  // -------------------------------------------------- P1: upgraded receiver, mixed traffic
  if (wants('p1') || wants('p2')) {
    log('starting the upgraded receiver…');
    receiver = startProcess(process.execPath, path.join(nextDir, 'next-receiver.mjs'), [
      '--jwks',
      privateJwksPath,
      '--port',
      '0',
    ]);
    const { port } = await receiver.ready;
    const url = `http://127.0.0.1:${port}/telemetry`;
    const metricsUrl = `http://127.0.0.1:${port}/metrics`;
    log(`receiver listening on ${port}`);

    if (wants('p1')) {
      await check('P1', `receiver decrypts a ${LEGACY_VERSION} sender's request`, async () => {
        const summary = runJson(process.execPath, path.join(legacyDir, 'legacy-sender.cjs'), [
          '--url',
          url,
          '--jwks',
          senderJwksPath,
          '--kids',
          kids.join(','),
          '--count',
          '4',
          '--concurrency',
          '2',
          ...payloadArgs,
        ]);
        assert.equal(summary.failed, 0, `errors: ${summary.errors.join('; ')}`);
        assert.deepEqual(Object.keys(summary.byAlg), ['RSA-OAEP']);
        return `${summary.ok}/${summary.sent} ok, all RSA-OAEP`;
      });

      await check('P1', 'receiver decrypts a v3 sender request', async () => {
        const summary = runJson(process.execPath, path.join(nextDir, 'next-sender.mjs'), [
          '--url',
          url,
          '--jwks',
          senderJwksPath,
          '--kids',
          kids.join(','),
          '--count',
          '4',
          '--concurrency',
          '2',
          ...payloadArgs,
        ]);
        assert.equal(summary.failed, 0, `errors: ${summary.errors.join('; ')}`);
        assert.deepEqual(Object.keys(summary.byAlg), ['RSA-OAEP-256']);
        return `${summary.ok}/${summary.sent} ok, all RSA-OAEP-256`;
      });

      await check('P1', 'onKeyWrap agrees with what was on the wire', async () => {
        const metrics = await (await fetch(metricsUrl)).json();
        assert.equal(metrics.failures, 0, `receiver failures: ${metrics.errors.join('; ')}`);
        assert.equal(metrics.mismatches, 0, 'payload integrity mismatch');
        assert.deepEqual(
          metrics.fromHook,
          metrics.fromHeader,
          'the hook reported a different mix than the tokens carried'
        );
        assert.deepEqual(Object.keys(metrics.byKid).sort(), [...kids].sort(), 'not all kids served');
        return `${metrics.total} requests, mix ${JSON.stringify(metrics.fromHeader)}, kids ${Object.keys(
          metrics.byKid
        ).join(' + ')}`;
      });
    }

    // ------------------------------------------------------------------------ P2: soak the mix
    if (wants('p2')) {
      const legacyWorkers = Math.max(1, Math.round(concurrency * ratio));
      const nextWorkers = Math.max(1, concurrency - legacyWorkers);
      const before = await (await fetch(metricsUrl)).json();
      log(
        `soaking for ${durationMs}ms — ${legacyWorkers} legacy workers, ${nextWorkers} v3 workers, ` +
          `payload ${payloadFile ? 'large' : 'small'}`
      );

      const senders = await Promise.all([
        runJsonAsync(process.execPath, path.join(legacyDir, 'legacy-sender.cjs'), [
          '--url',
          url,
          '--jwks',
          senderJwksPath,
          '--kids',
          kids.join(','),
          '--duration-ms',
          String(durationMs),
          '--concurrency',
          String(legacyWorkers),
          ...payloadArgs,
        ]),
        runJsonAsync(process.execPath, path.join(nextDir, 'next-sender.mjs'), [
          '--url',
          url,
          '--jwks',
          senderJwksPath,
          '--kids',
          kids.join(','),
          '--duration-ms',
          String(durationMs),
          '--concurrency',
          String(nextWorkers),
          ...payloadArgs,
        ]),
      ]);
      const [legacySummary, nextSummary] = senders;
      const after = await (await fetch(metricsUrl)).json();

      await check('P2', 'no failed requests under sustained mixed traffic', async () => {
        assert.equal(legacySummary.failed, 0, `legacy sender: ${legacySummary.errors.join('; ')}`);
        assert.equal(nextSummary.failed, 0, `v3 sender: ${nextSummary.errors.join('; ')}`);
        assert.equal(after.failures, 0, `receiver: ${after.errors.join('; ')}`);
        return `${legacySummary.ok} legacy + ${nextSummary.ok} v3 requests, 0 failures`;
      });

      await check('P2', 'every payload survived the round trip', async () => {
        assert.equal(after.mismatches, 0, 'a decrypted payload did not match what was sent');
        const received = after.total - before.total;
        assert.equal(
          received,
          legacySummary.ok + nextSummary.ok,
          `receiver saw ${received}, senders reported ${legacySummary.ok + nextSummary.ok} ok`
        );
        return `${received} bodies, sha256 verified on each`;
      });

      await check('P2', 'the rollout metric stays accurate at volume', async () => {
        assert.deepEqual(after.fromHook, after.fromHeader, 'hook counts drifted from the wire');
        // Report the soak's own traffic, not the P1 requests that preceded it.
        const mix = delta(after.fromHeader, before.fromHeader);
        const total = Object.values(mix).reduce((sum, n) => sum + n, 0);
        const legacyShare = (mix['RSA-OAEP'] || 0) / total;
        assert.ok(legacyShare > 0 && legacyShare < 1, 'expected a genuinely mixed sample');
        return `legacy share ${(legacyShare * 100).toFixed(1)}% of ${total} — ${JSON.stringify(mix)}`;
      });

      await check('P2', 'receiver memory stays flat', async () => {
        // Gate on the peak, not the final reading: a large peak followed by a collection would
        // otherwise pass a check named "stays flat" while the same line reports the peak. The
        // sampler in next-receiver.mjs polls every 500 ms, so this is a sampled maximum.
        const growth = after.rss.peakMb - after.rss.startMb;
        assert.ok(
          growth < rssBudgetMb,
          `peak RSS grew ${growth.toFixed(1)} MB (budget ${rssBudgetMb} MB)`
        );
        return `start ${after.rss.startMb} MB → peak ${after.rss.peakMb} MB → end ${after.rss.lastMb} MB`;
      });

      await check('P2', 'decrypt latency per algorithm', async () => {
        const legacyLatency = after.latencyMs['RSA-OAEP'];
        const nextLatency = after.latencyMs['RSA-OAEP-256'];
        assert.ok(legacyLatency && nextLatency, 'expected samples for both algorithms');
        return (
          `RSA-OAEP p50 ${legacyLatency.p50}ms / p95 ${legacyLatency.p95}ms (n=${legacyLatency.count}); ` +
          `RSA-OAEP-256 p50 ${nextLatency.p50}ms / p95 ${nextLatency.p95}ms (n=${nextLatency.count})`
        );
      });
    }
  }
} catch (err) {
  results.push({ phase: 'setup', name: 'harness setup', status: 'FAIL', detail: err.message });
} finally {
  await stopProcess(receiver);
  if (!args.keep && fs.existsSync(KEYS_DIR)) {
    fs.rmSync(KEYS_DIR, { recursive: true, force: true });
  }
}

report();

function report() {
  const width = Math.max(...results.map(r => r.name.length), 20);
  process.stdout.write('\n');
  for (const result of results) {
    const icon = { PASS: '✔', FAIL: '✘', SKIP: '−' }[result.status];
    process.stdout.write(
      `${icon} ${result.phase.padEnd(5)} ${result.name.padEnd(width)}  ${result.detail || ''}\n`
    );
  }
  const failed = results.filter(r => r.status === 'FAIL');
  const skipped = results.filter(r => r.status === 'SKIP');
  process.stdout.write(
    `\n${results.length - failed.length - skipped.length} passed, ${failed.length} failed, ${
      skipped.length
    } skipped\n`
  );
  process.exit(failed.length > 0 ? 1 : 0);
}

/** Async variant of runJson, so two senders can be driven concurrently. */
function runJsonAsync(nodeBin, script, argv) {
  return new Promise((resolve, reject) => {
    const handle = startProcess(nodeBin, script, argv);
    handle.ready.then(resolve, err => reject(new Error(`${path.basename(script)}: ${err.message}`)));
  });
}

/** Per-key difference between two counter snapshots. */
function delta(after, before) {
  const result = {};
  for (const [key, value] of Object.entries(after)) {
    const diff = value - (before[key] || 0);
    if (diff > 0) {
      result[key] = diff;
    }
  }
  return result;
}

/** Extracts the JWKS object literal out of Kibana's telemetry_jwks.ts. */
function parseTsJwks(source) {
  const anchor = source.indexOf('telemetryJWKS');
  const start = source.indexOf('{', anchor);
  const end = source.lastIndexOf('}');
  const literal = source
    .slice(start, end + 1)
    .replace(/'/g, '"')
    .replace(/([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:/g, '$1"$2":')
    .replace(/,(\s*[}\]])/g, '$1');
  return JSON.parse(literal);
}
