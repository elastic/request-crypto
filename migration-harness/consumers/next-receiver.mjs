// The upgraded receiver (phase P1): request-crypto v3 installed from the packed tarball, serving
// HTTP, accepting both key wrap algorithms and reporting which one each request used.
//
// Runs inside .work/next/, so `@elastic/request-crypto` resolves through the installed package's
// own exports map — the same resolution a real consumer gets.

import http from 'node:http';
import fs from 'node:fs';
import { createRequestDecryptor, LEGACY_KEY_WRAP_ALGORITHM } from '@elastic/request-crypto';
import shared from './_shared.cjs';

const { parseArgs, sha256, percentiles, keyWrapFromBody } = shared;
const args = parseArgs(process.argv.slice(2));
const privateJWKS = JSON.parse(fs.readFileSync(args.jwks, 'utf8'));

const state = {
  total: 0,
  failures: 0,
  mismatches: 0,
  fromHeader: {},
  fromHook: {},
  byKid: {},
  latency: {},
  errors: [],
  rss: { startMb: mb(process.memoryUsage().rss), peakMb: 0, lastMb: 0 },
};

// The hook under test: this is what a receiver would wire to its metrics backend to watch legacy
// traffic drain away.
const decryptor = await createRequestDecryptor(privateJWKS, {
  onKeyWrap: ({ kid, alg, legacy }) => {
    bump(state.fromHook, alg);
    bump(state.byKid, kid === undefined ? '<none>' : kid);
    if (legacy !== (alg === LEGACY_KEY_WRAP_ALGORITHM)) {
      pushError(`legacy flag (${legacy}) disagrees with alg (${alg})`);
    }
  },
});

const sampler = setInterval(() => {
  const rss = mb(process.memoryUsage().rss);
  state.rss.lastMb = rss;
  state.rss.peakMb = Math.max(state.rss.peakMb, rss);
}, 500);
sampler.unref();

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    return json(res, 200, { ok: true });
  }
  if (req.method === 'GET' && req.url === '/metrics') {
    return json(res, 200, metrics());
  }
  if (req.method === 'POST' && req.url === '/shutdown') {
    json(res, 200, { ok: true });
    setTimeout(() => process.exit(0), 25);
    return;
  }
  if (req.method !== 'POST' || req.url !== '/telemetry') {
    return json(res, 404, { ok: false, reason: 'not found' });
  }

  const body = await readBody(req);
  const expectedSha = req.headers['x-payload-sha256'];
  state.total++;
  let alg = 'unknown';
  try {
    // Read the algorithm off the wire, independently of the hook, so the two can be compared.
    alg = keyWrapFromBody(body);
    bump(state.fromHeader, alg);

    const started = performance.now();
    const payload = await decryptor.decrypt(body);
    const elapsed = performance.now() - started;
    sample(alg, elapsed);

    if (expectedSha !== undefined && sha256(JSON.stringify(payload)) !== expectedSha) {
      state.mismatches++;
      pushError(`payload integrity mismatch (${alg})`);
      return json(res, 500, { ok: false, alg, reason: 'integrity mismatch' });
    }
    return json(res, 200, { ok: true, alg, ms: Math.round(elapsed * 100) / 100 });
  } catch (err) {
    state.failures++;
    pushError(`${alg}: ${err.code || err.name} ${err.message}`);
    return json(res, 500, { ok: false, alg, error: err.message, code: err.code });
  }
});

server.listen(Number(args.port || 0), '127.0.0.1', () => {
  process.stdout.write(`${JSON.stringify({ ready: true, port: server.address().port })}\n`);
});

// Reservoir sampling keeps the latency percentiles unbiased without the sample buffer itself
// growing with traffic — otherwise the memory check below would be measuring this harness rather
// than the library under test.
const SAMPLE_CAPACITY = 4096;

function sample(alg, elapsed) {
  const bucket = (state.latency[alg] = state.latency[alg] || { seen: 0, samples: [] });
  bucket.seen++;
  if (bucket.samples.length < SAMPLE_CAPACITY) {
    bucket.samples.push(elapsed);
    return;
  }
  const index = Math.floor(Math.random() * bucket.seen);
  if (index < SAMPLE_CAPACITY) {
    bucket.samples[index] = elapsed;
  }
}

function metrics() {
  const latencyMs = {};
  for (const [alg, bucket] of Object.entries(state.latency)) {
    latencyMs[alg] = { ...percentiles(bucket.samples), count: bucket.seen };
  }
  return {
    total: state.total,
    failures: state.failures,
    mismatches: state.mismatches,
    fromHeader: state.fromHeader,
    fromHook: state.fromHook,
    byKid: state.byKid,
    latencyMs,
    rss: state.rss,
    errors: state.errors,
  };
}

function bump(counter, key) {
  counter[key] = (counter[key] || 0) + 1;
}

function pushError(message) {
  if (state.errors.length < 10) {
    state.errors.push(message);
  }
}

function mb(bytes) {
  return Math.round((bytes / 1024 / 1024) * 10) / 10;
}

function json(res, status, payload) {
  const encoded = JSON.stringify(payload);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(encoded) });
  res.end(encoded);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.setEncoding('utf8');
    req.on('data', chunk => (data += chunk));
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}
