'use strict';

// Helpers shared by every consumer process in the harness. Written as CommonJS so both the ESM
// consumers (`import shared from './_shared.cjs'`) and the legacy CommonJS sender can use it.

const crypto = require('node:crypto');
const fs = require('node:fs');

function parseArgs(argv) {
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

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function percentiles(samples) {
  if (samples.length === 0) {
    return null;
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const at = q => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
  return {
    count: sorted.length,
    p50: round(at(0.5)),
    p95: round(at(0.95)),
    max: round(sorted[sorted.length - 1]),
  };
}

function round(n) {
  return Math.round(n * 100) / 100;
}

/** The key wrap algorithm named in a packed body's JWE protected header. No crypto involved. */
function keyWrapFromBody(body) {
  const { encryptedAESKey } = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  const header = encryptedAESKey.split('.')[0];
  return JSON.parse(Buffer.from(header, 'base64url').toString('utf8')).alg;
}

function buildPayload(args) {
  if (args['payload-file']) {
    return JSON.parse(fs.readFileSync(args['payload-file'], 'utf8'));
  }
  return {
    cluster_uuid: 'harness-cluster-0000',
    timestamp: '2026-09-07T00:00:00.000Z',
    stack_stats: { kibana: { versions: [{ version: '9.2.0', count: 3 }] } },
  };
}

/**
 * Drives one sender: encrypts a payload, POSTs the packed body to the receiver, records the result.
 * Runs `concurrency` workers until either `count` requests have been sent or `duration-ms` elapses.
 */
async function driveSender({ encrypt, args, label }) {
  const url = args.url;
  const kids = String(args.kids).split(',');
  const payload = buildPayload(args);
  const payloadSha = sha256(JSON.stringify(payload));
  const count = args.count ? Number(args.count) : null;
  const durationMs = args['duration-ms'] ? Number(args['duration-ms']) : null;
  const concurrency = Number(args.concurrency || 1);
  const deadline = durationMs != null ? Date.now() + durationMs : Infinity;

  const state = { label, sent: 0, ok: 0, failed: 0, latency: [], byAlg: {}, errors: [] };

  const worker = async () => {
    while (true) {
      if (count != null && state.sent >= count) {
        return;
      }
      if (Date.now() >= deadline) {
        return;
      }
      const kid = kids[state.sent % kids.length];
      state.sent++;
      const started = Date.now();
      try {
        const body = await encrypt(kid, payload);
        const alg = keyWrapFromBody(body);
        state.byAlg[alg] = (state.byAlg[alg] || 0) + 1;
        const response = await fetch(url, {
          method: 'POST',
          headers: { 'content-type': 'text/plain', 'x-payload-sha256': payloadSha },
          body,
        });
        const result = await response.json().catch(() => ({}));
        if (response.ok && result.ok === true) {
          state.ok++;
        } else {
          state.failed++;
          pushError(state, `${response.status} ${result.reason || result.error || 'unknown'}`);
        }
      } catch (err) {
        state.failed++;
        pushError(state, err.message);
      }
      state.latency.push(Date.now() - started);
    }
  };

  await Promise.all(Array.from({ length: concurrency }, worker));
  return {
    label: state.label,
    sent: state.sent,
    ok: state.ok,
    failed: state.failed,
    byAlg: state.byAlg,
    latencyMs: percentiles(state.latency),
    errors: state.errors,
  };
}

function pushError(state, message) {
  if (state.errors.length < 5) {
    state.errors.push(message);
  }
}

module.exports = {
  buildPayload,
  driveSender,
  keyWrapFromBody,
  parseArgs,
  percentiles,
  sha256,
};
