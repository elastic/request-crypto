# Migrating the key wrap algorithm to RSA-OAEP-256

Status: proposed, tracked by [#56](https://github.com/elastic/request-crypto/pull/56).
Sender: Kibana (`telemetry_collection_manager`). Receiver:
[`aqueduct/decrypt`](https://github.com/elastic/telemetry/blob/main/aqueduct/decrypt/package.json)
in `elastic/telemetry`, owned by @elastic/platform-analytics. The receiver bump is tracked in
[elastic/telemetry#7527](https://github.com/elastic/telemetry/issues/7527).

This document covers the *key wrap* migration only. Everything else about the token — content
encryption, compression, serialization, the packed body — is unchanged.

## What changes

| Parameter | Before | After |
|---|---|---|
| Key wrap (`alg`) | `RSA-OAEP` — RSAES-OAEP, SHA-1 + MGF1-SHA-1 | **encrypt:** `RSA-OAEP-256` only.<br>**decrypt:** `RSA-OAEP-256` *or* `RSA-OAEP`, chosen per token |
| Content encryption (`enc`) | `A128CBC-HS256` | unchanged, now pinned on decrypt |
| Compression (`zip`) | `DEF` (raw DEFLATE) | unchanged, now with an explicit 250 KB inflate ceiling |
| Serialization | JWE compact, header `{zip, enc, alg, kid}` | unchanged |
| JWK `alg` on newly generated keys | `RSA-OAEP` | `RSA-OAEP-256` |

`RSA-OAEP` is RSAES-OAEP with SHA-1 and MGF1-SHA-1, which is not FIPS 140-3 approved. `RSA-OAEP-256`
is the same scheme with SHA-256 and MGF1-SHA-256.

Note that the JWK `alg` member no longer decides anything at runtime: keys are imported for whichever
algorithm is needed, so the public keys Kibana already ships — all stamped `alg: "RSA-OAEP"` — wrap
with `RSA-OAEP-256` without being rotated or re-published.

## Compatibility matrix

| Sender | Receiver | Result |
|---|---|---|
| request-crypto ≤2.x (`RSA-OAEP`) | ≤2.x | works — today's production path |
| request-crypto ≤2.x (`RSA-OAEP`) | ≥3.x | **works** — receiver reads `alg` from the header and uses the SHA-1 binding |
| request-crypto ≥3.x (`RSA-OAEP-256`) | ≥3.x | works |
| request-crypto ≥3.x (`RSA-OAEP-256`) | **≤2.x** | **fails** — see below |

The last row is the constraint the whole rollout order hangs on, and it was verified against real
node-jose 2.2.0, not assumed. node-jose intersects a key's usable algorithms with the JWK's own
`alg` member (`JWK.Key#algorithms()` in `cisco/node-jose lib/jwk/basekey.js`), and its keystore then
only offers keys that support the token's algorithm:

```
jwk alg on the stored key: RSA-OAEP | algorithms("unwrap"): [ 'RSA-OAEP' ]
2.x receiver + RSA-OAEP-256 token -> Error: no key found
```

Because every private JWK in production is stamped `alg: "RSA-OAEP"`, a 2.x receiver rejects an
`RSA-OAEP-256` token outright — and it surfaces as `no key found`, which reads like a key
configuration problem rather than an algorithm mismatch. **Receivers must be upgraded and deployed
before any sender starts emitting `RSA-OAEP-256`.**

## Rollout

Each phase has an exit gate. Do not start a phase before the previous gate is green.

### P0 — publish an alpha, prove it, then publish 3.0.0

Nothing here changes any traffic: publishing does not upgrade anybody. The point of the alpha is to
put the real artifact through Kibana's CI (including FIPS) and through the staging receiver, so
that the GA release is a formality rather than a leap.

[#59](https://github.com/elastic/request-crypto/pull/59) is merged, and this branch includes it, so
the publish workflow derives the dist-tag from the version. A bare `npm publish` uses the `latest`
dist-tag regardless of the semver prerelease component; the workflow is what keeps an alpha off
`latest`.

#### P0.1 — publish `3.0.0-alpha.1`

Run the harness first (`cd migration-harness && npm run harness`); its *version is bumped for a
breaking release* check exists precisely to gate this step. Then follow the release process in the
README: bump `version` in a PR against `main`, tag the merge commit `v3.0.0-alpha.1`, and publish a
GitHub release for that tag with **Set as a pre-release** checked.

The workflow derives the dist-tag from the version: anything containing a `-` publishes under
**`next`**, so `latest` keeps pointing at 2.0.4 and nobody picks the alpha up by accident.

*Gate:* `npm view @elastic/request-crypto dist-tags` shows `next: 3.0.0-alpha.1` with `latest`
unchanged, and the published tarball carries provenance.

#### P0.2 — alpha in Kibana's CI, including FIPS

Open a **draft** PR against `elastic/kibana` bumping `"@elastic/request-crypto"` in
[`package.json`](https://github.com/elastic/kibana/blob/main/package.json) from `2.0.4` to
`3.0.0-alpha.1` (pin the exact version, as Kibana already does) and refreshing `yarn.lock`. Kibana
is a sender and only ever encrypts, so the blast radius is one plugin:
`src/platform/plugins/shared/telemetry_collection_manager/server/encryption/`.

```bash
# from a Kibana checkout, on a branch
yarn add --exact @elastic/request-crypto@3.0.0-alpha.1
GH_PAGER=cat gh pr create --draft -R elastic/kibana \
  --title 'Bump @elastic/request-crypto to 3.0.0-alpha.1 (RSA-OAEP-256 key wrap)' \
  --body '…'
GH_PAGER=cat gh pr edit <number> -R elastic/kibana \
  --add-label 'ci:enable-fips-140-3-agent' --add-label 'ci:build-docker-fips'
GH_PAGER=cat gh pr checks <number> -R elastic/kibana
```

How FIPS actually gets exercised, since this is easy to get wrong:

- **`ci:enable-fips-140-3-agent`** is the one that matters. `getAgentImageConfig` swaps the agents
  for FIPS images when any FIPS label is present (`.buildkite/pipeline-utils/agent_images.ts`), and
  the label also sets `TEST_ENABLE_FIPS_VERSION=140-3`, so **the normal suites run under FIPS** and
  a `Verify FIPS Enabled` step is added. Buildkite annotates the build with a warning that FIPS mode
  can produce new test failures — expect to have to separate pre-existing FIPS flakes from anything
  this bump caused.
- **`ci:build-docker-fips`** additionally builds a FIPS image, but that step is `soft_fail: true`:
  it will not fail the build. Read its result, do not infer it from a green tick.
- The nightly `kibana-fips` pipeline (buildkite.com/elastic/kibana-fips, notifying `#kibana-fips`)
  runs against `main`, so it only covers this after merge. Use the labels to get the signal *before*.

Two specific things to watch, because they are where an ESM-only package bites a CJS host:

- Kibana runs Node `24.19.0` (`.node-version`), comfortably above this package's `>=20.12` floor.
  The harness covers 20.19, 22.x and 24.19 for both `import` and `require`.
- `encrypt.test.mocks.ts` replaces the package wholesale with `jest.doMock`, so Kibana's unit tests
  never load the real ESM module. That is why the suite passing is *not* evidence the import works —
  the FIPS/functional runs and a real Kibana boot are.

*Gate:* CI green with the FIPS agent label (or every failure traced to a pre-existing FIPS issue);
telemetry encryption verified end to end in a running Kibana; the PR stays a draft — it is a probe,
not a change we intend to merge yet.

#### P0.3 — alpha on the staging receiver

Staging is where the alpha meets a live receiver. The bump of
[`aqueduct/decrypt`](https://github.com/elastic/telemetry/blob/main/aqueduct/decrypt/package.json)
to `3.0.0-alpha.1` is tracked in
[elastic/telemetry#7527](https://github.com/elastic/telemetry/issues/7527). Once the alpha is
published, that service is upgraded on staging.

The first measure, before that deploy, is tests in `aqueduct/decrypt` for a legacy body and a
new-format body. Those tests live in that service.

Staging then receives both kinds of body: legacy `RSA-OAEP`, which is everything real senders
still emit, and `RSA-OAEP-256` bodies sent at it on purpose. `onKeyWrap` should report that mix.
Wire the hook here; staging is where you find out whether the metric lands, not production.

The harness can be pointed at real key material first, so this is not the first time the alpha meets
those keys:

```bash
cd migration-harness
node run.mjs --keys /path/to/your/keys --phase p1   # private.json + sender-jwks.json
```

*Gate:* staging `aqueduct/decrypt` on the alpha; both formats decrypt; the events land in the stack
telemetry index and the BigQuery view; `onKeyWrap` reports the mix that was sent.

#### P0.4 — publish `3.0.0`

Bump to `3.0.0`, tag, release without the pre-release box — the workflow publishes it under
`latest`. Nothing is deployed by this; it just makes the version installable.

*Gate:* P0.2 and P0.3 green; `latest: 3.0.0`.

### P1 — production receiver (decrypt-capable, fleet traffic unchanged)

Production `aqueduct/decrypt` bumps to `3.0.0`. Staging already proved the alpha. Fleet traffic is
still `RSA-OAEP`, and stays working: the receiver accepts both algorithms and picks per token.
While upgrading, wire the `onKeyWrap` hook to a counter — this is the instrument the rest of the
rollout is steered by:

```ts
const decryptor = await createRequestDecryptor(privateJWKS, {
  onKeyWrap: ({ alg, kid, legacy }) => {
    metrics.increment('telemetry.request_crypto.key_wrap', { alg, kid, legacy: String(legacy) });
  },
});
```

The counter records one increment per request the receiver fully decrypted and served, labelled by
the key wrap algorithm that request's token carried. A body whose payload fails to decrypt is not
counted, which keeps the counter reconcilable with served traffic; `getJWKMetadata` recovers the
algorithm for such a body from the error handler.

After the production deploy, and before any Kibana sender switches, send one `RSA-OAEP-256` sample
from a local machine. That sample must decrypt, show up on the counter, and land in the stack
telemetry index and the BigQuery view.

*Gate:* production `aqueduct/decrypt` on `3.0.0`; fleet decrypt error rate flat; the counter shows
fleet traffic still on `RSA-OAEP`; the controlled `RSA-OAEP-256` sample is visible in the counter,
the stack telemetry index, and BigQuery.

### P2 — soak the receiver

Leave the receiver on v3 with legacy-only traffic for at least one full release/reporting cycle
(suggest ≥1 week, covering a weekly telemetry peak).

*Gate:* no increase in decrypt failures, `no key found`, or `ERR_JOSE_ALG_NOT_ALLOWED`; no latency
regression on the decrypt path.

### P3 — sender switches

Kibana bumps to v3 and begins emitting `RSA-OAEP-256`. Traffic is now mixed, and stays mixed for a
long time: every Kibana version already in the field keeps sending `RSA-OAEP`, and self-managed
clusters upgrade on their own schedule.

*Gate:* the counter shows a non-zero and rising `RSA-OAEP-256` share with no corresponding rise in
decrypt failures. Verify with a dev Kibana build against `kibana_dev1` before the production key.

### P4 — drain

Watch the legacy share decay as older Kibana versions age out. This is bounded by Kibana version
EOL, so expect a multi-year tail — that is expected and costs nothing, since accepting both
algorithms is not a security regression for the new one.

*Gate:* `RSA-OAEP` share at zero for an agreed window (suggest ≥1 release cycle past the EOL of the
last Kibana version that shipped a pre-v3 request-crypto).

### P5 — drop legacy

Remove `LEGACY_KEY_WRAP_ALGORITHM` from `SUPPORTED_KEY_WRAP_ALGORITHMS` in `src/jwks.ts` — a
one-line change, deliberately isolated there — and release it as a major. Only after this is the
receiver free of SHA-1 on this path, which is also the precondition for running it under a FIPS-only
crypto provider (see below).

One `aqueduct/decrypt` process covers both algorithms, which is why the rollout is a version bump
of that service. A second decrypt service is the fallback for a later decision to reject legacy
tokens while still accepting events from clusters that have not upgraded.

*Gate:* P4 gate held for the agreed window; @elastic/platform-analytics sign-off.

## Local validation

### Emulating P0–P2 before deploying anything

[`migration-harness/`](../migration-harness/README.md) runs phases P0 to P2 on one machine, with the
old path not simulated: the v3 build comes from `npm pack`, the un-upgraded sender is
`@elastic/request-crypto@2.0.4` from the npm registry, and bodies travel over real HTTP.

```bash
cd migration-harness
npm run harness          # P0 + P1 + P2
npm run soak             # five-minute P2
node run.mjs --keys /path/to/your/keys --phase p1   # against your own key material
```

Measured here (M-series laptop, Node 22.22), as a baseline to compare your own run against:

| Soak | Requests | Failures | Peak RSS | `RSA-OAEP` p50 | `RSA-OAEP-256` p50 |
|---|---|---|---|---|---|
| 20 s | 27,903 | 0 | 119.2 MB | 2.76 ms | 2.86 ms |
| 90 s | 128,543 | 0 | 119.5 MB | 2.71 ms | 2.81 ms |

4.6× the traffic left peak memory unchanged, and SHA-256 costs roughly 0.1 ms (~4%) per request on a
~12 KB body. The harness also confirmed that Kibana's **real published** `kibana1` / `kibana_dev1`
public keys — stamped `alg: "RSA-OAEP"` — wrap with `RSA-OAEP-256` untouched, and that `onKeyWrap`
reports exactly the mix the tokens carried on the wire at volume, which is the property the P2 and
P4 gates depend on.

### The unit suite

The automated suite covers the matrix above:

```bash
npm run lint          # tslint + prettier
npm test              # mocha via tsx
npm run test:coverage # c8
npm run build         # tsc
```

What proves what:

| Spec | Proves |
|---|---|
| `test/key-wrap.spec.ts` → *encryption side* | encrypt emits `RSA-OAEP-256` even from a JWK stamped `alg: "RSA-OAEP"` (the production shape) |
| `test/key-wrap.spec.ts` → *decryption side* | frozen node-jose vectors for **both** algorithms decrypt; an end-to-end legacy sender simulation decrypts; both algorithms interleaved and concurrent on one manager |
| `test/key-wrap.spec.ts` → *the JWK's own alg member* | a key stamped `alg: "RSA-OAEP-256"` still reads legacy tokens; a JWKS with no `alg` member reads both; one JWKS serves a different algorithm per `kid`, on distinct key material |
| `test/key-wrap.spec.ts` → *legacy requests through the full request path* | legacy metadata through `getJWKMetadata`; a large legacy payload round trips |
| `test/key-wrap.spec.ts` → *pinned algorithms* | an out-of-allowlist `alg`/`enc` is rejected; a compression bomb is rejected at the inflate ceiling |
| `test/key-wrap.spec.ts` → *onKeyWrap* | the rollout metric reports the right algorithm and cannot break a request |
| `test/compat.spec.ts` | the rest of the wire format is still byte-identical to node-jose output |

Note what the suite deliberately does **not** cover: that a 2.x receiver rejects `RSA-OAEP-256`.
That is a property of node-jose, not of this package, so asserting it in CI would mean re-adding the
dependency to test someone else's library. The reproducible evidence lives in the section above
instead. The half of the constraint that *is* ours — that this version never emits the legacy
algorithm — is asserted.

### Regenerating the frozen vectors

The frozen `RSA-OAEP-256` vector in `test/key-wrap.spec.ts` was produced with real node-jose so that
it proves cross-library compatibility. To regenerate (outside the repo, node-jose is not a
dependency):

```bash
npm init -y && npm install node-jose@2.2.0
# fixtures.json = { privateJWKS, publicJWKS } dumped from test/fixture/*.ts
node -e '
const jose = require("node-jose");
const { publicJWKS } = require("./fixtures.json");
(async () => {
  // node-jose pins a key to its JWK "alg", so import without it to wrap with SHA-256.
  const { alg, ...pub } = publicJWKS.keys[0];
  const key = await jose.JWK.asKey(pub);
  console.log(await jose.JWE.createEncrypt(
    { format: "compact", zip: true, fields: { alg: "RSA-OAEP-256" } }, key
  ).update(Buffer.from("<plaintext>", "utf8")).final());
})();'
```

### Driving the full matrix by hand

The unit tests simulate a 2.x sender with jose. To exercise the matrix against *real* node-jose
bodies — including the failure that dictates the phase order — build two throwaway scripts outside
the repo, in a directory with `node-jose@2.2.0`, `@elastic/node-crypto@1.2.3`, and a `fixtures.json`
holding `{ privateJWKS, publicJWKS }` dumped from `test/fixture/*.ts`.

**A 2.x sender** (`old-sender.cjs`) — AES-encrypt the payload, wrap the passphrase with the legacy
key wrap, pack both:

```js
const jose = require('node-jose');
const crypto = require('crypto');
// node-crypto is CJS-with-default; unwrap it or you get "nodeCrypto is not a function".
const nodeCrypto = require('@elastic/node-crypto').default || require('@elastic/node-crypto');
const { publicJWKS } = require('./fixtures.json');

(async () => {
  const payload = { cluster: 'abc', metrics: [1, 2, 3] };
  const passphrase = crypto.randomBytes(32);
  const encryptedPayload = await nodeCrypto({ encryptionKey: passphrase }).encrypt(payload);
  const key = await jose.JWK.asKey(publicJWKS.keys[0]);
  const encryptedAESKey = await jose.JWE.createEncrypt({ format: 'compact', zip: true }, key)
    .update(passphrase)
    .final();
  const body = jose.util.base64url.encode(
    JSON.stringify({ encryptedAESKey, encryptedPayload }), 'utf8'
  );
  console.log(JSON.stringify({ body, payload }));
})();
```

**A 2.x receiver** (`old-receiver.cjs`) — a node-jose keystore built from the production-shaped
private JWKS, i.e. keys stamped `alg: "RSA-OAEP"`:

```js
const jose = require('node-jose');
const { privateJWKS } = require('./fixtures.json');

(async () => {
  const ks = await jose.JWK.asKeyStore(privateJWKS);
  const key = ks.get(privateJWKS.keys[0].kid);
  console.log('algorithms("unwrap"):', key.algorithms('unwrap'));  // [ 'RSA-OAEP' ]
  try {
    await jose.JWE.createDecrypt(ks).decrypt('<encryptedAESKey from a v3 sender>');
  } catch (e) {
    console.log('expected failure:', e.message);                   // no key found
  }
})();
```

Feed the bodies across the four combinations. Verified outcomes:

| Case | Result |
|---|---|
| 0. 2.x sender → 2.x receiver | `OK (passphrase bytes: 32)` — today's baseline |
| 1. v3 sender → v3 receiver | `OK`, `onKeyWrap` reports `{ alg: 'RSA-OAEP-256', legacy: false }` |
| 2. 2.x sender → v3 receiver | `OK`, `onKeyWrap` reports `{ alg: 'RSA-OAEP', legacy: true }` |
| 3. v3 sender → 2.x receiver | `FAILS: no key found` |

## Cloud / staging validation

1. **Replay legacy traffic.** Staging `aqueduct/decrypt` on the alpha replays captured `RSA-OAEP`
   bodies. Every one must decrypt, the `onKeyWrap` counter must report `legacy: true`, and the
   events must land in the stack telemetry index and the BigQuery view.
2. **Drive the new algorithm at staging.** Send `RSA-OAEP-256` bodies at the same staging receiver.
   A dev Kibana build (v3 dependency) pointed at staging with `kibana_dev1` is one way to produce
   them. Confirm those documents land in the same index and BigQuery view, and that the counter
   reports both algorithms side by side.
3. **Watch the failure modes explicitly.** Alert on decrypt failure rate, `no key found`, and
   `ERR_JOSE_ALG_NOT_ALLOWED`. The first is what a premature sender switch would look like on an
   un-upgraded receiver; the last is what a genuinely unexpected algorithm looks like.
4. **Production canary.** Because senders roll out per Kibana release, P3 is inherently canaried —
   the first upgraded clusters are a small share of traffic. Do not accelerate it with a forced
   upgrade until the mixed-traffic gate has held.
5. **Key rotation is not required.** Existing keys keep working. If a key *is* rotated with v3, the
   new JWK is stamped `alg: "RSA-OAEP-256"`; a pre-v3 sender reading that JWK would then wrap with
   SHA-256, which only a v3 receiver can read. Do not publish a v3-generated key to senders until
   P1 is complete.

## FIPS mode: verify before enabling

Accepting `RSA-OAEP` means the receiver still performs SHA-1 OAEP whenever a legacy token arrives. A
FIPS-only crypto provider may refuse that operation outright, in which case **enabling FIPS mode on
the receiver before P4 would break legacy senders**.

This could not be settled locally: a stock Node build has no loadable FIPS provider
(`node --enable-fips` fails to `dlopen` `fips.dylib`, and `crypto.setFips(1)` then makes *every*
digest fail with `ERR_OSSL_EVP_UNSUPPORTED`, so it is not a usable simulation). It has to be checked
in a genuinely FIPS-enabled runtime:

```bash
# On a FIPS-capable Node/OpenSSL build, with a FIPS provider actually loaded:
node --enable-fips -e 'require("crypto").getFips()'   # must print 1
npm test                                              # legacy specs tell you the answer
```

**What P0.2 does and does not settle.** Kibana's FIPS CI answers the *sender* question — whether
`RSA-OAEP-256` encryption works under a FIPS provider — and that is the half that has to work for
Kibana to run FIPS-enabled at all. It says nothing about the receiver decrypting legacy `RSA-OAEP`
under FIPS, because Kibana never decrypts. Answering the receiver half needs either the command
above in a FIPS runtime, or a FIPS-enabled staging receiver at P0.3. If staging is not
FIPS-enabled, this question stays open.

The case for keeping SHA-1 on the receiver is that this path is decrypt-only. That case is what
would carry the receiver through 2030, and decrypt-only exemptions often continue past a cutoff.
It has not been granted. Until it is, the reading below applies.

Expected reading of the result:

- If legacy decryption works under FIPS, the receiver can enable FIPS mode at any point.
- If it fails, the receiver cannot enable FIPS mode until P4/P5, and the migration order becomes:
  receiver upgrade → senders migrate → legacy dropped → FIPS mode enabled.

Either way the sender side is FIPS-clean from P3 onwards, since it only ever performs SHA-256 OAEP.

If the FIPS suites fail on the P0.2 PR, triage them with the `/debug-fips-failure` skill rather than
by eye — most red in that pipeline is pre-existing FIPS flake, and the skill's job is separating
that from a real regression.

## Rollback

| Situation | Action |
|---|---|
| v3 receiver misbehaves, before P3 | Roll the receiver back to 2.x. Safe: no sender is emitting `RSA-OAEP-256` yet. |
| v3 receiver misbehaves, after P3 | **Do not roll the receiver back** — it would start rejecting every upgraded sender with `no key found`. Fix forward, or roll the *sender* back by pinning Kibana's request-crypto dependency. |
| A sender needs to revert | Pin request-crypto to 2.x in that Kibana branch; the v3 receiver keeps accepting its legacy tokens indefinitely. |
| The alpha misbehaves anywhere in P0 | Close the draft Kibana PR, roll staging `aqueduct/decrypt` back to 2.0.4, fix, publish `3.0.0-alpha.2`. Nothing is at stake: the alpha only ever lived on the `next` dist-tag, in one draft Kibana PR and on staging. |

The rollback window for the receiver therefore closes when the first sender ships v3. Confirm the P2
gate before letting P3 start.

## Sign-off checklist

- [x] #59 merged, so prereleases publish under `next` instead of `latest`
- [ ] P0.1 — `3.0.0-alpha.1` published, `latest` still on 2.0.4
- [ ] P0.2 — draft Kibana PR bumped to the alpha, CI green with `ci:enable-fips-140-3-agent`
- [ ] P0.3 — staging `aqueduct/decrypt` on the alpha; old and new bodies decrypt and land in the stack telemetry index and BigQuery; `onKeyWrap` shows that mix
- [ ] P0.4 — `3.0.0` published under `latest`
- [ ] P1 — production `aqueduct/decrypt` on `3.0.0`; fleet traffic still legacy; the controlled `RSA-OAEP-256` sample visible in the counter, the stack telemetry index, and BigQuery
- [ ] P2 — soak clean for the agreed window
- [ ] @elastic/platform-analytics acknowledges the receiver-first ordering and the closed rollback
      window
- [ ] FIPS-mode behaviour for legacy tokens determined and recorded above
- [ ] P3 — Kibana on v3, mixed traffic healthy
- [ ] P4 — legacy share at zero for the agreed window
- [ ] P5 — legacy algorithm removed in a major release
