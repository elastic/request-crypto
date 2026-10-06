# Migration harness — phases P0 to P2, locally

Emulates the first three phases of [../docs/rsa-oaep-256-migration.md](../docs/rsa-oaep-256-migration.md)
on one machine, so the `RSA-OAEP` → `RSA-OAEP-256` key wrap migration can be exercised before
anything reaches a live environment.

```bash
cd migration-harness
npm run harness              # P0 + P1 + P2, ~2 minutes
npm run p0                   # just the artifact checks
npm run p1                   # just the mixed-traffic checks
npm run soak                 # P2 for five minutes
```

No dependencies to install — the harness provisions what it needs under `.work/` (gitignored).

## What is actually real here

The point of the harness is that the old path is not simulated:

| Piece | What it really is |
|---|---|
| The v3 build | `npm pack` of the working tree, installed from the tarball. `npm pack` runs the package's `prepare` script, so the artifact is built from a clean tree with lint and tests passing. |
| The old sender | `@elastic/request-crypto@2.0.4` installed from the npm registry — CommonJS, backed by node-jose. |
| The receiver | A separate process serving HTTP, resolving the package through its published `exports` map. |
| The transport | Real HTTP POSTs of the packed body, with a `sha256` of the payload in a header so integrity is verified rather than assumed. |
| The keys | Freshly generated, but shaped like production (see below). Optionally your own — `--keys <dir>`. |

### The key shape is the whole trick

`gen-keys.mjs` writes two JWKS from one key pair:

- `private.json` — what the receiver holds, stamped `alg: "RSA-OAEP-256"` because v3 generates keys that way.
- `sender-jwks.json` — the same public keys, stamped `alg: "RSA-OAEP"`, which is what every public key published to senders looks like today (see Kibana's `telemetry_jwks.ts`).

Both senders read the *same* `sender-jwks.json`. The 2.0.4 sender follows the `alg` member and wraps
with `RSA-OAEP`; the v3 sender ignores it and wraps with `RSA-OAEP-256`. That is phase P3 traffic,
reproduced without touching a real key.

## What each phase asserts

**P0 — the artifact that would be published**

- the tarball excludes `test/`, `docs/`, `migration-harness/` and includes `lib/index.js`, `lib/index.d.ts`
- the package version has had its major bump (see *Expected failure* below)
- a body produced by the real 2.0.4 decrypts through the packed artifact, and the hook reports `legacy: true`
- ESM `import` and CommonJS `require`/`await import` both work, on the current Node plus the lowest and highest installed versions at or above the `engines` floor. The floor matters because `zip:DEF` needs `DecompressionStream` (Node 20.12) and `require(esm)` lands at 20.19 / 22.12; the ceiling matters because Kibana runs Node 24 (`.node-version`). Locally that means 20.19.4, 22.22.0 and 24.19.0 — all green.
- the shipped `.d.ts` types `DecryptorOptions`, `KeyWrapInfo` and the algorithm constants under NodeNext
- Kibana's **real published** `kibana1` / `kibana_dev1` public keys wrap with `RSA-OAEP-256` (encryption only — the private halves belong to @elastic/platform-analytics)

**P1 — upgraded receiver, mixed traffic**

- the receiver decrypts requests from the 2.0.4 sender, all `RSA-OAEP`
- it decrypts requests from the v3 sender, all `RSA-OAEP-256`
- `onKeyWrap` reports exactly the mix the tokens carried on the wire, across every `kid`

The last one matters more than it looks: the receiver reads each body's protected header itself,
with no crypto, and compares that count against what the hook reported. If the hook ever
misattributed traffic, the metric steering the rollout would lie.

**P2 — soak**

- zero failed requests under sustained mixed traffic
- every payload verified by `sha256` after decryption, and the receiver's request count reconciled against both senders'
- the hook stays accurate at volume
- receiver RSS stays within budget (`--rss-budget-mb`, default 150)
- decrypt latency reported per algorithm, so the cost of SHA-256 is measured rather than assumed

## Measured on an M-series laptop, Node 22.22

| Soak | Requests | Failures | Peak RSS | `RSA-OAEP` p50 | `RSA-OAEP-256` p50 |
|---|---|---|---|---|---|
| 20 s | 27,903 | 0 | 119.2 MB | 2.76 ms | 2.86 ms |
| 90 s | 128,543 | 0 | 119.5 MB | 2.71 ms | 2.81 ms |

Two things worth reading off that: **4.6× the traffic left peak memory unchanged**, which is what
you want from the per-algorithm key import cache, and **SHA-256 costs about 0.1 ms**, roughly 4%,
on a ~12 KB body. Neither number is a reason to hesitate.

## Options

| Flag | Default | Purpose |
|---|---|---|
| `--phase all\|p0\|p1\|p2` | `all` | Which phase to run. |
| `--duration-ms` | `20000` | P2 soak length. |
| `--concurrency` | `8` | Total sender workers, split by `--ratio`. |
| `--ratio` | `0.5` | Share of workers on the legacy sender. |
| `--payload large\|small` | `large` | `large` uses `test/fixture/large_payload.json` (~12 KB body). |
| `--rss-budget-mb` | `150` | Fails P2 if receiver RSS grows past this. |
| `--keys <dir>` | generated | Use your own `private.json` + `sender-jwks.json`. |
| `--published-keys auto\|<path>\|off` | `auto` | Fetches Kibana's `telemetry_jwks.ts`; skips if offline. |
| `--skip-install` | off | Reuse `.work/` installs (faster reruns). |
| `--keep` | off | Keep generated keys in `.work/keys/` for inspection. |

### Running it against your own keys

@elastic/platform-analytics can point the harness at real key material before phase P1, without any
of it leaving the machine:

```bash
mkdir -p /tmp/harness-keys
# private.json     — the receiver's private JWKS
# sender-jwks.json — the public JWKS as published to senders (alg: "RSA-OAEP")
node run.mjs --keys /tmp/harness-keys --phase p1
```

The `kid`s are read from the JWKS, so nothing else needs changing.

## Expected failure

`version is bumped for a breaking release` fails until `package.json` is bumped to a `3.x` version
(`3.0.0-alpha.1` counts). That is deliberate — the harness treats P0 as *the artifact that would be
published*, and publishing this as `2.0.x` would hand an ESM-only package with a changed key wrap to
consumers expecting a patch. Run the harness before **each** publish, alpha and GA: it is the gate on
P0.1 and P0.4 in the migration doc.

## What this cannot tell you

- **FIPS mode.** A stock Node build has no loadable FIPS provider, so whether a FIPS-only provider
  refuses SHA-1 OAEP — and therefore whether enabling FIPS mode on the receiver before P4 would
  break legacy senders — has to be checked in a FIPS-enabled runtime. See the migration doc.
- **Phase P3's negative case.** That a 2.0.4 *receiver* rejects an `RSA-OAEP-256` token is a
  property of node-jose, not of this package; the migration doc carries a reproducible script for it
  instead.
- **Anything about real traffic volumes, network behaviour, or the receiver's own service.** This is
  a library harness. It says the crypto and the rollout metric behave; it says nothing about your
  deployment.
