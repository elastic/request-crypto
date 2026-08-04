# Changelog

## 3.0.0 (2026-08-04)

### Summary

Removes `node-jose` and replaces it with Node.js built-ins (`node:crypto` + `node:zlib`). The wire
format is **unchanged** — tokens produced by 2.x and 3.x are byte-compatible in both directions,
so no re-encryption or coordinated deploy is required.

**Removes 15 transitive packages (~14.7 MB)** - leaves one runtime dependency:
`@elastic/node-crypto`.

Requires **Node.js ≥ 16**.

---

### Breaking changes

#### The wire format does not change

Byte-compatible in both directions with `node-jose`. No coordinated deploy, no re-encryption, and
the encrypt and decrypt sides can be upgraded independently in either order.

#### API changes (compile-time)

| # | Change | Only reachable if… |
|---|---|---|
| 1 | `createJWKS(jwk, jwks?)` → `createJWKS(jwks?)` | you passed a node-jose `JWK` object as arg 1 |
| 2 | `createJWKManager(jwks?, jwk?)` → `createJWKManager(jwks?, options?)` | you passed `jose.JWK` as arg 2 |
| 3 | `new JWKSManager(store, jwk, jwe)` → `new JWKSManager(store, options?)` | same |
| 4 | `JWKSManager.store: any` → `KeyStore` | you called node-jose keystore methods on `.store` |
| 5 | `JWKMetadata` / `JWKDecryptResult` no longer alias `@types/node-jose` types | you relied on `@types/node-jose` resolving transitively through this package |

Items 1–4 are only constructible by importing `node-jose` directly, which is the library being
removed. Item 5 is structurally identical — the standalone interfaces have the same members in the
same order.

#### API changes (runtime)

6. **`JWKDecryptResult.key.keystore` is removed.** It was a live node-jose back-reference to the
   private keystore. It was already invisible to typed consumers (`JWKMetadata` excluded it), so
   only untyped JavaScript could reach it. As a side effect, `getJWKMetadata().key` is now a flat
   snapshot rather than a live key handle, so metadata can be logged without leaking key material.

7. **A wrong-key / same-kid unwrap failure now throws `'decryption failed'`, not `'no key found'`.**
   node-jose funnelled RSA unwrap failures into `no key found`; the replacement substitutes a random
   CEK so the failure is indistinguishable from a MAC mismatch (RFC 3218 / RFC 7516 §11 defence).
   The three cases that *are* asserted in practice — unknown kid, public-only store, unknown `alg`
   — still produce `'no key found'` from the store lookup.

8. **New 250 KB cap on inflated plaintext.** node-jose had no decompression limit. The request
   encryption path has ~7,800× headroom (a 32-byte AES key inflated). If you encrypted large
   buffers directly through `JWKSManager.encrypt()`, use the new `maxDecompressedSize` option:
   ```js
   await createRequestDecryptor(privateJWKS, { maxDecompressedSize: 500_000 });
   ```

9. **`removeKey` now works.** Previously a silent no-op (zero test coverage). It now removes all
   entries matching the given `kid`.

10. **`createJWKS(nonJWKS)` throws `TypeError`** instead of returning an empty store.

11. **Unsupported `enc` values (e.g. `A256GCM`) throw** instead of silently decrypting.

12. **`insertKey` with `form !== 'json'`** throws `'unsupported form: <form>'` instead of a
    `SyntaxError`.

13. **Integer-like `kid` values** retain insertion order in `toJSON` instead of node-jose's
    accidental numeric-first reordering.

#### Environment

14. **`engines: { "node": ">=16" }` is new.** Node < 16 will not work — the required built-ins
    (`crypto.createPublicKey({format:'jwk'})`, `Buffer 'base64url'`) were introduced in Node 15–16.

---

### New features

- `KeyStore` and `StoredKey` are now exported from the package root (`src/keystore.ts`).
- `JWKSManagerOptions.maxDecompressedSize` — configurable decompression limit, threaded through
  all factory functions (`createRequestDecryptor`, `createJWKManager`, `createJWKSManager`).
- `RSA_OAEP_256_ALGORITHM` (`'RSA-OAEP-256'`) exported from `src/jwks.ts` — keys tagged with
  `alg: RSA-OAEP-256` now encrypt and decrypt correctly (previously they were silently
  accepted but produced wrong output because node-jose derived the hash from the `alg` string,
  which the replacement now also does).
