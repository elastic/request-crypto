// Phase P0: the shipped .d.ts must actually resolve and type the new surface under NodeNext. This
// file is only ever type-checked, never run.

import {
  createRequestDecryptor,
  createRequestEncryptor,
  DecryptorOptions,
  KEY_WRAP_ALGORITHM,
  KeyWrapInfo,
  LEGACY_KEY_WRAP_ALGORITHM,
  MAX_DECOMPRESSED_LENGTH,
  PrivateJWKS,
  PublicJWKS,
  SUPPORTED_KEY_WRAP_ALGORITHMS,
} from '@elastic/request-crypto';

const options: DecryptorOptions = {
  onKeyWrap: (info: KeyWrapInfo): void => {
    const legacy: boolean = info.legacy;
    const alg: string = info.alg;
    const kid: string | undefined = info.kid;
    void legacy;
    void alg;
    void kid;
  },
};

export async function roundTrip(publicJWKS: PublicJWKS, privateJWKS: PrivateJWKS, kid: string) {
  const encryptor = await createRequestEncryptor(publicJWKS);
  const decryptor = await createRequestDecryptor(privateJWKS, options);

  // The optional second argument must remain optional.
  await createRequestDecryptor(privateJWKS);

  const wrapAlgorithms: string[] = [...SUPPORTED_KEY_WRAP_ALGORITHMS];
  const limit: number = MAX_DECOMPRESSED_LENGTH;
  const current: string = KEY_WRAP_ALGORITHM;
  const legacyAlgorithm: string = LEGACY_KEY_WRAP_ALGORITHM;
  void wrapAlgorithms;
  void limit;
  void current;
  void legacyAlgorithm;

  const body = await encryptor.encrypt(kid, { hello: 'world' });
  const metadata = await decryptor.getJWKMetadata(body);
  const headerAlg: string = metadata.header.alg;
  void headerAlg;

  return decryptor.decrypt(body);
}
