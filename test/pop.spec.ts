import { SignedPrivateJWK } from '../src';
import { Confirmation, createPOPManager, POPManager } from '../src/pop';
import { mismatchPublicJWKS } from './fixture/mismatch_public_jwks';
import { publicJWK } from './fixture/public_jwk';
import { publicUJWK } from './fixture/public_ujwk';
import { publicComponents } from './helpers';

describe('Proof of Possesssion', () => {
  let manager: POPManager;
  let signature: Confirmation;
  it('creates POP Key', async () => {
    manager = await createPOPManager();
    await manager.addKey();
    const key = manager.getKey();
    expect(key.use).to.eql('pop');
  });
  it('creates identity from key', async () => {
    const identity = manager.getIdentity();
    expect(identity).to.be.a('string');
  });
  it('parses POP Key in identity', async () => {
    const identity = manager.getIdentity();
    const identityPOPKey = await manager.parseIdentity(identity);
    const key = manager.getPublicJWKS().keys[0];
    expect(identityPOPKey).to.eql(key);
  });
  it('parses POP Key in identity', async () => {
    const identity = manager.getIdentity();
    const identityPOPKey = await manager.parseIdentity(identity);
    const key = manager.getPublicJWKS().keys[0];
    expect(identityPOPKey).to.eql(key);
  });
  it('only returns public component in identity', async () => {
    const identity = manager.getIdentity();
    const identityPOPKey = await manager.parseIdentity(identity);
    expect(identityPOPKey).to.have.keys(publicComponents);
  });
  it('creates confirmations from identity', async () => {
    const identity = manager.getIdentity();
    signature = await manager.createSignature(publicUJWK, identity);
    expect(signature).to.be.a('string');
  });
  it('verifies signed JWK using private POP Key', async () => {
    const popJWKS = manager.getPrivateJWKS();
    const SJWK = Object.assign({}, publicUJWK, { cnf: signature });
    const isVerified = await manager.verifyJWK(SJWK, popJWKS);
    expect(isVerified).to.eql(true);
  });
  it('fails to verify unsigned JWK', async () => {
    const popJWKS = manager.getPrivateJWKS();
    const isVerified = await manager.verifyJWK(publicUJWK as SignedPrivateJWK, popJWKS);
    expect(isVerified).to.eql(false);
  });
  it('fails to verify signed JWK with a different POP Key', async () => {
    let errorMessage: string;
    const popJWKS = manager.getPrivateJWKS();
    try {
      const mismatchPublicJWK = mismatchPublicJWKS.keys[0];
      await manager.verifyJWK(mismatchPublicJWK, popJWKS);
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.eql('Error: no key found');
  });
});
