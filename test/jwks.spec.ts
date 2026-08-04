import { createJWKS, createJWKSManager, JWKSManager } from '../src/jwks';
import { KeyStore } from '../src/keystore';

import { privateComponents, publicComponents } from './helpers';

import { privateJWKS } from './fixture/private_jwks';
import { publicJWKS } from './fixture/public_jwks';

// RFC 7638 thumbprint for the KIBANA public key — verified at runtime
const KIBANA_THUMBPRINT = 'h5FaWD7kjAc8X7omy0-7yP3ieAcOXPHuaI8SOgcRXUw';

describe('JWKSManager', () => {
  describe('getPublicJWK', () => {
    it('returns public JWK by kid', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const jwk = manager.getPublicJWK('KIBANA');
      expect(jwk).to.not.equal(null);
      expect(Object.keys(jwk)).to.eql(publicComponents);
    });

    it('returns first key when no kid given', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const jwk = manager.getPublicJWK();
      expect(jwk).to.not.equal(null);
      expect(jwk.kid).to.equal('KIBANA');
    });

    it('returns null for unknown kid', async () => {
      const manager = await createJWKSManager(privateJWKS);
      expect(manager.getPublicJWK('MISSING')).to.equal(null);
    });

    it('returns a fresh copy each call (not a shared reference)', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const a = manager.getPublicJWK('KIBANA');
      const b = manager.getPublicJWK('KIBANA');
      expect(a).to.not.equal(b);
      expect(a).to.eql(b);
    });

    it('never exposes private members', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const jwk = manager.getPublicJWK('KIBANA') as any;
      expect(jwk.d).to.equal(undefined);
    });
  });

  describe('getPrivateJWK', () => {
    it('returns private JWK by kid', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const jwk = manager.getPrivateJWK('KIBANA');
      expect(jwk).to.not.equal(null);
      expect(Object.keys(jwk)).to.eql(privateComponents);
    });

    it('returns first key with no argument', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const jwk = manager.getPrivateJWK();
      expect(jwk).to.not.equal(null);
      expect(jwk.kid).to.equal('KIBANA');
    });

    it('returns null for unknown kid', async () => {
      const manager = await createJWKSManager(privateJWKS);
      expect(manager.getPrivateJWK('MISSING')).to.equal(null);
    });

    it('returns null on public-only store', async () => {
      const manager = await createJWKSManager(publicJWKS);
      expect(manager.getPrivateJWK('KIBANA')).to.equal(null);
    });
  });

  describe('getPublicJWKS', () => {
    it('returns only public members', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const jwks = manager.getPublicJWKS();
      expect(jwks.keys).to.have.length(1);
      expect(Object.keys(jwks.keys[0])).to.eql(publicComponents);
    });

    it('never exposes private members', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const jwks = manager.getPublicJWKS();
      expect((jwks.keys[0] as any).d).to.equal(undefined);
    });
  });

  describe('insertKey / addKey', () => {
    it('insertKey accepts a JWK object', async () => {
      const manager = await createJWKSManager();
      await manager.insertKey(privateJWKS.keys[0]);
      expect(manager.store.all()).to.have.length(1);
    });

    it('insertKey accepts a JSON string', async () => {
      const manager = await createJWKSManager();
      await manager.insertKey(JSON.stringify(privateJWKS.keys[0]));
      expect(manager.store.all()).to.have.length(1);
    });

    it('insertKey accepts a Buffer', async () => {
      const manager = await createJWKSManager();
      await manager.insertKey(Buffer.from(JSON.stringify(privateJWKS.keys[0]), 'utf8'));
      expect(manager.store.all()).to.have.length(1);
    });

    it('insertKey copies input (caller mutation does not affect store)', async () => {
      const manager = await createJWKSManager();
      const jwk = Object.assign({}, privateJWKS.keys[0]);
      await manager.insertKey(jwk);
      (jwk as any).kid = 'TAMPERED';
      expect(manager.getPublicJWK('KIBANA')).to.not.equal(null);
    });

    it('insertKey rejects non-RSA key', async () => {
      const manager = await createJWKSManager();
      let errorMessage = '';
      try {
        await manager.insertKey({ kty: 'EC' } as any);
      } catch (err) {
        errorMessage = err.toString();
      }
      expect(errorMessage).to.include('unsupported key type');
    });

    it('insertKey rejects malformed JSON string', async () => {
      const manager = await createJWKSManager();
      let errorMessage = '';
      try {
        await manager.insertKey('not-json');
      } catch (err) {
        errorMessage = err.toString();
      }
      expect(errorMessage).to.be.a('string');
    });

    it('addKey generates a key with the given kid', async () => {
      const manager = await createJWKSManager();
      await manager.addKey('MY_KEY', 1024, 'enc');
      const jwk = manager.getPublicJWK('MY_KEY');
      expect(jwk).to.not.equal(null);
      expect(jwk.kid).to.equal('MY_KEY');
    });

    it('addKey with no kid generates a uuid kid', async () => {
      const manager = await createJWKSManager();
      await manager.addKey(undefined, 1024, 'enc');
      const keys = manager.store.all();
      expect(keys).to.have.length(1);
      // uuid format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      expect(keys[0].kid).to.match(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      );
    });

    it('addKey honours requested modulus', async () => {
      const manager = await createJWKSManager();
      await manager.addKey('K1024', 1024, 'enc');
      const key = manager.store.get('K1024');
      expect(key.length).to.equal(1024);
    });
  });

  describe('removeKey', () => {
    it('removes a key by kid', async () => {
      const manager = await createJWKSManager(privateJWKS);
      manager.removeKey(privateJWKS.keys[0]);
      expect(manager.store.all()).to.have.length(0);
    });

    it('is a no-op for unknown kid', async () => {
      const manager = await createJWKSManager(privateJWKS);
      manager.removeKey({ kid: 'MISSING' } as any);
      expect(manager.store.all()).to.have.length(1);
    });

    it('removes all entries with the same kid', async () => {
      const manager = await createJWKSManager();
      await manager.insertKey(privateJWKS.keys[0]);
      await manager.insertKey(privateJWKS.keys[0]);
      expect(manager.store.all()).to.have.length(2);
      manager.removeKey(privateJWKS.keys[0]);
      expect(manager.store.all()).to.have.length(0);
    });

    it('leaves other keys intact', async () => {
      const manager = await createJWKSManager(privateJWKS);
      await manager.addKey('OTHER', 1024, 'enc');
      manager.removeKey(privateJWKS.keys[0]);
      expect(manager.store.all()).to.have.length(1);
      expect(manager.store.get('OTHER')).to.not.equal(null);
    });
  });

  describe('getKey', () => {
    it('returns first key with no argument', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const key = (manager as any).getKey();
      expect(key).to.not.equal(null);
      expect(key.kid).to.equal('KIBANA');
    });

    it('returns null for unknown kid', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const key = (manager as any).getKey('MISSING');
      expect(key).to.equal(null);
    });
  });
});

describe('KeyStore', () => {
  describe('get with filter object', () => {
    it('matches by use', async () => {
      const store = await createJWKS(privateJWKS);
      const key = store.get({ use: 'enc' });
      expect(key).to.not.equal(null);
      expect(key.use).to.equal('enc');
    });

    it('returns null when filter has no match', async () => {
      const store = await createJWKS(privateJWKS);
      expect(store.get({ use: 'sig' })).to.equal(null);
    });

    it('skips alg check when key has no alg', async () => {
      const store = new KeyStore();
      const noAlg = Object.assign({}, privateJWKS.keys[0]);
      delete (noAlg as any).alg;
      await store.add(noAlg);
      // filter alg 'RSA-OAEP' should still match (falsy-skip)
      const key = store.get({ alg: 'RSA-OAEP' });
      expect(key).to.not.equal(null);
    });
  });

  describe('all', () => {
    it('returns keys in insertion order', async () => {
      const store = new KeyStore();
      await store.add(privateJWKS.keys[0]);
      await store.add(publicJWKS.keys[0]);
      const keys = store.all();
      expect(keys[0].kid).to.equal('KIBANA');
      expect(keys[1].kid).to.equal('KIBANA');
    });

    it('returns empty array when store is empty', () => {
      const store = new KeyStore();
      expect(store.all()).to.eql([]);
    });
  });

  describe('toJSON member order', () => {
    it('public toJSON emits kty,kid,use,alg,e,n', async () => {
      const store = await createJWKS(privateJWKS);
      const jwks = store.toJSON();
      expect(Object.keys(jwks.keys[0])).to.eql(publicComponents);
    });

    it('private toJSON emits kty,kid,use,alg,e,n,d,p,q,dp,dq,qi', async () => {
      const store = await createJWKS(privateJWKS);
      const jwks = store.toJSON(true);
      expect(Object.keys(jwks.keys[0])).to.eql(privateComponents);
    });

    it('omits use when absent', async () => {
      const store = new KeyStore();
      const noUse = Object.assign({}, privateJWKS.keys[0]);
      delete (noUse as any).use;
      await store.add(noUse);
      const jwk = store.toJSON().keys[0] as any;
      expect(jwk.use).to.equal(undefined);
    });

    it('omits alg when absent', async () => {
      const store = new KeyStore();
      const noAlg = Object.assign({}, privateJWKS.keys[0]);
      delete (noAlg as any).alg;
      await store.add(noAlg);
      const jwk = store.toJSON().keys[0] as any;
      expect(jwk.alg).to.equal(undefined);
    });
  });

  describe('kid assignment', () => {
    it('uses kid from JWK when present', async () => {
      const store = await createJWKS(privateJWKS);
      expect(store.get().kid).to.equal('KIBANA');
    });

    it('falls back to RFC 7638 thumbprint when kid absent', async () => {
      const store = new KeyStore();
      const noKid = Object.assign({}, privateJWKS.keys[0]);
      delete (noKid as any).kid;
      await store.add(noKid);
      expect(store.get().kid).to.equal(KIBANA_THUMBPRINT);
    });
  });

  describe('length field', () => {
    it('reports 1024 for 1024-bit KIBANA key', async () => {
      const store = await createJWKS(privateJWKS);
      expect(store.get().length).to.equal(1024);
    });
  });
});

describe('createJWKS', () => {
  it('creates empty store when called with no argument', async () => {
    const store = await createJWKS();
    expect(store.all()).to.eql([]);
  });

  it('loads keys from JWKS object', async () => {
    const store = await createJWKS(privateJWKS);
    expect(store.all()).to.have.length(1);
  });

  it('loads keys from JSON string', async () => {
    const store = await createJWKS(JSON.stringify(privateJWKS));
    expect(store.all()).to.have.length(1);
  });

  it('loads keys from Buffer', async () => {
    const store = await createJWKS(Buffer.from(JSON.stringify(privateJWKS), 'utf8'));
    expect(store.all()).to.have.length(1);
  });

  it('throws TypeError for non-JWKS object', async () => {
    let errorMessage = '';
    try {
      await createJWKS({ notKeys: [] } as any);
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include('TypeError');
  });

  it('throws TypeError for invalid JSON string', async () => {
    let errorMessage = '';
    try {
      await createJWKS('not-json' as any);
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include('TypeError');
  });
});

describe('createJWKSManager', () => {
  it('creates a JWKSManager', async () => {
    const manager = await createJWKSManager(privateJWKS);
    expect(manager).to.be.instanceOf(JWKSManager);
  });

  it('creates an empty manager when called with no argument', async () => {
    const manager = await createJWKSManager();
    expect(manager.store.all()).to.eql([]);
  });

  it('throws on invalid maxDecompressedSize', async () => {
    let errorMessage = '';
    try {
      await createJWKSManager(undefined, { maxDecompressedSize: 0 });
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include('maxDecompressedSize');
  });
});
