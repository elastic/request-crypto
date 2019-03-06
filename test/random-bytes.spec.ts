import { generatePassphrase, KEY_LENGTH_IN_BYTES } from '../src/random-bytes';

describe('random-bytes', () => {
  describe('generatePassphrase', () => {
    it('generates a random passphrase', () => {
      const pass1 = generatePassphrase();
      const pass2 = generatePassphrase();
      expect(pass1).to.be.instanceof(Buffer);
      expect(pass1).to.not.equal(pass2);
    });
    it(`generates a passphrase with ${KEY_LENGTH_IN_BYTES} bytes length`, () => {
      const pass = generatePassphrase();
      expect(pass.length).to.equal(32);
    })
  });
});
