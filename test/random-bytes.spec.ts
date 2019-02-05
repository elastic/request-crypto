import { generatePassphrase } from '../src/random-bytes';

describe('helpers', () => {
  describe('generatePassphrase', () => {
    it('generates a random passphrase', () => {
      const pass1 = generatePassphrase();
      const pass2 = generatePassphrase();
      expect(pass1).to.be.a('string');
      expect(pass1).to.not.equal(pass2);
    });
  });
});
