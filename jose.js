const jose = require("node-jose");

;(async function() {
  // Build
  const kibanaVersion = 'kibana_6.7';

  const telemetryKey = await jose.JWK.createKey("RSA", 1024, {
    alg: 'RSA-OAEP',
    use: 'enc',
    k: 'asda',
    kid: kibanaVersion,
  });

  const telemetryKeystore = jose.JWK.createKeyStore();
  await telemetryKeystore.add(telemetryKey);


  const vaultKeystore = telemetryKeystore.toJSON(true);
  const wellknownJSONResponse = telemetryKeystore.toJSON();

  const keyFormat = 'utf8';
  
  // Kibana / ECE

  const unencryptedAesKey = Buffer.from('a', keyFormat)
  const publicKeystore = await jose.JWK.asKeyStore(wellknownJSONResponse);

  const effectiveKey = publicKeystore.get(kibanaVersion);
  const encryptConfig = {
    format: 'compact',
    zip: true,
  }
  const payload = await jose.JWE.createEncrypt(encryptConfig, effectiveKey).update(unencryptedAesKey).final();

  console.log('payload::', payload)

  // Phone Home

  const privateKeystore = await jose.JWK.asKeyStore(vaultKeystore);
  console.log('privateKeystoreL::',privateKeystore)
  const decrypter = jose.JWE.createDecrypt(privateKeystore);
  const decryptedPayload = await decrypter.decrypt(payload);

  const decryptedAesKey = decryptedPayload.payload.toString(keyFormat);

  console.log('decryptedAesKey::', decryptedAesKey)
})();