const { createJWKManager } = require('@elastic/request-crypto');
const path = require('path');
const fs = require('fs');
const { promisify } = require('util');

const writeFileAsync = promisify(fs.writeFile);

const jwksPath = path.join(process.cwd(), 'jwks_pairs.json');
const kid = process.argv[2];
const configs = process.argv.slice(2).join(' ');
const isHelp = /--help(?: |$)/.test(configs);
if (isHelp) return usagePrompt();
const isCreate = /--create(?: |$)/.test(configs);
const isForce = /--force(?: |$)/.test(configs);
const logPublic = /--public(?: |$)/.test(configs);
const logPrivate = /--private(?: |$)/.test(configs);

(async function main(kid, jwksPath, { isCreate, isForce, logPublic, logPrivate }) {
  if (!kid || /^--/.test(kid)) return usagePrompt(new Error('Missing `kid` parameter.'));
  if (logPublic && logPrivate) return usagePrompt(new Error('Cannot log both public and private compoments'));

  try {
    console.info('- Parsing Existing JWKS.');
    const existingJWKS = await parseJWKSFromFile(jwksPath);

    console.info('- Populating Existing JWKS.');
    const manager = await createJWKManager(existingJWKS);

    console.log(`- Checking for existing kid ${kid} in Set.`);
    const existingKey = manager.getKey(kid);

    if (isCreate) {
      if (existingKey && !isForce) throw new Error(`JWK with kid ${kid} already exists.`);
      await manager.removeKey(existingKey);
      console.info('- Creating a new JWK. This might take a while.');
      await manager.addKey(kid)
      console.info('- Generating updated JWKS.');
      const jwks = manager.getPrivateJWKS();

      console.info('- Saving JWKS to file.');
      await dumpJWKSToFile(jwksPath, jwks)
    }
    if(!isCreate && !existingKey) {
      return usagePrompt(new Error(`JWK with kid ${kid} does not exists.`));
    }

    if (logPrivate) {
      const privateComponent = manager.getPrivateJWK(kid);
      console.log('Private Component:');
      console.log(JSON.stringify(privateComponent, null, 2));
    } else {
      const publicComponent = manager.getPublicJWK(kid);
      console.log('Public Component:');
      console.log(JSON.stringify(publicComponent, null, 2));
    }

    console.info('Done! You\'re all set.');
  } catch(err) {
    console.error(`Something went wrong. ${err}\n`);
    console.error(err);
    process.exit(1);
  }
})(kid, jwksPath, { isCreate, isForce, logPublic, logPrivate });

function usagePrompt(error) {
  let exitCode;
  if (error) {
    console.error(`Something went wrong. ${error} \n`);
    exitCode = 1;
  }

  console.info(`Usage: jwks.js <kid> [options]
  kid:
    Key id of JWK to create or update
  Options:
    [--create]: create a new key.
    [--force]: force creating a new key.
    [--public]: log public component of key.
    [--private]: log private component of key.
    [--help]: show usage prompt.
  `)

  process.exit(exitCode);
}

async function parseJWKSFromFile(filepath) {
  const jwskPairs = require('../jwks_pairs.json');
  if (!jwskPairs) throw new Error(`No JWKS found in file ${filepath}`);
  return jwskPairs;
}

async function dumpJWKSToFile(filepath, jwks) {
  const output = JSON.stringify(jwks, null, 2)
  return writeFileAsync(filepath, output);
}
