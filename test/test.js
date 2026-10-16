'use strict';

const assert = require('assert');
const crypto = require('crypto');
const dkim = require('../lib/dkim');

async function main() {
  // 1. Generate an RSA key pair, derive p= exactly like a DKIM DNS record
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pubDer = publicKey.export({ format: 'der', type: 'spki' });
  const p = pubDer.toString('base64');
  const record = `v=DKIM1; k=rsa; p=${p}`;

  // 2. parseDkim
  const tags = dkim.parseDkim(record);
  assert.strictEqual(tags.v, 'DKIM1');
  assert.strictEqual(tags.k, 'rsa');
  assert.strictEqual(tags.p, p);
  console.log('✓ parseDkim OK');

  // 3. validatePublicKey
  const info = dkim.validatePublicKey(tags.p);
  assert.strictEqual(info.valid, true);
  assert.strictEqual(info.type, 'rsa');
  assert.strictEqual(info.bits, 2048);
  console.log(`✓ validatePublicKey OK (type=${info.type}, bits=${info.bits})`);

  // 4. keysMatch — private key PEM should match
  const privPem = privateKey.export({ format: 'pem', type: 'pkcs8' });
  const user = dkim.parseUserKey(privPem);
  assert.strictEqual(user.error, null);
  assert.strictEqual(dkim.keysMatch(user.publicKey, tags.p), true);
  console.log('✓ keysMatch(private key) → MATCH');

  // 5. keysMatch — public key PEM should match
  const pubPem = publicKey.export({ format: 'pem', type: 'spki' });
  const user2 = dkim.parseUserKey(pubPem);
  assert.strictEqual(dkim.keysMatch(user2.publicKey, tags.p), true);
  console.log('✓ keysMatch(public key) → MATCH');

  // 6. keysMatch — a DIFFERENT key should NOT match
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const otherPub = dkim.parseUserKey(other.publicKey.export({ format: 'pem', type: 'spki' }));
  assert.strictEqual(dkim.keysMatch(otherPub.publicKey, tags.p), false);
  console.log('✓ keysMatch(different key) → MISMATCH');

  // 7. Ed25519 support (RFC 8463)
  const ed = crypto.generateKeyPairSync('ed25519');
  const edDer = ed.publicKey.export({ format: 'der', type: 'spki' });
  const edP = edDer.toString('base64');
  const edInfo = dkim.validatePublicKey(edP);
  assert.strictEqual(edInfo.valid, true);
  assert.strictEqual(edInfo.type, 'ed25519');
  assert.strictEqual(edInfo.bits, 256);
  const edUser = dkim.parseUserKey(ed.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  assert.strictEqual(dkim.keysMatch(edUser.publicKey, edP), true);
  console.log('✓ Ed25519 supported');

  // 8. Invalid key should be flagged
  const bad = dkim.validatePublicKey('bm90IGEga2V5');
  assert.strictEqual(bad.valid, false);
  console.log('✓ invalid p= correctly rejected');

  // 9. Live DNS lookups (informational only — do not assert)
  for (const [dom, sel] of [['gmail.com', 'gmail'], ['google.com', 'google']]) {
    const live = await dkim.lookupDkim(dom, sel);
    console.log(
      `ℹ live lookup ${sel}._domainkey.${dom} → found=${live.found}` +
        (live.found ? `, records=${live.records.length}` : ` (${live.error})`)
    );
  }

  console.log('\nAll tests passed ✓');
}

main().catch((e) => {
  console.error('TEST FAILED:', e);
  process.exit(1);
});
