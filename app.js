'use strict';

const express = require('express');
const path = require('path');
const dkim = require('./lib/dkim');

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/**
 * POST /api/check
 * Body: { domain: string, selector?: string, key?: string }
 *   - domain   (required) the email domain, e.g. example.com
 *   - selector (optional) DKIM selector, defaults to "default"
 *   - key      (optional) a PEM public OR private key to match against DNS
 */
app.post('/api/check', async (req, res) => {
  const { domain, selector, key } = req.body || {};

  if (!domain || typeof domain !== 'string') {
    return res.status(400).json({ ok: false, error: 'Domain is required' });
  }

  const result = await dkim.lookupDkim(domain, selector || 'default');

  const response = {
    ok: true,
    hostname: result.hostname,
    found: result.found,
    error: result.error,
    records: result.records,
    multipleRecords: result.multipleRecords,
    parsed: null,
    keyInfo: null,
    match: null,
    warnings: [],
  };

  if (!result.found) {
    response.warnings.push('No DKIM TXT record found for this domain + selector.');
    return res.json(response);
  }

  const tags = dkim.parseDkim(result.combined);
  response.parsed = tags;

  // --- warnings ---
  if (result.multipleRecords) {
    response.warnings.push(
      'Multiple TXT records found — keys were concatenated. Usually there should be exactly one DKIM record.'
    );
  }
  if (!tags.v) {
    response.warnings.push('Missing v= tag (record does not declare itself as DKIM).');
  } else if (String(tags.v).toUpperCase() !== 'DKIM1') {
    response.warnings.push(`Unrecognised v= value "${tags.v}" (expected DKIM1).`);
  }
  if (tags.t) {
    response.warnings.push(`t=${tags.t} — DKIM "testing mode" flags are set; remove them for production.`);
  }
  if (!tags.p) {
    response.warnings.push('Missing p= tag — no public key published in this record.');
  }

  // --- validate public key ---
  response.keyInfo = dkim.validatePublicKey(tags.p);
  if (response.keyInfo.valid && response.keyInfo.type === 'rsa') {
    if (response.keyInfo.bits < 1024) {
      response.warnings.push(`RSA key is only ${response.keyInfo.bits} bits — critically weak.`);
    } else if (response.keyInfo.bits < 2048) {
      response.warnings.push(`RSA key is ${response.keyInfo.bits} bits — consider 2048 bits or more.`);
    }
  }

  // --- optional key matching ---
  if (key && typeof key === 'string' && key.trim()) {
    const user = dkim.parseUserKey(key);
    if (user.error) {
      response.match = { checked: true, match: false, userKeyError: user.error };
      response.warnings.push('Could not parse the supplied key: ' + user.error);
    } else if (!response.keyInfo.valid) {
      response.match = { checked: true, match: false, userKeyError: 'DNS public key is invalid, cannot compare.' };
    } else {
      const userType = user.publicKey.asymmetricKeyType;
      const matched = dkim.keysMatch(user.publicKey, tags.p);
      response.match = {
        checked: true,
        match: matched,
        userKeyType: userType,
        dnsKeyType: response.keyInfo.type,
      };
      if (!matched) {
        response.warnings.push(
          `The supplied key (${userType}) does NOT match the DNS public key (${response.keyInfo.type}).`
        );
      }
    }
  }

  return res.json(response);
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Plesk Passenger requires app.js and uses the exported app.
// Standalone: `node app.js` starts the server directly.
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`DKIM Checker → http://localhost:${PORT}`));
}

module.exports = app;
