'use strict';

const crypto = require('crypto');
const dns = require('dns').promises;

// Allow overriding DNS servers (comma-separated) — useful in environments where
// the system resolver is unreachable (e.g. local stub on 127.0.0.1 refusing connections).
if (process.env.DKIM_DNS_SERVERS) {
  const servers = process.env.DKIM_DNS_SERVERS.split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (servers.length) {
    require('dns').setServers(servers);
  }
}

/**
 * Build the DKIM DNS hostname: {selector}._domainkey.{domain}
 */
function dkimHostname(domain, selector) {
  const d = String(domain || '')
    .trim()
    .toLowerCase()
    .replace(/^\.+/, '')
    .replace(/\.+$/, '');
  const s = String(selector || 'default')
    .trim()
    .toLowerCase()
    .replace(/^\.+/, '')
    .replace(/\.+$/, '');
  return `${s}._domainkey.${d}`;
}

/**
 * Look up the DKIM TXT record(s) for a domain + selector.
 * Returns { hostname, found, records, combined, multipleRecords, error }.
 *
 * Per RFC 6376, a key may be split across multiple TXT records / character
 * strings and MUST be concatenated without any separator.
 */
async function lookupDkim(domain, selector) {
  const hostname = dkimHostname(domain, selector);
  const empty = { hostname, found: false, records: [], combined: '', multipleRecords: false, error: null };

  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(hostname.split('._domainkey.')[0])) {
    return { ...empty, error: 'Invalid domain or selector' };
  }

  try {
    const records = await dns.resolveTxt(hostname);
    const perRecord = records.map((chunks) => chunks.join(''));
    const combined = perRecord.join('');
    return {
      hostname,
      found: true,
      records: perRecord,
      combined,
      multipleRecords: records.length > 1,
      error: null,
    };
  } catch (err) {
    if (err.code === 'ENOTFOUND' || err.code === 'ENODATA' || err.code === 'NXDOMAIN') {
      return { ...empty, error: `No DKIM TXT record at ${hostname}` };
    }
    return { ...empty, error: err.message || String(err) };
  }
}

/**
 * Parse a DKIM record into a tag map.
 * Tags are separated by ';', each "k=v"; values may be quoted.
 */
function parseDkim(txt) {
  const tags = {};
  const parts = String(txt || '').split(';');
  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    let val = part.slice(eq + 1).trim();
    val = val.replace(/^["']/, '').replace(/["']$/, '');
    if (key) tags[key] = val;
  }
  return tags;
}

/**
 * Validate a DKIM p= value (base64 of DER-encoded SubjectPublicKeyInfo).
 * Returns { valid, type, bits, error }.
 */
function validatePublicKey(p) {
  if (!p) {
    return { valid: false, type: null, bits: null, error: 'Missing p= tag (no public key in record)' };
  }
  const cleaned = String(p).replace(/\s+/g, '');
  let der;
  try {
    der = Buffer.from(cleaned, 'base64');
  } catch (e) {
    return { valid: false, type: null, bits: null, error: 'p= is not valid base64' };
  }

  let key;
  try {
    key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch (e) {
    return {
      valid: false,
      type: null,
      bits: null,
      error: 'p= is not a valid public key (SPKI DER): ' + e.message,
    };
  }

  const type = key.asymmetricKeyType;
  const details = key.asymmetricKeyDetails || {};
  let bits = null;
  if (type === 'rsa') bits = details.modulusLength || null;
  else if (type === 'ec') bits = details.namedCurve || null;
  else if (type === 'ed25519') bits = 256;
  else if (type === 'ed448') bits = 448;

  return { valid: true, type, bits, error: null };
}

/**
 * Parse a user-supplied PEM key (private OR public) into a public key.
 */
function parseUserKey(pem) {
  const text = String(pem || '').trim();
  if (!text) return { publicKey: null, error: 'No key provided' };
  try {
    const pub = crypto.createPublicKey(text);
    return { publicKey: pub, error: null };
  } catch (e) {
    return {
      publicKey: null,
      error: 'Could not parse key (expect a PEM public or private key): ' + e.message,
    };
  }
}

/**
 * Compare a user public key against the DKIM p= public key.
 */
function keysMatch(userPub, dnsP) {
  const der = Buffer.from(String(dnsP).replace(/\s+/g, ''), 'base64');
  const dnsPub = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  const t = userPub.asymmetricKeyType;
  const a = userPub.export({ format: 'jwk' });
  const b = dnsPub.export({ format: 'jwk' });

  if (t === 'rsa') return a.n === b.n && a.e === b.e;
  if (t === 'ed25519' || t === 'ed448') return a.x === b.x;
  if (t === 'ec') return a.crv === b.crv && a.x === b.x && a.y === b.y;

  const ad = userPub.export({ format: 'der', type: 'spki' });
  const bd = dnsPub.export({ format: 'der', type: 'spki' });
  return ad.equals(bd);
}

module.exports = {
  dkimHostname,
  lookupDkim,
  parseDkim,
  validatePublicKey,
  parseUserKey,
  keysMatch,
};
