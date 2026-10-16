# DKIM Checker

A standalone web tool that verifies whether a **DKIM public key matches the DNS TXT record** — and lets you confirm your private/public key matches the key published in DNS.

Built with Node.js + Express. DNS lookups happen server-side; no keys are stored or logged.

## Features

- Look up the DKIM TXT record at `{selector}._domainkey.{domain}`
- Parse all DKIM tags (`v`, `k`, `p`, `s`, `t`, `h`, `n`, …)
- Validate the `p=` public key (RSA / Ed25519 / EC) and report its type + size
- **Match a supplied private/public key against the published DNS key** (MATCH / MISMATCH)
- Warn about common misconfigurations:
  - missing / invalid `v=` or `p=` tags
  - weak RSA keys (< 1024 / < 2048 bits)
  - `t=` testing-mode flags
  - multiple TXT records

## Quick start

```bash
npm install
npm start
# → http://localhost:3000
```

Run the unit tests (no dependencies required beyond Node):

```bash
npm test
```

## Usage

Open the web UI and enter:

- **Domain** — e.g. `example.com`
- **Selector** — the DKIM selector, defaults to `default`
- **(optional) Key** — paste a PEM private *or* public key to check it matches the DNS record

The tool queries `{selector}._domainkey.{domain}` and reports whether the record is valid and whether your key matches.

## API

### `POST /api/check`

Request body:

```json
{
  "domain": "example.com",
  "selector": "default",
  "key": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
}
```

- `domain` — **required**
- `selector` — optional, defaults to `default`
- `key` — optional PEM key to match against DNS

Response:

```json
{
  "ok": true,
  "hostname": "default._domainkey.example.com",
  "found": true,
  "records": ["v=DKIM1; k=rsa; p=MIIB..."],
  "multipleRecords": false,
  "parsed": { "v": "DKIM1", "k": "rsa", "p": "MIIB..." },
  "keyInfo": { "valid": true, "type": "rsa", "bits": 2048 },
  "match": { "checked": true, "match": true, "userKeyType": "rsa", "dnsKeyType": "rsa" },
  "warnings": []
}
```

## How it works

1. Resolve the TXT record at `{selector}._domainkey.{domain}` using Node's `dns.promises.resolveTxt`.
2. Concatenate split keys per RFC 6376 (§3.6.2.2).
3. Parse the `k=v; k=v` tag list.
4. Decode `p=` (base64 of DER-encoded `SubjectPublicKeyInfo`) with `crypto.createPublicKey`.
5. If a key was supplied, derive its public key and compare the JWK modulus/exponent (RSA) or `x` coordinate (Ed25519) — a mismatch means the DNS record was not updated to match the key, or the wrong key was pasted.

## Deployment

Runs anywhere Node runs. The app exports the Express instance, so it also works with **Plesk Phusion Passenger** (require `app.js` — the server only auto-listens when run directly via `node app.js`).

```bash
PORT=8080 node app.js
```

## License

MIT
