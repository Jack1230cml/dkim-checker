'use strict';

const form = document.getElementById('checkForm');
const submit = document.getElementById('submit');
const resultEl = document.getElementById('result');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const domain = document.getElementById('domain').value.trim();
  const selector = document.getElementById('selector').value.trim() || 'default';
  const key = document.getElementById('key').value.trim();

  submit.disabled = true;
  submit.textContent = 'Checking…';
  resultEl.innerHTML = '<div class="loading">Looking up DNS record…</div>';
  resultEl.classList.remove('hidden');

  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, selector, key }),
    });
    const data = await res.json();
    render(data);
  } catch (err) {
    resultEl.innerHTML = `<div class="banner err">Request failed: ${escapeHtml(err.message)}</div>`;
  } finally {
    submit.disabled = false;
    submit.textContent = 'Check DKIM record';
  }
});

function render(d) {
  const parts = [];

  parts.push(
    `<div class="hostname">Record: <code>${escapeHtml(d.hostname)}</code></div>`
  );

  if (!d.found) {
    parts.push(`<div class="banner err">✗ DKIM record not found</div>`);
    if (d.error) parts.push(`<div class="detail">${escapeHtml(d.error)}</div>`);
    parts.push(
      `<div class="detail">Check the selector and domain, and confirm a TXT record exists at <code>${escapeHtml(
        d.hostname
      )}</code>.</div>`
    );
    resultEl.innerHTML = parts.join('');
    return;
  }

  // Overall banner
  if (d.match && d.match.checked) {
    if (d.match.match) {
      parts.push(`<div class="banner ok">✓ MATCH — supplied key matches the DNS record</div>`);
    } else if (d.match.userKeyError) {
      parts.push(`<div class="banner warn">⚠ Key comparison failed: ${escapeHtml(d.match.userKeyError)}</div>`);
    } else {
      parts.push(`<div class="banner err">✗ MISMATCH — supplied key does NOT match the DNS record</div>`);
    }
  } else if (d.keyInfo && d.keyInfo.valid) {
    parts.push(`<div class="banner ok">✓ DKIM record found and key is valid</div>`);
  } else {
    parts.push(`<div class="banner warn">⚠ DKIM record found, but key has problems</div>`);
  }

  // Raw records
  parts.push(`<h3>DNS TXT record</h3>`);
  (d.records || []).forEach((r, i) => {
    parts.push(`<pre class="record">${escapeHtml(r)}</pre>`);
  });

  // Parsed tags
  if (d.parsed) {
    parts.push(`<h3>Parsed tags</h3><table class="tags"><tbody>`);
    for (const [k, v] of Object.entries(d.parsed)) {
      const display = k === 'p' && v.length > 48 ? v.slice(0, 48) + '…' : v;
      parts.push(
        `<tr><td class="k">${escapeHtml(k)}</td><td class="v"><code>${escapeHtml(display)}</code></td></tr>`
      );
    }
    parts.push(`</tbody></table>`);
  }

  // Key info
  if (d.keyInfo) {
    parts.push(`<h3>Public key</h3>`);
    if (d.keyInfo.valid) {
      const bits =
        d.keyInfo.bits != null
          ? typeof d.keyInfo.bits === 'number'
            ? ` · ${d.keyInfo.bits} bits`
            : ` · ${d.keyInfo.bits}`
          : '';
      parts.push(
        `<div class="detail">Type: <strong>${escapeHtml(d.keyInfo.type)}</strong>${escapeHtml(
          bits
        )} — <span class="good">valid</span></div>`
      );
    } else {
      parts.push(
        `<div class="detail"><span class="bad">Invalid public key:</span> ${escapeHtml(
          d.keyInfo.error
        )}</div>`
      );
    }
  }

  // Warnings
  if (d.warnings && d.warnings.length) {
    parts.push(`<h3>Notes</h3><ul class="warnings">`);
    d.warnings.forEach((w) => parts.push(`<li>${escapeHtml(w)}</li>`));
    parts.push(`</ul>`);
  }

  resultEl.innerHTML = parts.join('');
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
