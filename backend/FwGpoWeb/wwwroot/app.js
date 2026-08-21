// app.js — FW-GPO Builder SPA (vanilla ES module)
import { api, authStatus, ApiError } from './api.js';

// ---------------------------------------------------------------- utilities
const $ = (id) => document.getElementById(id);
const VIEWS = ['welcome', 'mfa', 'setup', 'forbidden', 'main'];
function showView(name) {
  for (const v of VIEWS) $('view-' + v).classList.toggle('hidden', v !== name);
}
function log(msg, cls = '') {
  const el = $('log');
  const t = new Date().toLocaleTimeString();
  el.textContent += `\n[${t}] ${msg}`;
  el.scrollTop = el.scrollHeight;
}
function setStatus(el, text, cls = '') {
  el.textContent = text;
  el.className = 'status ' + cls;
}
let STATUS = null; // last /api/auth/status

// ------------------------------------------------------- IP list validation
// Mirrors the server rules (defense in depth; server re-validates).
const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
function validIp(s) {
  s = (s || '').replace(/[^0-9.]/g, '');
  if (!IP_RE.test(s)) return false;
  return s.split('.').every(p => p.length <= 3 && +p <= 255);
}
function maskToPrefix(mask) {
  if (!validIp(mask)) return null;
  const ip = mask.split('.').reduce((a, o) => (a << 8) + (+o), 0) >>> 0;
  if (ip === 0) return 0;
  if (ip === 0xFFFFFFFF) return 32;
  const inv = (~ip) >>> 0;
  if ((inv & (inv + 1)) !== 0) return null;
  let c = 0;
  for (let i = 31; i >= 0; i--) if ((ip >> i) & 1) c++; else break;
  return c;
}
function isIpOrCidr(s) {
  if (!s) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(s)) {
    const [ip, p] = s.split('/');
    return validIp(ip) && +p <= 32;
  }
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    const [ip, mask] = s.split('/');
    return validIp(ip) && maskToPrefix(mask) !== null;
  }
  const m = s.match(/^(\d{1,3}(\.\d{1,3}){3})-(\d{1,3}(\.\d{1,3}){3})$/);
  if (m) return validIp(m[1]) && validIp(m[3]);
  return validIp(s);
}
function parseAddressList(text) {
  const valid = [], invalid = [];
  for (const line of (text || '').split(/\r?\n/)) {
    for (const raw of line.split(/[,\s;]+/)) {
      const seg = raw.replace(/[^0-9./\-A-Za-z]/g, '');
      if (!seg) continue;
      if (isIpOrCidr(seg)) valid.push(seg); else invalid.push(seg);
    }
  }
  return { valid, invalid };
}
function refreshAddressCount() {
  const { valid, invalid } = parseAddressList($('addresses').value);
  const c = $('addrCount'), i = $('addrInvalid');
  c.textContent = `${valid.length} valid`;
  c.className = 'status ' + (valid.length ? 'ok' : '');
  i.textContent = invalid.length ? `${invalid.length} invalid: ${invalid.slice(0, 8).join(', ')}` : '';
  resetValidated();
}

// ------------------------------------------------------------------- routing
async function refresh() {
  STATUS = await authStatus();
  const ub = $('userbox');
  if (STATUS.authenticated) {
    ub.classList.remove('hidden');
    $('userLabel').textContent = STATUS.upn;
    const badge = $('mfaBadge');
    badge.textContent = STATUS.verified ? 'MFA verified' : 'MFA required';
    badge.className = 'badge ' + (STATUS.verified ? 'ok' : 'no');
    if (STATUS.locked) {
      setStatus($('validateStatus'), `Account locked for MFA (${STATUS.lockRemainingSec}s remaining).`, 'err');
    }
  } else {
    ub.classList.add('hidden');
  }
  if (!STATUS.authenticated) return showView('welcome');
  if (!STATUS.verified) return showView('mfa');
  if (!STATUS.isAdmin) {
    $('forbiddenMsg').textContent =
      `Authenticated as ${STATUS.upn}, but you are not a member of the admin group(s). Ask your AD administrator for access.`;
    return showView('forbidden');
  }
  $('btnMfaTotp').disabled = !STATUS.totpConfigured;
  $('btnMfaFido').disabled = !STATUS.fidoConfigured;
  $('noMfaNote').style.display = (STATUS.totpConfigured || STATUS.fidoConfigured) ? 'none' : '';
  return showView('main');
}

// ------------------------------------------------------------------ SSO view
function initWelcome() {
  $('btnSso').onclick = async () => {
    $('ssoError').classList.add('hidden');
    try {
      const r = await fetch('/api/auth/sso', { credentials: 'same-origin' });
      if (r.status === 401) {
        // The browser will be challenged again on the next navigation if the
        // site is in the intranet zone. Surface a helpful message.
        $('ssoError').textContent =
          'SSO challenge issued. If the login dialog did not appear, ensure this site is in your browser Intranet zone (IE/Edge Internet Options) and you are on a domain-joined machine.';
        $('ssoError').classList.remove('hidden');
        return;
      }
      const j = await r.json().catch(() => ({}));
      if (j && j.ok) await refresh();
      else $('ssoError').textContent = 'SSO handshake did not authenticate. See hint below.';
    } catch (e) {
      $('ssoError').textContent = 'SSO failed: ' + e.message;
    }
    $('ssoError').classList.remove('hidden');
  };
  $('btnLogout').onclick = async () => {
    try { await fetch('/api/auth/logout', { credentials: 'same-origin' }); } catch { }
    csrfReset();
    await refresh();
  };
  function csrfReset() { /* token is re-fetched on next POST */ window.csrfToken = null; }
}

// ------------------------------------------------------------------- MFA view
function initMfa() {
  $('btnMfaTotp').onclick = () => {
    $('totpBox').classList.toggle('hidden');
    $('fidoBox').classList.add('hidden');
    $('mfaError').classList.add('hidden');
  };
  $('btnMfaFido').onclick = async () => {
    $('fidoBox').classList.toggle('hidden');
    $('totpBox').classList.add('hidden');
    $('mfaError').classList.add('hidden');
  };
  $('btnTotpSubmit').onclick = () => doMfa('totp', { code: $('totpCode').value.trim() });
  $('btnFidoMfa').onclick = doFidoMfa;
  $('linkMfaSetup').onclick = (e) => { e.preventDefault(); $('btnSetup').click(); };
}
async function doMfa(method, extra = {}) {
  $('mfaError').classList.add('hidden');
  try {
    await api('/api/auth/mfa/complete', { method: 'POST', body: { method, ...extra } });
    $('totpCode').value = '';
    await refresh();
  } catch (e) {
    $('mfaError').textContent = e.message + (e.status === 423 ? ' Try again later.' : '');
    $('mfaError').classList.remove('hidden');
  }
}
async function doFidoMfa() {
  $('mfaError').classList.add('hidden');
  try {
    const begin = await api('/api/auth/fido/mfa/begin', { method: 'GET' });
    let cred;
    try {
      cred = await navigator.credentials.get({
        publicKey: {
          ...begin.options,
          challenge: b64urlToBytes(begin.options.challenge),
          allowCredentials: (begin.options.allowCredentials || []).map(c => ({ ...c, id: b64urlToBytes(c.id) })),
          timeout: begin.options.timeout || 60000
        }
      });
    } catch (pe) {
      $('mfaError').textContent = 'FIDO2: ' + (pe.name === 'NotAllowedError' ? 'operation cancelled / not allowed.' : pe.message);
      $('mfaError').classList.remove('hidden');
      return;
    }
    if (!cred) throw new Error('No credential returned.');
    await doMfa('webauthn', { credential: credToJson(cred) });
  } catch (e) {
    $('mfaError').textContent = e.message;
    $('mfaError').classList.remove('hidden');
  }
}

// ------------------------------------------------------------- WebAuthn glue
function b64urlToBytes(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(pad);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
function bytesToB64url(buf) {
  let s = btoa(String.fromCharCode(...new Uint8Array(buf)));
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function credToJson(cred) {
  const r = cred.response;
  const base = {
    id: cred.id,
    rawId: cred.rawId,
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || null,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
  };
  if (cred.type === 'public-key') {
    if (r && r.type === 'create') {
      return { ...base, response: {
        clientDataJson: r.clientDataJSON,
        authenticatorData: r.authenticatorData,
        transports: r.getTransports ? r.getTransports() : undefined,
        publicKey: r.publicKey || undefined,
        publicKeyAlgorithm: r.publicKeyAlgorithm ?? undefined,
        attestationObject: r.attestationObject
      } };
    }
    if (r && r.type === 'get') {
      return { ...base, response: {
        clientDataJson: r.clientDataJSON,
        authenticatorData: r.authenticatorData,
        signature: r.signature,
        userHandle: r.userHandle || null
      } };
    }
  }
  return base;
}

// ----------------------------------------------------------------- Setup view
let totpSetupSecret = null;
function initSetup() {
  $('btnSetup').onclick = async () => {
    showView('setup');
    $('setupError').classList.add('hidden');
    await loadSetup();
  };
  $('btnBack').onclick = () => refresh();
  $('btnTotpRegen').onclick = loadTotpSetup;
  $('btnTotpConfirm').onclick = async () => {
    $('setupError').classList.add('hidden');
    try {
      await api('/api/auth/totp/confirm', {
        method: 'POST',
        body: { code: $('totpSetupCode').value.trim(), setupSecret: totpSetupSecret }
      });
      setStatus($('totpSetupStatus'), 'TOTP enrolled. You can now use TOTP as your second factor.', 'ok');
      $('totpSetupCode').value = '';
      await refresh();
    } catch (e) {
      $('setupError').textContent = e.message;
      $('setupError').classList.remove('hidden');
    }
  };
  $('btnFidoReg').onclick = doFidoRegister;
}
async function loadSetup() {
  try {
    await loadTotpSetup();
    await loadFidoList();
  } catch (e) { /* shown below */ }
}
async function loadTotpSetup() {
  try {
    const j = await api('/api/auth/totp/setup', { method: 'GET' });
    totpSetupSecret = j.secret;
    $('totpQr').src = j.qrPngDataUrl;
    $('totpQr').classList.remove('hidden');
    $('totpSecretText').textContent = j.secret;
    setStatus($('totpSetupStatus'), STATUS && STATUS.totpConfigured
      ? 'TOTP is already configured. Enter a code to verify the QR still matches your app.' : '', '');
  } catch (e) {
    $('setupError').textContent = 'TOTP setup: ' + e.message;
    $('setupError').classList.remove('hidden');
  }
}
async function loadFidoList() {
  try {
    const j = await api('/api/auth/fido/list', { method: 'GET' });
    const box = $('fidoList');
    box.innerHTML = '';
    for (const c of j.credentials || []) {
      const div = document.createElement('div');
      div.className = 'cred';
      const name = document.createElement('span');
      name.textContent = c.description || 'FIDO2 credential';
      const del = document.createElement('button');
      del.className = 'ghost';
      del.textContent = 'Delete';
      del.onclick = async () => {
        if (!confirm('Delete this credential?')) return;
        try {
          await api('/api/auth/fido/' + encodeURIComponent(c.id), { method: 'DELETE' });
          await loadFidoList();
          await refresh();
        } catch (e) { alert(e.message); }
      };
      div.append(name, del);
      box.appendChild(div);
    }
    if (!(j.credentials || []).length) {
      box.innerHTML = '<span class="hint">No FIDO2 credentials registered yet.</span>';
    }
  } catch (e) { /* ignore */ }
}
async function doFidoRegister() {
  $('setupError').classList.add('hidden');
  try {
    const begin = await api('/api/auth/fido/register/begin', { method: 'GET' });
    let cred;
    try {
      cred = await navigator.credentials.create({
        publicKey: {
          ...begin.options,
          challenge: b64urlToBytes(begin.options.challenge),
          rp: { ...begin.options.rp, id: begin.options.rp.id },
          user: {
            ...begin.options.user,
            id: b64urlToBytes(begin.options.user.id)
          },
          excludeCredentials: (begin.options.excludeCredentials || []).map(c => ({ ...c, id: b64urlToBytes(c.id) })),
          timeout: begin.options.timeout || 120000,
          attestation: begin.options.attestation || 'none'
        }
      });
    } catch (pe) {
      $('setupError').textContent = 'FIDO2 registration: ' + (pe.name === 'NotAllowedError' ? 'cancelled / not allowed.' : pe.message);
      $('setupError').classList.remove('hidden');
      return;
    }
    if (!cred) throw new Error('No credential created.');
    await api('/api/auth/fido/register/complete', {
      method: 'POST',
      body: { description: prompt('Credential name (optional):', '') || undefined, credential: credToJson(cred) }
    });
    await loadFidoList();
    await refresh();
    $('setupError').textContent = '';
  } catch (e) {
    $('setupError').textContent = e.message;
    $('setupError').classList.remove('hidden');
  }
}

// ------------------------------------------------------------- Builder (main)
let validated = false;
let searched = false;
let allOus = [];
let allGpos = [];

function resetValidated() {
  validated = false;
  $('btnApply').disabled = true;
  if (searched) { /* keep searched */ } else setStatus($('validateStatus'), '', '');
  $('btnValidate').disabled = !searched;
}
function currentMode() {
  return document.querySelector('input[name="srcmode"]:checked').value;
}

function initBuilder() {
  const port = $('port'), preset = $('preset');
  preset.onchange = () => {
    const v = preset.value;
    if (v === 'custom') return;
    port.value = v;
    if (v === '53') $('protocol').value = 'Any';
    else $('protocol').value = 'TCP';
    searched = false;
    $('existingName').value = '';
    setStatus($('searchStatus'), 'Port/preset changed — Search again (mandatory).', 'warn');
    resetValidated();
  };
  $('protocol').onchange = () => { searched = false; $('existingName').value = ''; setStatus($('searchStatus'), 'Protocol changed — Search again (mandatory).', 'warn'); resetValidated(); };
  port.oninput = () => { searched = false; $('existingName').value = ''; setStatus($('searchStatus'), 'Port changed — Search again (mandatory).', 'warn'); resetValidated(); };
  $('addresses').oninput = refreshAddressCount;
  document.querySelectorAll('input[name="srcmode"]').forEach(r => r.onchange = () => {
    $('specificBox').style.display = currentMode() === 'specific' ? '' : 'none';
    resetValidated();
  });

  $('btnPickOu').onclick = () => openOuModal();
  $('btnSearch').onclick = doSearch;
  $('btnListGpos').onclick = async () => {
    try {
      const j = await api('/api/gpo/list', { method: 'GET' });
      allGpos = j.gpos || [];
      log('Loaded ' + allGpos.length + ' GPOs.');
      const pick = prompt('GPO list:\n' + allGpos.join('\n') + '\n\nType a name to select it:', '');
      if (pick) $('existingName').value = pick;
    } catch (e) { log('List GPOs failed: ' + e.message, 'err'); }
  };
  $('btnValidate').onclick = doValidate;
  $('btnApply').onclick = doApply;
}

function openOuModal() {
  $('modal').classList.remove('hidden');
  $('ouFilter').value = '';
  renderOuList('');
}
function closeOuModal() { $('modal').classList.add('hidden'); }
async function loadOus() {
  if (allOus.length) return;
  try {
    const j = await api('/api/ad/ous', { method: 'GET' });
    allOus = j.ous || [];
    log('Loaded ' + allOus.length + ' OUs.');
  } catch (e) {
    log('Failed to load OUs: ' + e.message, 'err');
  }
}
function renderOuList(filter) {
  const ul = $('ouList');
  ul.innerHTML = '';
  const f = (filter || '').toLowerCase();
  for (const o of allOus) {
    if (f && !(o.name.toLowerCase().includes(f) || o.dn.toLowerCase().includes(f))) continue;
    const li = document.createElement('li');
    const b = document.createElement('b'); b.textContent = o.name;
    const s = document.createElement('span'); s.textContent = o.dn;
    li.append(b, s);
    li.onclick = () => {
      $('ouDn').value = o.dn;
      searched = false;
      $('existingName').value = '';
      setStatus($('searchStatus'), 'OU changed — Search again (mandatory).', 'warn');
      resetValidated();
      closeOuModal();
    };
    ul.appendChild(li);
  }
}
$('ouFilter').addEventListener('input', e => renderOuList(e.target.value));
$('btnOuCancel').onclick = closeOuModal;
$('modal').addEventListener('click', e => { if (e.target.id === 'modal') closeOuModal(); });

async function searchParams() {
  const portText = $('port').value.trim();
  const portIsAny = /^(any|\*)$/i.test(portText);
  let port = 0;
  if (!portIsAny) {
    port = parseInt(portText, 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new ApiError('PORT', `Port must be 1-65535 or "Any". Got "${portText}"`, 400);
    }
  }
  return {
    ouDn: $('ouDn').value.trim(),
    port,
    portIsAny,
    protocol: $('protocol').value
  };
}

async function doSearch() {
  $('existingName').value = '';
  setStatus($('searchStatus'), 'Searching…');
  try {
    const p = await searchParams();
    if (!p.ouDn) throw new ApiError('OU', 'Select a target OU first.', 400);
    const j = await api('/api/gpo/search', { method: 'POST', body: p });
    searched = true;
    $('btnValidate').disabled = false;
    if (j.found) {
      $('existingName').value = j.gpoName;
      const prev = j.existing || [];
      if (prev.length) $('addresses').value = prev.join('\n');
      setStatus($('searchStatus'), `Found existing: ${j.gpoName}${prev.length ? ` — loaded ${prev.length} previous IP(s) for edit.` : '.'} Validate when ready.`, 'ok');
      log(`Search: existing GPO ${j.gpoName}, ${prev.length} previous addresses loaded.`);
    } else {
      setStatus($('searchStatus'), 'No existing GPO for this OU/port — a new one will be created. Validate when ready.', 'warn');
      log('Search: no existing GPO — will create new on Apply.');
    }
    refreshAddressCount();
  } catch (e) {
    setStatus($('searchStatus'), 'Search failed: ' + e.message, 'err');
  }
}

async function doValidate() {
  try {
    const p = await searchParams();
    if (!p.ouDn) throw new ApiError('OU', 'Select a target OU first.', 400);
    if (!searched) throw new ApiError('SEARCH', 'Search existing GPO first (mandatory).', 400);
    if (currentMode() === 'specific') {
      const { valid, invalid } = parseAddressList($('addresses').value);
      if (invalid.length) throw new ApiError('IPS', `Invalid entries: ${invalid.slice(0, 10).join(', ')}`, 400);
      if (!valid.length) throw new ApiError('IPS', 'No valid IP/CIDR/range entries.', 400);
    }
    // server-side DN check
    const chk = await fetch('/api/ad/ou/check?dn=' + encodeURIComponent(p.ouDn), { credentials: 'same-origin' });
    const cj = await chk.json().catch(() => ({}));
    if (!cj.exists) throw new ApiError('OU', 'OU not found in AD: ' + p.ouDn, 400);
    validated = true;
    $('btnApply').disabled = false;
    const n = currentMode() === 'specific' ? parseAddressList($('addresses').value).valid.length : 0;
    setStatus($('validateStatus'), `Validate OK${n ? ` — ${n} address(es) valid` : ''}.`, 'ok');
    log('Validate OK.');
  } catch (e) {
    validated = false;
    $('btnApply').disabled = true;
    setStatus($('validateStatus'), 'FAILED: ' + e.message, 'err');
  }
}

async function doApply() {
  if (!validated) { alert('Please Validate first.'); return; }
  if (!confirm('APPLY will delete all existing managed rules for this OU/port and rebuild them. Continue?')) return;
  $('btnApply').disabled = true;
  try {
    const p = await searchParams();
    const mode = currentMode();
    const body = {
      ...p,
      mode,
      addresses: mode === 'specific' ? parseAddressList($('addresses').value).valid : [],
      blockOthers: $('blockOthers').checked,
      searchExisting: true
    };
    const j = await api('/api/gpo/apply', { method: 'POST', body });
    log(`Applied GPO ${j.gpoName}${j.created ? ' (created)' : ' (updated)'}`);
    for (const line of j.log || []) log('  ' + line);
    setStatus($('applyStatus'),
      `Applied: ${j.gpoName} — ${j.allowCount} allow + ${j.blockCount} block rule(s) written, ${j.deletedOld} old removed. Read-back: ${j.readBackAllows}/${j.readBackBlocks}.`, 'ok');
    // refresh the IP list to the newly applied set
    searched = false;
    validated = false;
    $('btnValidate').disabled = true;
    $('existingName').value = j.gpoName;
    setStatus($('searchStatus'), 'Applied — Search again to re-load the new state.', 'warn');
  } catch (e) {
    setStatus($('applyStatus'), 'Apply failed: ' + e.message, 'err');
    log('Apply failed: ' + e.message, 'err');
    $('btnApply').disabled = false;
  }
}

// ------------------------------------------------------------------- boot
(async function boot() {
  initWelcome();
  initMfa();
  initSetup();
  initBuilder();
  refreshAddressCount();
  await refresh();
  // auto-load OUs in the background once authenticated
  setInterval(async () => { if (STATUS && STATUS.authenticated && STATUS.verified) await loadOus().catch(() => { }); }, 15000);
})();
