// api.js — fetch wrapper with antiforgery token + error mapping
let csrfToken = null;

export class ApiError extends Error {
  constructor(code, message, status) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

async function ensureCsrf() {
  if (csrfToken) return csrfToken;
  const r = await fetch('/api/auth/csrf', { credentials: 'same-origin' });
  if (!r.ok) throw new ApiError('CSRF_FAIL', 'Could not obtain CSRF token', r.status);
  const j = await r.json();
  csrfToken = j.token;
  return csrfToken;
}

export async function api(path, { method = 'GET', body } = {}) {
  const headers = { Accept: 'application/json' };
  const mutating = method !== 'GET' && method !== 'HEAD';
  if (mutating) {
    headers['Content-Type'] = 'application/json';
    headers['RequestVerificationToken'] = await ensureCsrf();
  }
  let res;
  try {
    res = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body)
    });
  } catch (e) {
    throw new ApiError('NETWORK', 'Network error: ' + e.message, 0);
  }
  let data = null;
  try { data = await res.json(); } catch { data = null; }
  if (!res.ok) {
    const code = (data && (data.code || data.error)) || 'ERROR';
    const msg = (data && (data.error || data.message)) || res.statusText;
    throw new ApiError(code, typeof msg === 'string' ? msg : JSON.stringify(msg), res.status);
  }
  return data;
}

export async function authStatus() {
  const r = await fetch('/api/auth/status', { credentials: 'same-origin' });
  return r.json();
}
