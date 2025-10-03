// server.js (ES Modules) — versión con diseño estético, API protagonista y diagnóstico OAuth/OIDC/JWT

import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import axios from 'axios';
import crypto from 'crypto';
import { nanoid } from 'nanoid';
import https from 'https';

dotenv.config();

// ====== Config ======
const {
  PORT = 3000,
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI,
  SCOPES = 'openid profile email',
  AUDIENCE, // opcional, para pedir token de tu API
  AUTHORIZE_URL,
  TOKEN_URL,
  USERINFO_URL,
  SESSION_SECRET = 'dev-secret-cambia-esto',
  API_BASE = 'https://localhost:7078' // puedes sobreescribirlo por env en la nube
} = process.env;

console.log('ENV check', {
  PORT,
  CLIENT_ID_SET: !!CLIENT_ID,
  CLIENT_SECRET_SET: !!CLIENT_SECRET,
  REDIRECT_URI,
  AUTHORIZE_URL,
  TOKEN_URL,
  USERINFO_URL,
  AUDIENCE,
  API_BASE
});

// ====== Utilidades ======
import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}
function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}
function genCodeVerifier() { return base64url(crypto.randomBytes(64)); }
function genCodeChallenge(verifier) { return base64url(sha256(verifier)); }

const insecureAgent = new https.Agent({ rejectUnauthorized: false });

function escapeHtml(str = '') {
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

// Decodifica SOLO el payload del JWT (para UI; no valida firma)
function decodeJwt(token = '') {
  try {
    const payload = token.split('.')[1];
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch { return {}; }
}

function ensureScope(required, token) {
  const payload = decodeJwt(token);
  const perms = payload.permissions || [];
  const scope = (payload.scope || '').split(' ').filter(Boolean);
  return perms.includes(required) || scope.includes(required);
}

async function apiCall(method, url, token, data) {
  return axios({
    method, url, data,
    headers: { Authorization: `Bearer ${token}` },
    httpsAgent: insecureAgent
  });
}

// ====== Estilos & Layout ======
const THEME = `
  :root{
    --bg:#0b1020; --card:#121830; --muted:#93a1c0; --text:#e6ecff; --accent:#6ea8fe; --accent2:#24d3ee; --danger:#ef4444; --ok:#22c55e; --warn:#f59e0b;
    --border:#223056; --chip:#1b2345;
  }
  *{box-sizing:border-box}
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,'Helvetica Neue',sans-serif;margin:0;background:radial-gradient(1200px 800px at 10% -10%,#12204a 0%,#0b1020 40%,#0b1020 100%);color:var(--text)}
  a{color:var(--accent);text-decoration:none}
  .wrap{max-width:980px;margin:36px auto;padding:0 20px}
  .nav{display:flex;gap:10px;align-items:center;justify-content:space-between;background:rgba(255,255,255,0.04);border:1px solid var(--border);padding:12px 14px;border-radius:14px;backdrop-filter:blur(6px)}
  .nav .links a{padding:8px 10px;border-radius:10px}
  .nav .links a:hover{background:rgba(255,255,255,0.06)}
  .status{display:flex;gap:8px;align-items:center}
  .chip{background:var(--chip);border:1px solid var(--border);padding:6px 10px;border-radius:999px;color:#cfe1ff;font-size:13px}
  .chip.ok{border-color:rgba(34,197,94,.4);box-shadow:0 0 0 2px rgba(34,197,94,.06) inset}
  .chip.bad{border-color:rgba(239,68,68,.4);box-shadow:0 0 0 2px rgba(239,68,68,.06) inset}
  .chip.ttl{border-color:rgba(36,211,238,.4)}
  .grid{display:grid;grid-template-columns:1fr;gap:16px;margin-top:18px}
  @media(min-width:900px){.grid{grid-template-columns:1.4fr .8fr}}
  .card{background:linear-gradient(135deg,rgba(255,255,255,0.06),rgba(255,255,255,0.04));border:1px solid var(--border);border-radius:16px;padding:18px 18px 14px}
  .card h1,.card h2,.card h3{margin:.1rem 0 1rem 0}
  .muted{color:var(--muted)}
  .btns{display:flex;flex-wrap:wrap;gap:10px}
  .btn{display:inline-flex;gap:8px;align-items:center;background:linear-gradient(135deg,var(--accent),#5a8ffd);border:none;color:white;padding:10px 14px;border-radius:12px;font-weight:600;cursor:pointer;box-shadow:0 8px 30px rgba(110,168,254,.25)}
  .btn:hover{filter:brightness(1.06)}
  .btn.sec{background:linear-gradient(135deg,#1f2937,#0f172a);border:1px solid var(--border);color:#dbeafe}
  .btn.warn{background:linear-gradient(135deg,var(--warn),#ffb74d);color:#131313}
  .btn.danger{background:linear-gradient(135deg,var(--danger),#ff6b6b)}
  table{width:100%;border-collapse:separate;border-spacing:0 8px}
  th,td{text-align:left;padding:10px 12px}
  thead th{color:#c7d7ff;font-weight:700}
  tbody tr{background:rgba(255,255,255,0.04);border:1px solid var(--border)}
  tbody tr td{border-top:1px solid var(--border);border-bottom:1px solid var(--border)}
  tbody tr td:first-child{border-left:1px solid var(--border);border-top-left-radius:12px;border-bottom-left-radius:12px}
  tbody tr td:last-child{border-right:1px solid var(--border);border-top-right-radius:12px;border-bottom-right-radius:12px}
  pre{background:#0e1530;border:1px solid var(--border);border-radius:14px;padding:14px;overflow:auto}
  details{border:1px solid var(--border);border-radius:14px;overflow:hidden}
  details summary{padding:12px 14px;background:#0f1836;cursor:pointer;font-weight:600}
  details .box{padding:10px 14px;background:rgba(255,255,255,0.04)}
  .note{font-size:14px;color:#c9d7ff}
  .hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
`;

function tokenPanel(at) {
  if (!at) return '<p class="note">Sin access_token</p>';
  const p = decodeJwt(at);
  const now = Math.floor(Date.now() / 1000);
  const ttl = Math.max(0, (p.exp ?? 0) - now);
  return `
    <details open>
      <summary>🔎 Diagnóstico del Token (JWT)</summary>
      <div class="box">
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
          <span class="chip">iss: ${escapeHtml(p.iss||'-')}</span>
          <span class="chip">aud: ${escapeHtml(Array.isArray(p.aud)?p.aud.join(', '):(p.aud||'-'))}</span>
          <span class="chip">sub: ${escapeHtml(p.sub||'-')}</span>
          <span class="chip ttl">expira en: ${ttl}s</span>
          ${p.permissions ? `<span class="chip">permissions: ${escapeHtml(p.permissions.join(' '))}</span>` : ''}
          ${p.scope ? `<span class="chip">scope: ${escapeHtml(p.scope)}</span>` : ''}
        </div>
        <pre>${escapeHtml(JSON.stringify(p, null, 2))}</pre>
        <p class="note"><a target="_blank" href="https://jwt.io/">Ver en jwt.io</a></p>
      </div>
    </details>
  `;
}

function layout({ title='Demo OAuth 2.0', logged=false, body='', at=null }) {
  const p = at ? decodeJwt(at) : {};
  const now = Math.floor(Date.now()/1000);
  const ttl = at ? Math.max(0,(p.exp ?? 0) - now) : null;

  return `<!doctype html>
  <html lang="es">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>${escapeHtml(title)}</title>
    <style>${THEME}</style>
  </head>
  <body>
    <div class="wrap">
      <div class="nav">
        <div class="links">
          <a href="/">🏠 Inicio</a>
          <a href="/login">🔐 Iniciar sesión</a>
          <a href="/profile">👤 Perfil</a>
          <a href="/orders">📦 Órdenes</a>
          <a href="/logout">🚪 Logout</a>
        </div>
        <div class="status">
          <span class="chip ${logged ? 'ok':'bad'}">${logged ? 'Autenticado' : 'No autenticado'}</span>
          ${ttl !== null ? `<span class="chip ttl">TTL: ${ttl}s</span>` : ''}
        </div>
      </div>

      <div class="grid">
        <div class="card">
          ${body}
        </div>

        <div class="card">
          <div class="hdr"><h3>Qué se demuestra</h3></div>
          <ul class="muted">
            <li><b>Autenticación</b> (OIDC): login con Auth0 y <code>/userinfo</code>.</li>
            <li><b>Autorización</b>: acceso a API ASP.NET con <code>Bearer JWT</code> y <i>scopes</i>.</li>
            <li><b>JWT</b>: claims, expiración y diagnóstico visual.</li>
            <li><b>OAuth 2.0</b>: flujo <b>Authorization Code + PKCE</b>.</li>
          </ul>
          <div class="btns">
            <a href="/login" class="btn">🔑 Iniciar sesión</a>
            <a href="/profile" class="btn sec">👤 Ver perfil</a>
            <a href="/orders" class="btn sec">📦 Ver órdenes (API)</a>
          </div>
        </div>
      </div>
    </div>
  </body>
  </html>`;
}

// ====== App ======
const app = express();
// app.set('trust proxy', 1); // habilítalo si usas HTTPS detrás de proxy

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 1000*60*60 }
  })
);

// ====== Rutas ======
app.get('/', (req, res) => {
  const logged = !!req.session.tokens?.access_token;
  const body = `
    <div class="hdr">
      <h1>Demo OAuth 2.0 (Auth0) — Authorization Code + PKCE</h1>
      <span class="chip">API_BASE: ${escapeHtml(API_BASE)}</span>
    </div>
    <p class="muted">Sistema de ejemplo con <b>Auth0</b> + <b>API ASP.NET</b> protegida por <b>JWT</b> y <b>scopes</b>. Usa los botones para recorrer el flujo completo.</p>
    <div class="btns" style="margin-top:10px">
      <a href="/login" class="btn">🔐 Iniciar sesión</a>
      <a href="/profile" class="btn sec">👤 Perfil (userinfo)</a>
      <a href="/orders" class="btn sec">📦 Órdenes (API)</a>
    </div>
  `;
  res.send(layout({ title:'Inicio', logged, body, at: req.session.tokens?.access_token }));
});

// Login (Authorization Code + PKCE)
app.get('/login', (req, res) => {
  const state = nanoid();
  const code_verifier = genCodeVerifier();
  const code_challenge = genCodeChallenge(code_verifier);

  req.session.oauth = { state, code_verifier };

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: SCOPES,
    state,
    code_challenge,
    code_challenge_method: 'S256'
  });
  if (AUDIENCE) params.append('audience', AUDIENCE);

  const url = `${AUTHORIZE_URL}?${params.toString()}`;
  console.log('Authorize URL =>', url);
  res.redirect(url);
});

// Callback: code -> tokens
app.get('/callback', async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!req.session.oauth) return res.status(400).send('Sesión PKCE inexistente. Vuelve a /login');
    if (state !== req.session.oauth.state) return res.status(400).send('CSRF: state inválido.');

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code,
      code_verifier: req.session.oauth.code_verifier
    });
    if (CLIENT_SECRET) body.append('client_secret', CLIENT_SECRET);

    console.log('TOKEN EXCHANGE BODY', {
      has_code: !!code,
      has_code_verifier: !!req.session.oauth?.code_verifier,
      redirect_uri: REDIRECT_URI,
      client_id_set: !!CLIENT_ID,
      client_secret_set: !!CLIENT_SECRET
    });

    const r = await axios.post(TOKEN_URL, body.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

req.session.tokens = {
  access_token: r.data.access_token,
  id_token: r.data.id_token,
  refresh_token: r.data.refresh_token,
  token_type: r.data.token_type,
  expires_in: r.data.expires_in
};

console.log("Nuevo access_token =>", r.data.access_token);  // 👈 lo imprime en la consola

    delete req.session.oauth;

    res.redirect('/profile');
  } catch (e) {
    console.error('Token exchange ERROR:', e?.response?.status, e?.response?.data || e.message);
    const body = `
      <h2>Fallo en el intercambio de código por tokens</h2>
      <pre>${escapeHtml(e?.response?.data ? JSON.stringify(e.response.data, null, 2) : e.message)}</pre>
      <div class="btns"><a href="/login" class="btn">Reintentar login</a></div>
    `;
    res.status(500).send(layout({ title:'Error', logged:false, body }));
  }
});

// Perfil (userinfo) — Autenticación
app.get('/profile', async (req, res) => {
  try {
    const at = req.session.tokens?.access_token;
    if (!at) return res.redirect('/login');

    const r = await axios.get(USERINFO_URL, { headers: { Authorization: `Bearer ${at}` } });

    const body = `
      <div class="hdr">
        <h2>Perfil (userinfo)</h2>
      </div>
      <div style="display:flex;gap:18px;align-items:flex-start;flex-wrap:wrap">
        ${r.data.picture ? `<img src="${escapeHtml(r.data.picture)}" alt="avatar" style="width:96px;height:96px;border-radius:12px;border:1px solid var(--border)"/>` : ''}
        <div>
          <div class="chip">name: ${escapeHtml(r.data.name||'-')}</div>
          <div class="chip">email: ${escapeHtml(r.data.email||'-')}</div>
          <div class="chip">sub: ${escapeHtml(r.data.sub||'-')}</div>
        </div>
      </div>
      <h3 style="margin-top:16px">Raw</h3>
      <pre>${escapeHtml(JSON.stringify(r.data, null, 2))}</pre>
      ${tokenPanel(at)}
      <div class="btns"><a class="btn sec" href="/orders">📦 Ir a Órdenes</a></div>
    `;
    res.send(layout({ title:'Perfil', logged:true, body, at }));
  } catch (e) {
    console.error('UserInfo ERROR:', e?.response?.status, e?.response?.data || e.message);
    const body = `
      <h2>No se pudo obtener el perfil</h2>
      <pre>${escapeHtml(e?.response?.data ? JSON.stringify(e.response.data, null, 2) : e.message)}</pre>
    `;
    res.status(500).send(layout({ title:'Error', logged:!!req.session.tokens?.access_token, body, at:req.session.tokens?.access_token }));
  }
});

// Órdenes — API como protagonista

// Listar todas (read:orders)
app.get('/orders', async (req, res) => {
  const at = req.session.tokens?.access_token;
  if (!at) return res.redirect('/login');

  if (!ensureScope('read:orders', at)) {
    const body = `<h2>Falta scope <code>read:orders</code></h2>${tokenPanel(at)}`;
    return res.status(403).send(layout({ title:'Sin permiso', logged:true, body, at }));
  }

  try {
    const r = await apiCall('GET', `${API_BASE}/api/orders`, at);
    const rows = r.data.map(o => `
      <tr>
        <td>${escapeHtml(o.id)}</td>
        <td>${escapeHtml(o.item)}</td>
        <td>${escapeHtml(String(o.qty))}</td>
        <td class="muted" style="font-size:12px">${escapeHtml(o.ownerSub)}</td>
        <td><a class="btn danger" style="padding:6px 10px" href="/orders/delete/${encodeURIComponent(o.id)}">🗑 Eliminar</a></td>
      </tr>`).join('');

    const body = `
      <div class="hdr">
        <h2>Órdenes (todas)</h2>
        <div class="btns">
          <a href="/orders/my" class="btn sec">👤 Mis órdenes</a>
          <a href="/orders/new" class="btn">➕ Nueva orden</a>
        </div>
      </div>
      ${tokenPanel(at)}
      <table>
        <thead><tr><th>ID</th><th>Item</th><th>Qty</th><th>OwnerSub</th><th>Acciones</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="5" class="muted">Sin datos</td></tr>`}</tbody>
      </table>
      <p class="note">💡 Si la API está apagada, verás error de conexión al entrar aquí.</p>
    `;
    res.send(layout({ title:'Órdenes', logged:true, body, at }));
  } catch (e) {
    console.error('Error API (GET /orders):', e?.response?.status, e?.response?.data || e.message);
    const body = `
      <h2>Error accediendo a la API</h2>
      <pre>${escapeHtml(e?.response?.data ? JSON.stringify(e.response.data, null, 2) : e.message)}</pre>
      <p class="note">❌ API apagada → fallo de conexión. ❌ Token inválido → 401 Unauthorized.</p>
    `;
    res.status(500).send(layout({ title:'Error API', logged:true, body, at }));
  }
});

// Mis órdenes (read:orders)
app.get('/orders/my', async (req, res) => {
  const at = req.session.tokens?.access_token;
  if (!at) return res.redirect('/login');

  if (!ensureScope('read:orders', at)) {
    const body = `<h2>Falta scope <code>read:orders</code></h2>${tokenPanel(at)}`;
    return res.status(403).send(layout({ title:'Sin permiso', logged:true, body, at }));
  }

  try {
    const r = await apiCall('GET', `${API_BASE}/api/orders/my`, at);
    const body = `
      <div class="hdr">
        <h2>Mis órdenes</h2>
        <a href="/orders" class="btn sec">⬅️ Volver</a>
      </div>
      ${tokenPanel(at)}
      <pre>${escapeHtml(JSON.stringify(r.data, null, 2))}</pre>
    `;
    res.send(layout({ title:'Mis Órdenes', logged:true, body, at }));
  } catch (e) {
    console.error('Error API (GET /orders/my):', e?.response?.status, e?.response?.data || e.message);
    const body = `<h2>Error API</h2><pre>${escapeHtml(e.message)}</pre>`;
    res.status(500).send(layout({ title:'Error API', logged:true, body, at }));
  }
});

// Nueva orden (form) (write:orders)
app.get('/orders/new', (req, res) => {
  const at = req.session.tokens?.access_token;
  if (!at) return res.redirect('/login');

  if (!ensureScope('write:orders', at)) {
    const body = `<h2>Falta scope <code>write:orders</code></h2>${tokenPanel(at)}`;
    return res.status(403).send(layout({ title:'Sin permiso', logged:true, body, at }));
  }

  const body = `
    <div class="hdr">
      <h2>Nueva orden</h2>
      <a href="/orders" class="btn sec">⬅️ Volver</a>
    </div>
    ${tokenPanel(at)}
    <form method="post" action="/orders/new" style="display:grid;gap:10px;max-width:360px">
      <label>Item<br><input name="item" required style="width:100%;padding:10px;border-radius:10px;border:1px solid var(--border);background:#0f1836;color:#e6ecff"></label>
      <label>Cantidad<br><input type="number" name="qty" min="1" value="1" required style="width:100%;padding:10px;border-radius:10px;border:1px solid var(--border);background:#0f1836;color:#e6ecff"></label>
      <button class="btn" type="submit">Crear</button>
    </form>
  `;
  res.send(layout({ title:'Nueva Orden', logged:true, body, at }));
});

// Crear (write:orders)
app.post('/orders/new', async (req, res) => {
  const at = req.session.tokens?.access_token;
  if (!at) return res.redirect('/login');

  if (!ensureScope('write:orders', at)) {
    const body = `<h2>Falta scope <code>write:orders</code></h2>${tokenPanel(at)}`;
    return res.status(403).send(layout({ title:'Sin permiso', logged:true, body, at }));
  }

  try {
    const payload = { item: req.body.item, qty: parseInt(req.body.qty || '1', 10) };
    await apiCall('POST', `${API_BASE}/api/orders`, at, payload);
    res.redirect('/orders');
  } catch (e) {
    console.error('Error API (POST /orders):', e?.response?.status, e?.response?.data || e.message);
    const body = `<h2>Error al crear</h2><pre>${escapeHtml(e.message)}</pre>`;
    res.status(500).send(layout({ title:'Error al crear', logged:true, body, at }));
  }
});

// Eliminar (delete:orders)
app.get('/orders/delete/:id', async (req, res) => {
  const at = req.session.tokens?.access_token;
  if (!at) return res.redirect('/login');

  if (!ensureScope('delete:orders', at)) {
    const body = `<h2>Falta scope <code>delete:orders</code></h2>${tokenPanel(at)}`;
    return res.status(403).send(layout({ title:'Sin permiso', logged:true, body, at }));
  }

  try {
    await apiCall('DELETE', `${API_BASE}/api/orders/${encodeURIComponent(req.params.id)}`, at);
    res.redirect('/orders');
  } catch (e) {
    console.error('Error API (DELETE /orders/:id):', e?.response?.status, e?.response?.data || e.message);
    const body = `<h2>Error al eliminar</h2><pre>${escapeHtml(e.message)}</pre>`;
    res.status(500).send(layout({ title:'Error al eliminar', logged:true, body, at }));
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    const url = new URL(`https://${process.env.AUTH_DOMAIN}/v2/logout`);
    url.searchParams.set('client_id', CLIENT_ID);
    url.searchParams.set('returnTo', 'http://localhost:3000/');
    res.redirect(url.toString());
  });
});

// Start
app.listen(PORT, () => {
  console.log(`✅ App en http://localhost:${PORT}`);
});
