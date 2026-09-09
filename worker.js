/**
 * Delicio Oman — Worker.
 *
 * Serves the dashboard, guards it with a username / password login, and keeps
 * store visits in D1.
 *
 * Needs two things configured in Cloudflare:
 *   • a D1 binding named  DB
 *   • a secret named      AUTH_SECRET   (any long random text — it signs the
 *                                        login cookie and peppers passwords)
 */

const SESSION_DAYS = 30;
const COOKIE = 'delicio_session';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // --- reachable without signing in ---
    if (path === '/api/login' && request.method === 'POST') return login(request, env);
    if (path === '/api/logout') return logout();
    if (path === '/setup') return setupPage(request, env);
    if (path === '/api/setup' && request.method === 'POST') return createUser(request, env);

    const session = await currentUser(request, env);

    if (path === '/login') {
      if (session) return Response.redirect(url.origin + '/', 302);
      return loginPage();
    }

    // --- everything else needs a session ---
    if (!session) {
      if (path.startsWith('/api/')) return json({ ok: false, error: 'not signed in' }, 401);
      return loginPage();
    }

    if (path === '/api/me') {
      return json({ ok: true, user: session.user, name: session.name || session.user });
    }

    if (path === '/api/visits') {
      if (request.method === 'POST') return saveVisit(request, env, session);
      if (request.method === 'GET') return readVisits(request, env, session);
      if (request.method === 'DELETE') return deleteVisit(request, env, session);
      return json({ ok: false, error: 'method not allowed' }, 405);
    }

    return env.ASSETS.fetch(request);
  }
};

/* ============================ helpers ============================ */

function json(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: Object.assign(
      { 'content-type': 'application/json;charset=utf-8', 'cache-control': 'no-store' },
      headers || {}
    )
  });
}

const enc = new TextEncoder();

function b64url(bytes) {
  let s = '';
  const b = new Uint8Array(bytes);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function hmac(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return b64url(await crypto.subtle.sign('HMAC', key, enc.encode(message)));
}

/** compare without revealing where two strings first differ */
function sameString(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function randomSalt() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return b64url(b);
}

/** Stored password = HMAC of salt + password, keyed by the server-side secret.
    The secret lives in Cloudflare and never in the database, so a copy of the
    database on its own gives an attacker nothing to attack. */
async function passwordHash(env, salt, password) {
  return hmac(env.AUTH_SECRET || 'unset', 'pw|' + salt + '|' + password);
}

async function makeSession(env, user, name) {
  const exp = Date.now() + SESSION_DAYS * 86400000;
  const body = b64url(enc.encode(JSON.stringify({ u: user, n: name || '', e: exp })));
  const sig = await hmac(env.AUTH_SECRET || 'unset', body);
  return body + '.' + sig;
}

async function readSession(env, token) {
  if (!token || token.indexOf('.') < 0) return null;
  const dot = token.indexOf('.');
  const body = token.slice(0, dot), sig = token.slice(dot + 1);
  const expect = await hmac(env.AUTH_SECRET || 'unset', body);
  if (!sameString(sig, expect)) return null;
  try {
    const bin = atob(body.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const data = JSON.parse(new TextDecoder().decode(bytes));
    if (!data.e || data.e < Date.now()) return null;
    return { user: data.u, name: data.n };
  } catch (e) {
    return null;
  }
}

function cookieValue(request, name) {
  const raw = request.headers.get('Cookie') || '';
  const parts = raw.split(';');
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i].trim();
    if (p.indexOf(name + '=') === 0) return p.slice(name.length + 1);
  }
  return '';
}

async function currentUser(request, env) {
  const s = await readSession(env, cookieValue(request, COOKIE));
  if (s) return s;
  // if Cloudflare Access is still switched on, its identity counts too
  const email = request.headers.get('Cf-Access-Authenticated-User-Email');
  if (email) return { user: email, name: email.split('@')[0] };
  return null;
}

function setCookie(token) {
  return COOKIE + '=' + token + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' +
         (SESSION_DAYS * 86400);
}

/* ============================ signing in ============================ */

async function login(request, env) {
  let body;
  try { body = await request.json(); } catch (e) { return json({ ok: false, error: 'bad request' }, 400); }
  const user = String(body.username || '').trim().toLowerCase();
  const pass = String(body.password || '');
  if (!user || !pass) return json({ ok: false, error: 'Enter a username and password' }, 400);
  if (!env.DB) return json({ ok: false, error: 'no DB binding on this Worker' }, 500);

  let row = null;
  try {
    row = await env.DB.prepare(
      `SELECT username, display_name, salt, hash, active FROM users WHERE username = ?`
    ).bind(user).first();
  } catch (err) {
    return json({ ok: false, error: 'No users table yet — open /setup first' }, 500);
  }

  // the same answer whether the account is unknown or the password is wrong
  const fail = json({ ok: false, error: 'Wrong username or password' }, 401);
  if (!row || !row.active) return fail;

  const got = await passwordHash(env, row.salt, pass);
  if (!sameString(got, row.hash)) return fail;

  const token = await makeSession(env, row.username, row.display_name);
  return json({ ok: true, user: row.username, name: row.display_name || row.username },
              200, { 'set-cookie': setCookie(token) });
}

function logout() {
  return new Response(null, {
    status: 302,
    headers: {
      'location': '/login',
      'set-cookie': COOKIE + '=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
    }
  });
}

async function userCount(env) {
  try {
    const r = await env.DB.prepare(`SELECT COUNT(*) AS n FROM users`).first();
    return (r && r.n) || 0;
  } catch (err) {
    return -1;                       // table missing
  }
}

/** Account creation. The very first account can be made by whoever reaches this
    page — do it immediately, while Cloudflare Access is still in front. After
    that, only someone already signed in can add more people. */
async function createUser(request, env) {
  if (!env.DB) return json({ ok: false, error: 'no DB binding on this Worker' }, 500);
  let body;
  try { body = await request.json(); } catch (e) { return json({ ok: false, error: 'bad request' }, 400); }

  const count = await userCount(env);
  if (count < 0) return json({ ok: false, error: 'The users table is missing — run the SQL from schema.sql' }, 500);

  const first = count === 0;
  const session = await currentUser(request, env);
  if (!first && !session) return json({ ok: false, error: 'Sign in first to add a user' }, 401);

  const user = String(body.username || '').trim().toLowerCase();
  const pass = String(body.password || '');
  const name = String(body.name || '').trim();
  if (!/^[a-z0-9._-]{3,32}$/.test(user)) {
    return json({ ok: false, error: 'Username: 3-32 letters, numbers, dot, dash or underscore' }, 400);
  }
  if (pass.length < 8) return json({ ok: false, error: 'Password must be at least 8 characters' }, 400);

  const salt = randomSalt();
  const hash = await passwordHash(env, salt, pass);
  await env.DB.prepare(
    `INSERT INTO users (username, display_name, salt, hash, created_at, active)
     VALUES (?,?,?,?,?,1)
     ON CONFLICT(username) DO UPDATE SET display_name=excluded.display_name,
       salt=excluded.salt, hash=excluded.hash, active=1`
  ).bind(user, name || user, salt, hash, new Date().toISOString()).run();

  return json({ ok: true, user: user, first: first });
}

/* ============================ visits ============================ */

/* Everyone sees their own visits and nobody else's. The signed-in address comes
   from Cloudflare Access, so it cannot be spoofed by the browser, and every
   query is filtered by it — including the item detail, so a visit id belonging
   to someone else returns nothing.

   To let particular people see everyone's visits, set a Worker variable named
   ADMINS to their email addresses, comma separated. Leave it unset and the rule
   is strictly per person. */
function isAdmin(env, email) {
  if (!env.ADMINS || !email) return false;
  return String(env.ADMINS).toLowerCase().split(',')
    .map(s => s.trim()).filter(Boolean).indexOf(String(email).toLowerCase()) >= 0;
}

async function readVisits(request, env, session) {
  const url = new URL(request.url);
  const site = url.searchParams.get('site');
  const id = url.searchParams.get('id');
  const all = url.searchParams.get('all');

  if (!env.DB) return json({ ok: false, error: 'no DB binding on this Worker' }, 500);

  const me = session.user;
  if (!me) return json({ ok: false, error: 'not signed in' }, 401);
  const seesAll = isAdmin(env, me);

  try {
    if (all) {
      const { results } = seesAll
        ? await env.DB.prepare(
            `SELECT id, visit_date, saved_at, customer, site_code, site_name, checker, checker_email,
                    assortment, on_shelf, missing, never_supplied
               FROM visits ORDER BY visit_date DESC, saved_at DESC LIMIT 200`
          ).all()
        : await env.DB.prepare(
            `SELECT id, visit_date, saved_at, customer, site_code, site_name, checker, checker_email,
                    assortment, on_shelf, missing, never_supplied
               FROM visits WHERE checker_email = ?
              ORDER BY visit_date DESC, saved_at DESC LIMIT 200`
          ).bind(me).all();
      return json({ ok: true, visits: results || [], all: true, you: me, mineOnly: !seesAll });
    }

    if (id) {
      /* the join keeps someone else's visit id from returning anything */
      const { results } = seesAll
        ? await env.DB.prepare(
            `SELECT i.item_code, i.item_desc, i.category, i.status, i.last_supplied,
                    i.stock, i.qty_a, i.qty_b
               FROM visit_items i WHERE i.visit_id = ?
              ORDER BY i.status, i.category, i.item_desc`
          ).bind(id).all()
        : await env.DB.prepare(
            `SELECT i.item_code, i.item_desc, i.category, i.status, i.last_supplied,
                    i.stock, i.qty_a, i.qty_b
               FROM visit_items i
               JOIN visits v ON v.id = i.visit_id
              WHERE i.visit_id = ? AND v.checker_email = ?
              ORDER BY i.status, i.category, i.item_desc`
          ).bind(id, me).all();
      return json({ ok: true, items: results || [] });
    }

    if (!site) return json({ ok: false, error: 'site or id required' }, 400);

    const { results } = seesAll
      ? await env.DB.prepare(
          `SELECT id, visit_date, saved_at, checker, checker_email,
                  assortment, on_shelf, missing, never_supplied
             FROM visits WHERE site_code = ?
            ORDER BY visit_date DESC, saved_at DESC LIMIT 24`
        ).bind(site).all()
      : await env.DB.prepare(
          `SELECT id, visit_date, saved_at, checker, checker_email,
                  assortment, on_shelf, missing, never_supplied
             FROM visits WHERE site_code = ? AND checker_email = ?
            ORDER BY visit_date DESC, saved_at DESC LIMIT 24`
        ).bind(site, me).all();
    return json({ ok: true, visits: results || [], you: me, mineOnly: !seesAll });
  } catch (err) {
    return json({ ok: false, error: String(err) }, 500);
  }
}

async function deleteVisit(request, env, session) {
  if (!env.DB) return json({ ok: false, error: 'no DB binding on this Worker' }, 500);
  const id = new URL(request.url).searchParams.get('id');
  if (!id) return json({ ok: false, error: 'id required' }, 400);

  const me = session.user;
  if (!me) return json({ ok: false, error: 'not signed in' }, 401);

  try {
    if (!isAdmin(env, me)) {
      /* you can only delete a visit you saved yourself */
      const owner = await env.DB.prepare(
        `SELECT checker_email FROM visits WHERE id = ?`
      ).bind(id).first();
      if (!owner) return json({ ok: true, deleted: id });      /* already gone */
      if (String(owner.checker_email || '').toLowerCase() !== String(me).toLowerCase()){
        return json({ ok: false, error: 'That visit belongs to someone else' }, 403);
      }
    }
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM visit_items WHERE visit_id = ?`).bind(id),
      env.DB.prepare(`DELETE FROM visits WHERE id = ?`).bind(id)
    ]);
    return json({ ok: true, deleted: id });
  } catch (err) {
    return json({ ok: false, error: String(err) }, 500);
  }
}

async function saveVisit(request, env, session) {
  if (!env.DB) return json({ ok: false, error: 'no DB binding on this Worker' }, 500);

  let p;
  try { p = await request.json(); } catch (e) { return json({ ok: false, error: 'bad json' }, 400); }
  if (!p || !p.items || !p.items.length) return json({ ok: false, error: 'empty visit' }, 400);
  if (p.items.length > 500) return json({ ok: false, error: 'too many items' }, 400);

  const signedInAs = session.name || session.user;
  const savedAt = new Date().toISOString();
  // the visit carries its own id, so a queued visit sent twice updates rather than duplicates
  const id = String(p.id || (p.siteCode + '-' + p.visitDate + '-' + Date.now().toString(36)));
  const t = p.totals || {};

  const statements = [
    env.DB.prepare(
      `INSERT OR REPLACE INTO visits
        (id, saved_at, visit_date, customer, site_code, site_name, channel,
         checker, checker_email, period, assortment, on_shelf, missing, never_supplied)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      id, savedAt, p.visitDate || '', p.customer || '', p.siteCode || '', p.siteName || '',
      p.channel || '', p.checker || signedInAs, session.user, p.period || '',
      t.assortment | 0, t.onShelf | 0, t.missing | 0, t.never | 0
    ),
    env.DB.prepare(`DELETE FROM visit_items WHERE visit_id = ?`).bind(id)
  ];

  for (const it of p.items) {
    statements.push(
      env.DB.prepare(
        `INSERT INTO visit_items
          (visit_id, item_code, item_desc, category, status, last_supplied, stock, qty_a, qty_b)
         VALUES (?,?,?,?,?,?,?,?,?)`
      ).bind(
        id, String(it.code), it.desc || '', it.cat || '', it.status || '',
        it.last || '', (it.stock === '' || it.stock == null) ? null : (it.stock | 0),
        it.qA | 0, it.qB | 0
      )
    );
  }

  try {
    await env.DB.batch(statements);
    return json({ ok: true, id, saved: p.items.length, email: signedInAs });
  } catch (err) {
    return json({ ok: false, error: String(err) }, 500);
  }
}

/* ============================ sign-in pages ============================ */

const PAGE_CSS = `
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:#12242C;color:#EAF2F0;font-family:Archivo,'Segoe UI',system-ui,sans-serif;padding:20px}
.card{width:100%;max-width:360px;background:#fff;color:#12242C;border-radius:10px;
  padding:26px 24px;box-shadow:0 24px 60px rgba(0,0,0,.35)}
h1{margin:0 0 2px;font-size:19px;letter-spacing:.01em}
h1 span{color:#C9721F}
p.sub{margin:0 0 20px;font-size:12px;color:#6C7A78}
label{display:block;font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;
  color:#6C7A78;margin:0 0 5px}
input{width:100%;padding:11px 12px;font-size:16px;font-family:inherit;
  border:1px solid #DCDCD6;border-radius:6px;margin-bottom:14px;background:#fff;color:#12242C}
input:focus{outline:none;border-color:#12242C}
button{width:100%;padding:12px;font-size:14px;font-family:inherit;font-weight:600;
  background:#12242C;color:#fff;border:none;border-radius:6px;cursor:pointer}
button:hover{background:#1c3540}
button[disabled]{opacity:.6}
.err{background:#FBEAE5;border:1px solid #E3B5AA;color:#A33A1E;font-size:12px;
  padding:9px 11px;border-radius:6px;margin-bottom:14px;display:none}
.err.on{display:block}
.ok{background:#E7F3EC;border:1px solid #A7CDB5;color:#2C6B43;font-size:12px;
  padding:9px 11px;border-radius:6px;margin-bottom:14px}
.note{font-size:11px;color:#6C7A78;margin-top:14px;line-height:1.5}
`;

function page(title, inner) {
  return new Response(
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">' +
    '<title>' + title + '</title><style>' + PAGE_CSS + '</style></head><body>' + inner + '</body></html>',
    { status: 200, headers: { 'content-type': 'text/html;charset=utf-8', 'cache-control': 'no-store' } }
  );
}

function loginPage() {
  return page('Sign in — Delicio Oman',
'<form class="card" id="f">' +
  '<h1>Delicio <span>Oman</span></h1>' +
  '<p class="sub">Customer performance &amp; market visits</p>' +
  '<div class="err" id="e"></div>' +
  '<label for="u">Username</label>' +
  '<input id="u" name="username" autocomplete="username" autocapitalize="none" autocorrect="off" required>' +
  '<label for="p">Password</label>' +
  '<input id="p" name="password" type="password" autocomplete="current-password" required>' +
  '<button id="b" type="submit">Sign in</button>' +
'</form>' +
'<script>' +
'var f=document.getElementById("f"),e=document.getElementById("e"),b=document.getElementById("b");' +
'f.addEventListener("submit",function(ev){' +
'ev.preventDefault();e.className="err";b.disabled=true;b.textContent="Signing in\\u2026";' +
'fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},' +
'body:JSON.stringify({username:document.getElementById("u").value,password:document.getElementById("p").value})})' +
'.then(function(r){return r.json();})' +
'.then(function(j){if(j.ok){location.href="/";return;}' +
'e.textContent=j.error||"Wrong username or password";e.className="err on";' +
'b.disabled=false;b.textContent="Sign in";})' +
'.catch(function(){e.textContent="No connection. Try again.";e.className="err on";' +
'b.disabled=false;b.textContent="Sign in";});});' +
'<\/script>');
}

async function setupPage(request, env) {
  if (!env.DB) {
    return page('Setup', '<div class="card"><h1>Setup</h1>' +
      '<p class="sub">No database is attached to this Worker yet.</p></div>');
  }
  const count = await userCount(env);
  if (count < 0) {
    return page('Setup — Delicio Oman', '<div class="card"><h1>Almost there</h1>' +
      '<p class="sub">The <b>users</b> table does not exist yet. Open the D1 console and run the ' +
      'CREATE TABLE statement for users, then reload this page.</p></div>');
  }
  const first = count === 0;
  const session = await currentUser(request, env);
  if (!first && !session) {
    return page('Setup — Delicio Oman',
      '<div class="card"><h1>Add a user</h1>' +
      '<p class="sub">Sign in first, then come back to this page.</p>' +
      '<button onclick="location.href=\'/login\'">Go to sign in</button></div>');
  }
  return page('Add a user — Delicio Oman',
'<form class="card" id="f">' +
  '<h1>' + (first ? 'Create the first account' : 'Add a user') + '</h1>' +
  '<p class="sub">' + (first
      ? 'Nobody can sign in yet. Make your own account now.'
      : 'Signed in as ' + ((session.name || session.user)) + '.') + '</p>' +
  '<div class="err" id="e"></div>' +
  '<div class="ok" id="s" style="display:none"></div>' +
  '<label for="n">Full name</label><input id="n" required>' +
  '<label for="u">Username</label>' +
  '<input id="u" autocapitalize="none" autocorrect="off" required>' +
  '<label for="p">Password</label>' +
  '<input id="p" type="password" autocomplete="new-password" required>' +
  '<button id="b" type="submit">Create account</button>' +
  '<div class="note">At least 8 characters. Usernames may use letters, numbers, dot, dash and underscore.</div>' +
'</form>' +
'<script>' +
'var f=document.getElementById("f"),e=document.getElementById("e"),s=document.getElementById("s"),b=document.getElementById("b");' +
'f.addEventListener("submit",function(ev){ev.preventDefault();e.className="err";s.style.display="none";b.disabled=true;' +
'fetch("/api/setup",{method:"POST",headers:{"Content-Type":"application/json"},' +
'body:JSON.stringify({name:document.getElementById("n").value,username:document.getElementById("u").value,' +
'password:document.getElementById("p").value})})' +
'.then(function(r){return r.json();}).then(function(j){b.disabled=false;' +
'if(j.ok){s.textContent="Account \\""+j.user+"\\" is ready. You can sign in now.";s.style.display="block";f.reset();return;}' +
'e.textContent=j.error||"Could not create that account";e.className="err on";})' +
'.catch(function(){b.disabled=false;e.textContent="No connection.";e.className="err on";});});' +
'<\/script>');
}
