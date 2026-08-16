/**
 * Delicio Oman — Worker entry point.
 *
 * Serves the dashboard's static files and answers /api/visits.
 * Cloudflare Access sits in front, so the signed-in email arrives as a header
 * we can trust and nothing here is reachable without logging in first.
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/visits') {
      if (request.method === 'POST') return saveVisit(request, env);
      if (request.method === 'GET') return readVisits(request, env);
      if (request.method === 'DELETE') return deleteVisit(request, env);
      return json({ ok: false, error: 'method not allowed' }, 405);
    }

    // everything else is the dashboard itself
    return env.ASSETS.fetch(request);
  }
};

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'content-type': 'application/json;charset=utf-8', 'cache-control': 'no-store' }
  });
}

function who(request) {
  // set by Cloudflare Access — the browser cannot forge it
  return request.headers.get('Cf-Access-Authenticated-User-Email') || '';
}

async function readVisits(request, env) {
  const url = new URL(request.url);
  const site = url.searchParams.get('site');
  const id = url.searchParams.get('id');
  const all = url.searchParams.get('all');

  if (!env.DB) return json({ ok: false, error: 'no DB binding on this Worker' }, 500);

  try {
    if (all) {
      // every store, newest first — the overview when no site is selected
      const { results } = await env.DB.prepare(
        `SELECT id, visit_date, saved_at, customer, site_code, site_name, checker, checker_email,
                assortment, on_shelf, missing, never_supplied
           FROM visits
          ORDER BY visit_date DESC, saved_at DESC LIMIT 200`
      ).all();
      return json({ ok: true, visits: results || [], all: true, you: who(request) });
    }

    if (id) {
      const { results } = await env.DB.prepare(
        `SELECT item_code, item_desc, category, status, last_supplied, stock, qty_a, qty_b
           FROM visit_items WHERE visit_id = ? ORDER BY status, category, item_desc`
      ).bind(id).all();
      return json({ ok: true, items: results || [] });
    }

    if (!site) return json({ ok: false, error: 'site or id required' }, 400);

    const { results } = await env.DB.prepare(
      `SELECT id, visit_date, saved_at, checker, checker_email,
              assortment, on_shelf, missing, never_supplied
         FROM visits WHERE site_code = ?
        ORDER BY visit_date DESC, saved_at DESC LIMIT 24`
    ).bind(site).all();
    return json({ ok: true, visits: results || [], you: who(request) });
  } catch (err) {
    return json({ ok: false, error: String(err) }, 500);
  }
}

async function deleteVisit(request, env) {
  if (!env.DB) return json({ ok: false, error: 'no DB binding on this Worker' }, 500);
  const id = new URL(request.url).searchParams.get('id');
  if (!id) return json({ ok: false, error: 'id required' }, 400);
  try {
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM visit_items WHERE visit_id = ?`).bind(id),
      env.DB.prepare(`DELETE FROM visits WHERE id = ?`).bind(id)
    ]);
    return json({ ok: true, deleted: id });
  } catch (err) {
    return json({ ok: false, error: String(err) }, 500);
  }
}

async function saveVisit(request, env) {
  if (!env.DB) return json({ ok: false, error: 'no DB binding on this Worker' }, 500);

  let p;
  try {
    p = await request.json();
  } catch (e) {
    return json({ ok: false, error: 'bad json' }, 400);
  }
  if (!p || !p.items || !p.items.length) return json({ ok: false, error: 'empty visit' }, 400);
  if (p.items.length > 500) return json({ ok: false, error: 'too many items' }, 400);

  const email = who(request);
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
      p.channel || '', p.checker || '', email, p.period || '',
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
    return json({ ok: true, id, saved: p.items.length, email });
  } catch (err) {
    return json({ ok: false, error: String(err) }, 500);
  }
}
