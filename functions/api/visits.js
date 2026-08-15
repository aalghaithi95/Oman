/**
 * /api/visits — store visit storage, running on Cloudflare next to the dashboard.
 *
 * Same origin as the page, so the browser sends the Access cookie automatically
 * and Cloudflare hands us the signed-in email. Nothing here is reachable without
 * passing Access first.
 *
 *   POST /api/visits            save a visit
 *   GET  /api/visits?site=CODE  recent visits for one outlet
 *   GET  /api/visits?id=VISIT   the items recorded on one visit
 */

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'content-type': 'application/json;charset=utf-8', 'cache-control': 'no-store' }
  });
}

function who(request) {
  // set by Cloudflare Access — cannot be forged by the browser
  return request.headers.get('Cf-Access-Authenticated-User-Email') || '';
}

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const site = url.searchParams.get('site');
  const id = url.searchParams.get('id');

  try {
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

export async function onRequestPost({ request, env }) {
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
  // the client supplies its own id, so a queued visit sent twice cannot duplicate
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
        it.last || '', it.stock === '' || it.stock == null ? null : (it.stock | 0),
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
