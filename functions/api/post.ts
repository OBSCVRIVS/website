// functions/api/post.ts
// Create a note using the wa_session cookie as the author.
// Requires SERVICE_ROLE to bypass RLS for inserts.

export const onRequestPost: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SERVICE_ROLE) {
    return json({ error: 'missing_env' }, 500);
  }

  try {
    // 1) Auth: read session cookie set by login verify
    const cookie = ctx.request.headers.get('Cookie') || '';
    const jar = Object.fromEntries(cookie.split(';').map(p => p.trim().split('=')));
    const username = (jar['wa_session'] || '').toLowerCase();
    if (!username) return json({ error: 'unauthorized' }, 401);

    // 2) Input
    const payload = await ctx.request.json().catch(() => ({}));
    const text = String(payload.body || '').trim();
    if (!text) return json({ error: 'empty' }, 400);
    if (text.length > 1000) return json({ error: 'too_long' }, 413);

    // 3) Insert with service role
    const ins = await fetch(`${SUPABASE_URL}/rest/v1/notes`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${SERVICE_ROLE}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation'
      },
      body: JSON.stringify({ body: text, username })
    });

    if (!ins.ok) {
      const detail = await ins.text().catch(() => '');
      return json({ error: `insert ${ins.status}`, detail }, 500);
    }

    const row = (await ins.json())[0];
    return json({ ok: true, note: row });
  } catch (e: any) {
    return json({ error: String(e) }, 500);
  }
};

function json(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}
