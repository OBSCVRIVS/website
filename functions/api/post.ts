// functions/api/post.ts
// Inserts a note if the user has a valid wa_session cookie.
// Requires Supabase RLS on notes to allow inserts only via service role.

export const onRequestPost: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;

  // Require env
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SERVICE_ROLE) {
    return json({ error: 'missing_env' }, 500);
  }

  try {
    // 1) Check session cookie set by login verify
    const cookie = ctx.request.headers.get('Cookie') || '';
    const jar = Object.fromEntries(cookie.split(';').map(p => p.trim().split('=')));
    const username = (jar['wa_session'] || '').toLowerCase();
    if (!username) return json({ error: 'unauthorized' }, 401);

    // 2) Parse body
    const { body } = await ctx.request.json();
    const text = String(body || '').trim();
    if (!text) return json({ error: 'empty' }, 400);

    // 3) Insert note with SERVICE_ROLE
    const res = await fetch(`${SUPABASE_URL}/rest/v1/notes`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${SERVICE_ROLE}`, // service role to bypass RLS
        'Content-Type': 'application/json',
        Prefer: 'return=representation'
      },
      body: JSON.stringify({ body: text, username })
    });

    if (!res.ok) {
      const t = await res.text();
      return json({ error: `insert ${res.status}`, detail: t }, 500);
    }

    const row = (await res.json())[0];
    return json({ ok: true, note: row });
  } catch (e: any) {
    return json({ error: String(e) }, 500);
  }
};

function json(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
