// functions/api/admin/notes/hide.ts
// Body: { id: uuid, hidden: boolean }
export const onRequestPost: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SERVICE_ROLE) return j({ error: 'missing_env' }, 500);

  const cookie = ctx.request.headers.get('Cookie') || '';
  const jar = Object.fromEntries(cookie.split(';').map(p => p.trim().split('=')));
  if (!jar['wa_session']) return j({ error: 'unauthorized' }, 401);

  const { id, hidden } = await ctx.request.json().catch(() => ({} as any));
  if (!id || typeof hidden !== 'boolean') return j({ error: 'bad_request' }, 400);

  const r = await fetch(`${SUPABASE_URL}/rest/v1/notes?id=eq.${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: {
      apikey: SUPABASE_ANON_KEY,
      Authorization: `Bearer ${SERVICE_ROLE}`,
      'Content-Type': 'application/json',
      Prefer: 'return=representation',
    },
    body: JSON.stringify({ is_hidden: hidden }),
  });
  if (!r.ok) return j({ error: `update ${r.status}`, detail: await r.text() }, 500);
  return j((await r.json())[0]);
};

function j(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
