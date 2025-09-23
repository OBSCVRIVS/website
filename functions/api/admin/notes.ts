// functions/api/admin/notes.ts
// Admin list: requires wa_session cookie and service-role.
export const onRequestGet: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SERVICE_ROLE) return j({ error: 'missing_env' }, 500);

  const cookie = ctx.request.headers.get('Cookie') || '';
  const jar = Object.fromEntries(cookie.split(';').map(p => p.trim().split('=')));
  if (!jar['wa_session']) return j({ error: 'unauthorized' }, 401);

  const limit = Math.min(Number(new URL(ctx.request.url).searchParams.get('limit') || 50), 200);

  const url =
    `${SUPABASE_URL}/rest/v1/notes` +
    `?select=id,body,username,created_at,likes,is_hidden` +
    `&order=created_at.desc` +
    `&limit=${limit}`;

  const r = await fetch(url, {
    headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` },
  });
  if (!r.ok) return j({ error: `list ${r.status}` }, 500);
  return j(await r.json());
};

function j(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
