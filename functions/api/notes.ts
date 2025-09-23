// functions/api/notes.ts
// Public list: only visible notes, newest first.
export const onRequestGet: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY } = ctx.env as any;
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY) return j({ error: 'missing_env' }, 500);

  const url =
    `${SUPABASE_URL}/rest/v1/notes` +
    `?select=id,body,username,created_at,likes` +
    `&is_hidden=is.false` +
    `&order=created_at.desc`;

  const r = await fetch(url, {
    headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SUPABASE_ANON_KEY}` },
  });

  if (!r.ok) return j({ error: `list ${r.status}` }, 500);
  const rows = await r.json();
  return j(rows);
};

function j(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
