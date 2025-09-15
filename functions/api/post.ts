export const onRequestPost: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SESSION_SECRET } = ctx.env as any;

  // temp protection: require Authorization: Bearer <SESSION_SECRET>
  const auth = ctx.request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (token !== SESSION_SECRET) {
    return new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  const { body } = await ctx.request.json().catch(() => ({ body: '' }));
  if (!body || typeof body !== 'string') {
    return new Response(JSON.stringify({ error: 'invalid_body' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  const id = 'note-' + Date.now().toString(36);

  const url = new URL(`${SUPABASE_URL}/rest/v1/notes`);
  const res = await fetch(url.toString(), {
    method: 'POST',
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      'Content-Type': 'application/json',
      Prefer: 'return=representation'
    },
    body: JSON.stringify({ id, body })
  });

  const text = await res.text();
  if (!res.ok) {
    return new Response(JSON.stringify({ error: 'supabase_insert_failed', status: res.status, body: text }), {
      status: 500, headers: { 'Content-Type': 'application/json' }
    });
  }

  return new Response(text, { headers: { 'Content-Type': 'application/json' } });
};
