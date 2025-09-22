export const onRequestPost: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = ctx.env as any;

  // Require passkey login: cookie set by /webauthn/login/verify
  const hasSession = /(?:^|;\s*)admin=1(?:;|$)/.test(ctx.request.headers.get('Cookie') || '');
  if (!hasSession) {
    return new Response(JSON.stringify({ error: 'unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Parse body
  let payload: any;
  try {
    payload = await ctx.request.json();
  } catch {
    return new Response(JSON.stringify({ error: 'invalid_json' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  const body = typeof payload?.body === 'string' ? payload.body.trim() : '';
  if (!body) {
    return new Response(JSON.stringify({ error: 'body_required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Create id and insert
  const id = 'note-' + Date.now().toString(36);
  const res = await fetch(`${SUPABASE_URL}/rest/v1/notes`, {
    method: 'POST',
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      'Content-Type': 'application/json',
      Prefer: 'return=representation',
    },
    body: JSON.stringify({ id, body }),
  });

  const text = await res.text();
  if (!res.ok) {
    return new Response(JSON.stringify({ error: 'supabase_insert_failed', status: res.status, body: text }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response(text, { headers: { 'Content-Type': 'application/json' } });
};
