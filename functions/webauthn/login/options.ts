import { generateAuthenticationOptions } from '@simplewebauthn/server';

export const onRequestGet: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SITE_ORIGIN } = ctx.env as any;
  const url = new URL(ctx.request.url);
  const username = (url.searchParams.get('username') || 'levi').toLowerCase();

  const uRes = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${username}`, {
    headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` },
  });
  const users = await uRes.json();
  const user = users[0];
  if (!user) return new Response('no user', { status: 404 });

  const cRes = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_credentials?select=id,user_id&user_id=eq.${user.id}`, {
    headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` },
  });
  const creds = await cRes.json();

  const opts = await generateAuthenticationOptions({
    rpID: new URL(SITE_ORIGIN).hostname,
    allowCredentials: creds.map((c: any) => ({ id: c.id, type: 'public-key' })),
    userVerification: 'preferred',
  });

  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append('Set-Cookie', `wa_chal=${opts.challenge}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
  headers.append('Set-Cookie', `wa_user=${username}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
  return new Response(JSON.stringify(opts), { headers });
};
