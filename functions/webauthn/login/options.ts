import { generateAuthenticationOptions } from '@simplewebauthn/server';

export const onRequestGet: PagesFunction = async (ctx) => {
  const url = new URL(ctx.request.url);
  const rpID = url.hostname;
  const username = (url.searchParams.get('username') || 'levi').toLowerCase();

  try {
    const { SUPABASE_URL, SERVICE_ROLE } = ctx.env as any; // <-- correct secret name

    // lookup user
    const uRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${encodeURIComponent(
        username
      )}`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!uRes.ok) throw new Error(`user lookup ${uRes.status}`);
    const users = await uRes.json();
    const user = users[0];
    if (!user) return new Response('no user', { status: 404 });

    // lookup credentials
    const cRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_credentials?select=id,user_id&user_id=eq.${encodeURIComponent(
        user.id
      )}`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!cRes.ok) throw new Error(`creds lookup ${cRes.status}`);
    const creds = await cRes.json();

    const opts = await generateAuthenticationOptions({
      rpID,
      allowCredentials: Array.isArray(creds)
        ? creds.map((c: any) => ({ id: c.id, type: 'public-key' }))
        : [],
      userVerification: 'preferred',
    });

    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', `wa_chal=${opts.challenge}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
    headers.append('Set-Cookie', `wa_user=${username}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
    return new Response(JSON.stringify(opts), { headers });
  } catch (err: any) {
    console.error('login/options error:', err?.stack || err);
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
