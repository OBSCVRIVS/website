// functions/webauthn/login/options.ts
import { generateAuthenticationOptions } from '@simplewebauthn/server';

export const onRequestGet: PagesFunction = async (ctx) => {
  const url = new URL(ctx.request.url);
  const rpID = url.hostname;
  const username = (url.searchParams.get('username') || 'levi').toLowerCase();

  try {
    const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SERVICE_ROLE) {
      return new Response(JSON.stringify({ error: 'missing envs' }), {
        status: 500, headers: { 'Content-Type': 'application/json' }
      });
    }

    // 1) Find user
    const uRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${encodeURIComponent(username)}`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!uRes.ok) return new Response(JSON.stringify({ error: `user lookup ${uRes.status}` }), { status: 500 });
    const users = await uRes.json();
    const user = users[0];
    if (!user) return new Response('no user', { status: 404 });

    // 2) Find credentials for user
    const cRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_credentials?select=id&user_id=eq.${encodeURIComponent(user.id)}`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!cRes.ok) return new Response(JSON.stringify({ error: `creds lookup ${cRes.status}` }), { status: 500 });
    const creds = await cRes.json();
    if (!Array.isArray(creds) || creds.length === 0) return new Response('no credential', { status: 404 });

    // IMPORTANT: return base64url strings; the client JS will convert to bytes
    const allowCredentials = creds.map((c: any) => ({ id: String(c.id), type: 'public-key' }));

    const opts = await generateAuthenticationOptions({
      rpID,
      allowCredentials,
      userVerification: 'preferred',
    });

    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', `wa_chal=${opts.challenge}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
    headers.append('Set-Cookie', `wa_user=${username}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);

    return new Response(JSON.stringify(opts), { headers });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500, headers: { 'Content-Type': 'application/json' }
    });
  }
};
