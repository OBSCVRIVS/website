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

    // Optional lookups (keep to confirm user exists; not used to filter credentials)
    const uRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${encodeURIComponent(username)}`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!uRes.ok) return new Response(JSON.stringify({ error: `user lookup ${uRes.status}` }), { status: 500 });
    const users = await uRes.json();
    const user = users[0];
    if (!user) return new Response('no user', { status: 404 });

    // Do NOT pass allowCredentials → enable discoverable credential (passkey) selection
    const opts = await generateAuthenticationOptions({
      rpID,
      userVerification: 'preferred',
      // allowCredentials: []  // intentionally omitted
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
