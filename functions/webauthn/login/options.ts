// functions/webauthn/login/options.ts
import { generateAuthenticationOptions } from '@simplewebauthn/server';

const b64uToBytes = (s: string) => {
  // decode base64url -> Uint8Array
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = typeof atob !== 'undefined' ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

export const onRequestGet: PagesFunction = async (ctx) => {
  const url = new URL(ctx.request.url);
  const rpID = url.hostname;
  const username = (url.searchParams.get('username') || 'levi').toLowerCase();

  try {
    const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SERVICE_ROLE) {
      return new Response(JSON.stringify({ error: 'missing envs' }), { status: 500 });
    }

    // user lookup
    const uRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${encodeURIComponent(username)}`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!uRes.ok) throw new Error(`user lookup ${uRes.status}`);
    const users = await uRes.json();
    const user = users[0];
    if (!user) return new Response('no user', { status: 404 });

    // credentials for that user
    const cRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_credentials?select=id,user_id&user_id=eq.${encodeURIComponent(user.id)}`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!cRes.ok) throw new Error(`creds lookup ${cRes.status}`);
    const creds = await cRes.json();

    // id must be bytes
    const allowCredentials = Array.isArray(creds)
      ? creds.map((c: any) => ({ id: b64uToBytes(String(c.id)), type: 'public-key' }))
      : [];

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
