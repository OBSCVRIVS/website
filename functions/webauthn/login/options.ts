// functions/webauthn/login/options.ts
import { generateAuthenticationOptions } from '@simplewebauthn/server';

const VERSION = 'login-options-v2';

const b64uToBytes = (s: string) => {
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = typeof atob !== 'undefined' ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

export const onRequestGet: PagesFunction = async (ctx) => {
  // Cloudflare Pages injects env here. Do NOT hardcode keys.
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;

  try {
    const url = new URL(ctx.request.url);
    const username = (url.searchParams.get('username') || '').toLowerCase().trim();
    if (!username) return json({ error: 'missing_username', VERSION }, 400);
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SERVICE_ROLE) return json({ error: 'missing_env', VERSION }, 500);

    // 1) Lookup user
    const uRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${encodeURIComponent(username)}`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!uRes.ok) return json({ error: `user_select ${uRes.status}`, VERSION }, 500);
    const users = await uRes.json();
    const user = users?.[0];
    if (!user) return json({ error: 'no_user', VERSION }, 404);

    // 2) Fetch credentials for allowCredentials
    const cRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_credentials?select=id,user_id&user_id=eq.${encodeURIComponent(user.id)}`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!cRes.ok) return json({ error: `cred_select ${cRes.status}`, VERSION }, 500);
    const creds = await cRes.json();
    if (!Array.isArray(creds) || creds.length === 0) {
      return json({ error: 'no_credentials_for_user', VERSION }, 404);
    }

    const allowCredentials = creds
      .filter((c: any) => c?.id)
      .map((c: any) => ({
        type: 'public-key',
        id: b64uToBytes(String(c.id)), // server gives bytes to browser
        transports: ['internal', 'hybrid', 'usb', 'nfc', 'ble'] as const,
      }));

    // 3) RP values from request host
    const rpID = url.hostname;

    // 4) Build authentication options
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials,
      userVerification: 'preferred',
      timeout: 60_000,
    });

    // 5) Set short-lived cookies for verification step
    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append(
      'Set-Cookie',
      `wa_chal=${options.challenge}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300`
    );
    headers.append(
      'Set-Cookie',
      `wa_user=${encodeURIComponent(username)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300`
    );

    return new Response(JSON.stringify({ ...options, VERSION }), { headers });
  } catch (err: any) {
    return json({ error: String(err), VERSION }, 500);
  }
};

function json(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
