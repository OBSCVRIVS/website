// functions/webauthn/register/verify.ts
import { verifyRegistrationResponse } from '@simplewebauthn/server';

const VERSION = 'register-verify-v3';

const bytesToB64 = (arr: ArrayBuffer | Uint8Array) => {
  const u8 = arr instanceof Uint8Array ? arr : new Uint8Array(arr);
  // btoa expects binary string
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return (typeof btoa !== 'undefined' ? btoa(s) : Buffer.from(u8).toString('base64'));
};

function j(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}

export const onRequestPost: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;

  try {
    const cookie = ctx.request.headers.get('Cookie') || '';
    const jar = Object.fromEntries(cookie.split(';').map(p => p.trim().split('=')));
    const expectedChallenge = jar['wa_chal'];
    const username = (jar['wa_user'] || '').toLowerCase();
    if (!expectedChallenge || !username) return j({ error: 'missing_challenge_or_username', VERSION }, 400);

    const body = await ctx.request.json();

    const url = new URL(ctx.request.url);
    const rpID = url.hostname;
    const expectedOrigin = `${url.protocol}//${url.host}`;

    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });
    if (!verified || !registrationInfo) return j({ error: 'not_verified', VERSION }, 400);

    // Use browser-provided id as stored id (base64url string)
    const credIdB64u: string = String(body.id || '');
    if (!credIdB64u) return j({ error: 'missing_client_credential_id', VERSION }, 400);

    // Convert public key bytes → base64 string for PostgREST bytea
    const publicKey_b64 = bytesToB64(registrationInfo.credentialPublicKey);
    const counter = registrationInfo.counter ?? 0;

    // Ensure user
    const uRes = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${encodeURIComponent(username)}`, {
      headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` }
    });
    if (!uRes.ok) return j({ error: `user_select ${uRes.status}`, VERSION }, 500);
    const users = await uRes.json();
    let userId = users[0]?.id as string | undefined;

    if (!userId) {
      const ins = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_users`, {
        method: 'POST',
        headers: {
          apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}`,
          'Content-Type': 'application/json', Prefer: 'return=representation'
        },
        body: JSON.stringify({ username })
      });
      if (!ins.ok) return j({ error: `user_insert ${ins.status} ${await ins.text()}`, VERSION }, 500);
      userId = (await ins.json())[0].id;
    }

    // Insert/merge credential; send bytea as base64 string
    const credIns = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_credentials`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}`,
        'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates'
      },
      body: JSON.stringify({
        id: credIdB64u,           // base64url string
        user_id: userId,          // uuid
        public_key: publicKey_b64, // bytea via base64
        counter: counter,
        transports: null
      })
    });
    if (!credIns.ok) return j({ error: `cred_insert ${credIns.status} ${await credIns.text()}`, VERSION }, 500);

    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', 'wa_chal=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');
    headers.append('Set-Cookie', 'wa_user=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');

    return new Response(JSON.stringify({ ok: true, VERSION }), { headers });
  } catch (err: any) {
    return j({ error: String(err), VERSION }, 500);
  }
};
