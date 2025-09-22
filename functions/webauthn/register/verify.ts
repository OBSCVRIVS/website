// functions/webauthn/register/verify.ts
import { verifyRegistrationResponse } from '@simplewebauthn/server';

const VERSION = 'register-verify-v2';

const b64uToBytes = (s: string) => {
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = typeof atob !== 'undefined' ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const bytesToB64u = (arr: ArrayBuffer | Uint8Array) => {
  const u8 = arr instanceof Uint8Array ? arr : new Uint8Array(arr);
  const b64 = (typeof btoa !== 'undefined'
    ? btoa(String.fromCharCode(...u8))
    : Buffer.from(u8).toString('base64'));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
};

export const onRequestPost: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;

  try {
    // cookies
    const cookie = ctx.request.headers.get('Cookie') || '';
    const jar = Object.fromEntries(cookie.split(';').map(p => p.trim().split('=')));
    const expectedChallenge = jar['wa_chal'];
    const username = (jar['wa_user'] || '').toLowerCase();
    if (!expectedChallenge || !username) {
      return new Response(JSON.stringify({ error: 'missing_challenge_or_username', VERSION }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // client payload
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
    if (!verified || !registrationInfo) {
      return new Response(JSON.stringify({ error: 'not_verified', VERSION }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // Use the browser's credential id exactly as sent (base64url string)
    const credIdB64u: string = String(body.id || '');
    if (!credIdB64u) {
      return new Response(JSON.stringify({ error: 'missing_client_credential_id', VERSION }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // Public key bytes from SimpleWebAuthn
    const credentialPublicKey = registrationInfo.credentialPublicKey; // Uint8Array
    const counter = registrationInfo.counter ?? 0;

    // Ensure user row
    let uRes = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${encodeURIComponent(username)}`, {
      headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` }
    });
    if (!uRes.ok) throw new Error(`user_select ${uRes.status}`);
    const users = await uRes.json();
    let userId = users[0]?.id;

    if (!userId) {
      const ins = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_users`, {
        method: 'POST',
        headers: {
          apikey: SUPABASE_ANON_KEY,
          Authorization: `Bearer ${SERVICE_ROLE}`,
          'Content-Type': 'application/json',
          Prefer: 'return=representation'
        },
        body: JSON.stringify({ username })
      });
      if (!ins.ok) throw new Error(`user_insert ${ins.status} ${await ins.text()}`);
      userId = (await ins.json())[0].id;
    }

    // Insert or upsert credential by id
    const credIns = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_credentials`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${SERVICE_ROLE}`,
        'Content-Type': 'application/json',
        Prefer: 'resolution=merge-duplicates'
      },
      body: JSON.stringify({
        id: credIdB64u,
        user_id: userId,
        public_key: credentialPublicKey,
        counter: counter,
        transports: null
      })
    });
    if (!credIns.ok) throw new Error(`cred_insert ${credIns.status} ${await credIns.text()}`);

    // clear temp cookies
    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', 'wa_chal=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');
    headers.append('Set-Cookie', 'wa_user=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');

    return new Response(JSON.stringify({ ok: true, id: credIdB64u, VERSION }), { headers });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: String(err), VERSION }), {
      status: 500, headers: { 'Content-Type': 'application/json' }
    });
  }
};
