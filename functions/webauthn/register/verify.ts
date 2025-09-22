// functions/webauthn/register/verify.ts
// Verifies the WebAuthn attestation and stores user + credential in Supabase.

import { verifyRegistrationResponse } from '@simplewebauthn/server';

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
    // 1) Read cookies set by /webauthn/register/options
    const cookie = ctx.request.headers.get('Cookie') || '';
    const jar = Object.fromEntries(cookie.split(';').map(p => p.trim().split('=')));
    const expectedChallenge = jar['wa_chal'];
    const username = (jar['wa_user'] || '').toLowerCase();

    if (!expectedChallenge || !username) {
      return new Response(JSON.stringify({ error: 'missing_challenge_or_username' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // 2) Parse client response
    const body = await ctx.request.json();

    // 3) Verify with SimpleWebAuthn
    const url = new URL(ctx.request.url);
    const rpID = url.hostname;
    const expectedOrigin = `${url.protocol}//${url.host}`;

    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      // optionally: requireUserVerification: true,
    });

    if (!verified || !registrationInfo) {
      return new Response(JSON.stringify({ error: 'not_verified' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // Extract fields (v10 returns bytes for IDs/keys)
    const credentialID = registrationInfo.credentialID;                 // Uint8Array
    const credentialPublicKey = registrationInfo.credentialPublicKey;   // Uint8Array
    const counter = registrationInfo.counter ?? 0;

    // Store ID as base64url string so we can send it back to browsers
    const credIdB64u = bytesToB64u(credentialID);

    // 4) Ensure user exists
    // SELECT user
    let uRes = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${encodeURIComponent(username)}`, {
      headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` }
    });
    if (!uRes.ok) throw new Error(`user_select ${uRes.status}`);
    const users = await uRes.json();
    let userId = users[0]?.id;

    // INSERT if missing
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
      if (!ins.ok) {
        const t = await ins.text();
        throw new Error(`user_insert ${ins.status} ${t}`);
      }
      const row = await ins.json();
      userId = row[0].id;
    }

    // 5) Insert credential
    const credIns = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_credentials`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${SERVICE_ROLE}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        id: credIdB64u,                 // text (base64url)
        user_id: userId,                // uuid
        public_key: credentialPublicKey, // bytea
        counter: counter,
        transports: null
      })
    });
    if (!credIns.ok) {
      const t = await credIns.text();
      throw new Error(`cred_insert ${credIns.status} ${t}`);
    }

    // 6) Clear temp cookies
    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', 'wa_chal=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');
    headers.append('Set-Cookie', 'wa_user=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');

    return new Response(JSON.stringify({ ok: true, id: credIdB64u }), { headers });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500, headers: { 'Content-Type': 'application/json' }
    });
  }
};
