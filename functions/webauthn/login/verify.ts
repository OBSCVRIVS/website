// functions/webauthn/login/verify.ts
import { verifyAuthenticationResponse } from '@simplewebauthn/server';

const VERSION = 'login-verify-v2';

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

    // get user credentials from Supabase
    const credsRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_credentials?select=id,public_key,counter,user_id&user_id=eq.${encodeURIComponent(username)}`,
      {
        headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` }
      }
    );
    if (!credsRes.ok) throw new Error(`cred_select ${credsRes.status}`);
    const creds = await credsRes.json();

    if (!creds.length) {
      return new Response(JSON.stringify({ error: 'no_credential_for_user', VERSION }), {
        status: 404, headers: { 'Content-Type': 'application/json' }
      });
    }

    const cred = creds.find((c: any) => c.id === body.id);
    if (!cred) {
      return new Response(JSON.stringify({ error: 'credential_not_found', got: body.id, have: creds.map((c: any) => c.id), VERSION }), {
        status: 404, headers: { 'Content-Type': 'application/json' }
      });
    }

    // verify with SimpleWebAuthn
    const url = new URL(ctx.request.url);
    const rpID = url.hostname;
    const expectedOrigin = `${url.protocol}//${url.host}`;

    const { verified, authenticationInfo } = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: b64uToBytes(cred.id),
        credentialPublicKey: cred.public_key.data
          ? new Uint8Array(cred.public_key.data) // Supabase bytea → ArrayBuffer
          : b64uToBytes(cred.public_key),
        counter: cred.counter ?? 0
      },
      requireUserVerification: false,
    });

    if (!verified || !authenticationInfo) {
      return new Response(JSON.stringify({ error: 'not_verified', VERSION }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // update counter in Supabase
    const up = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_credentials?id=eq.${encodeURIComponent(cred.id)}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${SERVICE_ROLE}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ counter: authenticationInfo.newCounter })
    });
    if (!up.ok) throw new Error(`counter_update ${up.status} ${await up.text()}`);

    // success, set cookie
    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', `wa_session=${username}; Path=/; Secure; HttpOnly; SameSite=Strict`);

    return new Response(JSON.stringify({ ok: true, id: cred.id, VERSION }), { headers });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: String(err), VERSION }), {
      status: 500, headers: { 'Content-Type': 'application/json' }
    });
  }
};
