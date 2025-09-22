// functions/webauthn/login/verify.ts
import { verifyAuthenticationResponse } from '@simplewebauthn/server';

// --- helpers ---
const b64uToBytes = (s: string) => {
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = typeof atob !== 'undefined' ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const hexToBytes = (hex: string) => {
  const h = hex.startsWith('\\x') ? hex.slice(2) : hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
};

// parse Supabase bytea payload (hex "\x..." or base64)
const parseBytea = (v: any): Uint8Array => {
  if (v == null) return new Uint8Array();
  if (typeof v === 'string') {
    if (v.startsWith('\\x') || v.startsWith('0x')) return hexToBytes(v);
    // assume base64/base64url
    try { return b64uToBytes(v.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'')); } catch {}
    // last resort: std base64
    const bin = typeof atob !== 'undefined' ? atob(v) : Buffer.from(v, 'base64').toString('binary');
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array((v as any).buffer, (v as any).byteOffset, (v as any).byteLength);
  return new Uint8Array();
};

export const onRequestPost: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;

  try {
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SERVICE_ROLE) {
      return new Response(JSON.stringify({ error: 'missing envs' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }

    // cookies from /webauthn/login/options
    const cookie = ctx.request.headers.get('Cookie') || '';
    const jar = Object.fromEntries(cookie.split(';').map(p => p.trim().split('=')));
    const expectedChallenge = jar['wa_chal'];
    const username = (jar['wa_user'] || '').toLowerCase();
    if (!expectedChallenge || !username) {
      return new Response(JSON.stringify({ error: 'missing_challenge_or_username' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    // client payload
    const body = await ctx.request.json();
    const credIdB64u: string = body?.id;
    if (!credIdB64u) {
      return new Response(JSON.stringify({ error: 'missing_credential_id' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    // look up user
    const uRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${encodeURIComponent(username)}`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!uRes.ok) return new Response(JSON.stringify({ error: `user_select ${uRes.status}` }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    const users = await uRes.json();
    const user = users[0];
    if (!user) return new Response(JSON.stringify({ error: 'no_user' }), { status: 404, headers: { 'Content-Type': 'application/json' } });

    // fetch credential by id (since we used discoverable creds, not allowCredentials)
    const cRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_credentials?select=id,public_key,counter,user_id&id=eq.${encodeURIComponent(credIdB64u)}`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!cRes.ok) return new Response(JSON.stringify({ error: `cred_select ${cRes.status}` }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    const cred = (await cRes.json())[0];
    if (!cred) return new Response(JSON.stringify({ error: 'no_credential' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
    if (cred.user_id !== user.id) {
      return new Response(JSON.stringify({ error: 'credential_user_mismatch' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
    }

    // prepare inputs for verification
    const url = new URL(ctx.request.url);
    const expectedOrigin = `${url.protocol}//${url.host}`;
    const expectedRPID = url.hostname;

    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      credentialID: b64uToBytes(cred.id),           // bytes
      credentialPublicKey: parseBytea(cred.public_key), // bytes from DB
      counter: cred.counter ?? 0,
      requireUserVerification: false,               // relaxed UV
    });

    if (!verification.verified || !verification.authenticationInfo) {
      return new Response(JSON.stringify({ error: 'not_verified', details: verification }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // update counter
    const newCounter = verification.authenticationInfo.newCounter ?? cred.counter ?? 0;
    await fetch(`${SUPABASE_URL}/rest/v1/webauthn_credentials?id=eq.${encodeURIComponent(cred.id)}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${SERVICE_ROLE}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ counter: newCounter }),
    });

    // set session + clear temp cookies
    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', `session=ok; HttpOnly; Secure; SameSite=Strict; Max-Age=86400; Path=/`);
    headers.append('Set-Cookie', 'wa_chal=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');
    headers.append('Set-Cookie', 'wa_user=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');

    return new Response(JSON.stringify({ ok: true }), { headers });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500, headers: { 'Content-Type': 'application/json' }
    });
  }
};
