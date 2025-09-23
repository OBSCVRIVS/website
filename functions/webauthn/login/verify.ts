// functions/webauthn/login/verify.ts
import { verifyAuthenticationResponse } from '@simplewebauthn/server';

const VERSION = 'login-verify-v6';

// --- robust decoders ---
const b64urlToBytes = (s: string) => {
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = typeof atob !== 'undefined' ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const b64ToBytes = (s: string) => {
  const bin = typeof atob !== 'undefined' ? atob(s) : Buffer.from(s, 'base64').toString('binary');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const hexToBytes = (hex: string) => {
  const h = hex.startsWith('\\x') || hex.startsWith('0x') ? hex.slice(2) : hex;
  if (h.length % 2) throw new Error('hex length odd');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
};
const decodeAny = (v: any): Uint8Array => {
  if (!v) return new Uint8Array();
  if (v instanceof Uint8Array) return v;
  if (v?.data && Array.isArray(v.data)) return new Uint8Array(v.data); // some drivers
  if (typeof v === 'string') {
    try {
      if (v.startsWith('\\x') || v.startsWith('0x')) return hexToBytes(v);
      if (/^[A-Za-z0-9+/]+={0,2}$/.test(v)) return b64ToBytes(v);   // base64
      if (/^[A-Za-z0-9\-_]+$/.test(v)) return b64urlToBytes(v);     // base64url
      // last resort: try base64 then base64url
      try { return b64ToBytes(v); } catch {}
      return b64urlToBytes(v);
    } catch (e) {
      throw new Error('public_key decode failed');
    }
  }
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  throw new Error('unsupported public_key type');
};

function j(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}

export const onRequestPost: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;

  try {
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SERVICE_ROLE) return j({ error: 'missing_env', VERSION }, 500);

    const cookie = ctx.request.headers.get('Cookie') || '';
    const jar = Object.fromEntries(cookie.split(';').map(p => p.trim().split('=')));
    const expectedChallenge = jar['wa_chal'];
    const username = (jar['wa_user'] || '').toLowerCase();
    if (!expectedChallenge || !username) return j({ error: 'missing_challenge_or_username', VERSION }, 400);

    const body = await ctx.request.json();
    const credIdFromClient: string | undefined = body?.id;
    if (!credIdFromClient) return j({ error: 'missing_client_credential_id', VERSION }, 400);

    // user → UUID
    const uRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${encodeURIComponent(username)}`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!uRes.ok) return j({ error: `user_select ${uRes.status}`, VERSION }, 500);
    const users = await uRes.json();
    const user = users?.[0];
    if (!user?.id) return j({ error: 'no_user', VERSION }, 404);

    // creds for user_id
    const cRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_credentials?select=id,public_key,counter&user_id=eq.${encodeURIComponent(user.id)}`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!cRes.ok) return j({ error: `cred_select ${cRes.status}`, VERSION }, 500);
    const creds = (await cRes.json()) as Array<any>;
    if (!Array.isArray(creds) || creds.length === 0) return j({ error: 'no_credentials_for_user', VERSION }, 404);

    const cred = creds.find(c => String(c?.id || '') === String(credIdFromClient));
    if (!cred) return j({ error: 'no_credential_for_user', got: credIdFromClient, have: creds.map(c => c?.id || null), VERSION }, 404);

    // decode fields
    const credentialID = b64urlToBytes(String(cred.id));        // stored as base64url string
    const credentialPublicKey = decodeAny(cred.public_key);     // hex | base64 | base64url
    const prevCounter = Number(cred.counter ?? 0);

    const url = new URL(ctx.request.url);
    const { verified, authenticationInfo } = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: `${url.protocol}//${url.host}`,
      expectedRPID: url.hostname,
      authenticator: { credentialID, credentialPublicKey, counter: prevCounter },
      requireUserVerification: false,
    });
    if (!verified || !authenticationInfo) return j({ error: 'not_verified', VERSION }, 400);

    // bump counter
    const up = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_credentials?id=eq.${encodeURIComponent(String(cred.id))}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}`, 'Content-Type': 'application/json',
      },
      body: JSON.stringify({ counter: authenticationInfo.newCounter ?? prevCounter }),
    });
    if (!up.ok) return j({ error: `counter_update ${up.status}`, VERSION }, 500);

    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', `wa_session=${encodeURIComponent(username)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=86400`);
    headers.append('Set-Cookie', 'wa_chal=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');
    headers.append('Set-Cookie', 'wa_user=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');

    return new Response(JSON.stringify({ ok: true, VERSION }), { headers });
  } catch (err: any) {
    return j({ error: String(err), VERSION }, 500);
  }
};
