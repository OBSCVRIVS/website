// functions/webauthn/login/verify.ts
// v7-min: no counter usage, single-read, explicit debug
import { verifyAuthenticationResponse } from '@simplewebauthn/server';

const VERSION = 'login-verify-v7-min';

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
const parseBytea = (v: any): Uint8Array => {
  if (v == null) return new Uint8Array();
  if (typeof v === 'string') {
    if (v.startsWith('\\x') || v.startsWith('0x')) return hexToBytes(v);
    try { return b64uToBytes(v.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')); } catch {}
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
      return json({ error: 'missing envs', VERSION }, 500);
    }

    const cookie = ctx.request.headers.get('Cookie') || '';
    const jar = Object.fromEntries(cookie.split(';').map(p => p.trim().split('=')));
    const expectedChallenge = jar['wa_chal'];
    const username = (jar['wa_user'] || '').toLowerCase();
    if (!expectedChallenge || !username) return json({ error: 'missing_challenge_or_username', VERSION }, 400);

    const body = await ctx.request.json();
    const credIdFromClient: string | undefined = body?.id;
    if (!credIdFromClient) return json({ error: 'missing_credential_id', VERSION }, 400);

    // user
    const uRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${encodeURIComponent(username)}`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!uRes.ok) return json({ error: `user_select ${uRes.status}`, VERSION }, 500);
    const users = await uRes.json();
    const user = users?.[0];
    if (!user) return json({ error: 'no_user', VERSION }, 404);

    // credentials for user (no counter selected)
    const cRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_credentials?select=id,public_key,user_id&user_id=eq.${encodeURIComponent(user.id)}`,
      { headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    if (!cRes.ok) return json({ error: `cred_select ${cRes.status}`, VERSION }, 500);
    const credsRaw = await cRes.json();
    const allCreds: any[] = Array.isArray(credsRaw) ? credsRaw : [];

    const cred = allCreds.find((c: any) => String(c?.id || '') === String(credIdFromClient));
    if (!cred) return json({ error: 'no_credential_for_user', got: credIdFromClient, have: allCreds.map((c:any)=>c?.id || null), VERSION }, 404);

    const credIdStr = String(cred.id || '');
    if (!credIdStr) return json({ error: 'credential_has_empty_id', VERSION }, 500);

    const publicKeyBytes = parseBytea(cred.public_key);
    if (!publicKeyBytes?.length) return json({ error: 'credential_missing_public_key', VERSION }, 500);

    const url = new URL(ctx.request.url);
    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: `${url.protocol}//${url.host}`,
      expectedRPID: url.hostname,
      credentialID: b64uToBytes(credIdStr),
      credentialPublicKey: publicKeyBytes,
      // no counter at all
      requireUserVerification: false,
    });

    if (!verification?.verified) return json({ error: 'not_verified', details: verification || null, VERSION }, 400);

    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', `session=ok; HttpOnly; Secure; SameSite=Strict; Max-Age=86400; Path=/`);
    headers.append('Set-Cookie', 'wa_chal=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');
    headers.append('Set-Cookie', 'wa_user=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');

    return new Response(JSON.stringify({ ok: true, VERSION }), { headers });
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
