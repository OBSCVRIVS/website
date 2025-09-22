import { verifyAuthenticationResponse } from '@simplewebauthn/server';

export const onRequestPost: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SITE_ORIGIN } = ctx.env as any;

  const cookies = Object.fromEntries((ctx.request.headers.get('Cookie') || '')
    .split(';').map(p => p.trim().split('=')) as any);
  const expectedChallenge = cookies['wa_chal'];
  const username = cookies['wa_user'];
  if (!expectedChallenge || !username) return new Response('missing challenge', { status: 400 });

  const body = await ctx.request.json();

  const credId = body.id || body.rawId;
  const cRes = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_credentials?select=id,public_key,counter,user_id&id=eq.${credId}`, {
    headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` },
  });
  const rows = await cRes.json();
  const cred = rows[0];
  if (!cred) return new Response('unknown credential', { status: 400 });

  // Supabase bytea comes as { data: [...] } in some drivers. Normalize to Uint8Array.
  const pkBytes: Uint8Array = Array.isArray((cred.public_key as any)?.data)
    ? new Uint8Array((cred.public_key as any).data)
    : new Uint8Array(cred.public_key as any);

  const { verified, authenticationInfo } = await verifyAuthenticationResponse({
    response: body,
    expectedChallenge,
    expectedOrigin: SITE_ORIGIN,
    expectedRPID: new URL(SITE_ORIGIN).hostname,
    authenticator: {
      credentialID: cred.id,
      credentialPublicKey: pkBytes,
      counter: Number(cred.counter || 0),
    },
  });
  if (!verified || !authenticationInfo) return new Response('not verified', { status: 400 });

  await fetch(`${SUPABASE_URL}/rest/v1/webauthn_credentials?id=eq.${cred.id}`, {
    method: 'PATCH',
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ counter: authenticationInfo.newCounter, last_used_at: new Date().toISOString() })
  });

  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append('Set-Cookie', `admin=1; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`);
  headers.append('Set-Cookie', 'wa_chal=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');
  headers.append('Set-Cookie', 'wa_user=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');
  return new Response(JSON.stringify({ ok: true }), { headers });
};
