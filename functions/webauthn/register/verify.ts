import { verifyRegistrationResponse } from 'https://esm.sh/@simplewebauthn/server@10.0.0';

export const onRequestPost: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SITE_ORIGIN } = ctx.env as any;
  const cookies = Object.fromEntries((ctx.request.headers.get('Cookie')||'')
    .split(';').map(p=>p.trim().split('=')) as any);
  const expectedChallenge = cookies['wa_chal'];
  const username = cookies['wa_user'];
  if (!expectedChallenge || !username) return new Response('missing challenge', { status: 400 });

  const body = await ctx.request.json();

  const { verified, registrationInfo } = await verifyRegistrationResponse({
    response: body,
    expectedChallenge,
    expectedOrigin: SITE_ORIGIN,
    expectedRPID: new URL(SITE_ORIGIN).hostname,
  });

  if (!verified || !registrationInfo) return new Response('not verified', { status: 400 });

  // upsert user
  const userRes = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${username}`, {
    headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` },
  });
  const users = await userRes.json();
  let userId = users[0]?.id;
  if (!userId) {
    const ins = await fetch(`${SUPABASE_URL}/rest/v1/webauthn_users`, {
      method: 'POST',
      headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`, 'Content-Type':'application/json' },
      body: JSON.stringify({ username })
    });
    const row = await ins.json();
    userId = row[0].id;
  }

  const cred = registrationInfo.credential;
  await fetch(`${SUPABASE_URL}/rest/v1/webauthn_credentials`, {
    method: 'POST',
    headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`, 'Content-Type':'application/json' },
    body: JSON.stringify({
      id: cred.id,               // credential ID
      user_id: userId,
      public_key: registrationInfo.credentialPublicKey, // byte array; Supabase column is bytea
      counter: registrationInfo.counter,
      transports: cred.transports || null,
    })
  });

  // clear challenge cookies
  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append('Set-Cookie', 'wa_chal=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');
  headers.append('Set-Cookie', 'wa_user=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');
  return new Response(JSON.stringify({ ok: true }), { headers });
};
