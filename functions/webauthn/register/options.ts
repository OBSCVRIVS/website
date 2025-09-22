import { generateRegistrationOptions } from '@simplewebauthn/server';

export const onRequestGet: PagesFunction = async (ctx) => {
  const url = new URL(ctx.request.url);
  const rpID = url.hostname; // derive from request, no env needed
  const username = (url.searchParams.get('username') || 'levi').toLowerCase();

  const opts = await generateRegistrationOptions({
    rpName: 'Levi Admin',
    rpID,
    userID: username,
    userName: username,
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
  });

  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append('Set-Cookie', `wa_chal=${opts.challenge}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
  headers.append('Set-Cookie', `wa_user=${username}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
  return new Response(JSON.stringify(opts), { headers });
};
