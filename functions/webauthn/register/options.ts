import { generateRegistrationOptions } from 'npm:@simplewebauthn/server@10.0.0';

export const onRequestGet: PagesFunction = async (ctx) => {
  const { SITE_ORIGIN } = ctx.env as any;
  const url = new URL(ctx.request.url);
  const username = (url.searchParams.get('username') || 'levi').toLowerCase();

  const opts = await generateRegistrationOptions({
    rpName: 'Levi Admin',
    rpID: new URL(SITE_ORIGIN).hostname,
    userID: username,            // single admin user
    userName: username,
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
  });

  // store challenge + username in secure, short-lived cookies
  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append('Set-Cookie', `wa_chal=${opts.challenge}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
  headers.append('Set-Cookie', `wa_user=${username}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
  return new Response(JSON.stringify(opts), { headers });
};
