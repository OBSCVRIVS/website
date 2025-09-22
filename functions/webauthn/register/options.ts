// functions/webauthn/register/options.ts
// Issues WebAuthn registration options and sets short-lived cookies binding the challenge.
// No env vars required here.

import { generateRegistrationOptions } from '@simplewebauthn/server';

export const onRequestGet: PagesFunction = async (ctx) => {
  try {
    const url = new URL(ctx.request.url);
    const rpID = url.hostname; // derive from request host
    const username = (url.searchParams.get('username') || 'levi').toLowerCase();

    // Generate options
    const opts = await generateRegistrationOptions({
      rpName: 'Levi Admin',
      rpID,
      userID: username,   // stable id for your account
      userName: username, // display name
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    // Bind challenge to short-lived cookies
    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', `wa_chal=${opts.challenge}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
    headers.append('Set-Cookie', `wa_user=${username}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);

    return new Response(JSON.stringify(opts), { headers });
  } catch (err: any) {
    // Return explicit JSON so Cloudflare does not show 1101
    return new Response(
      JSON.stringify({
        error: String(err?.message || err),
        hint: 'Check that the file path is /functions/webauthn/register/options.ts and the project built with @simplewebauthn/server installed.',
      }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
};
