// functions/webauthn/register/options.ts
import { generateRegistrationOptions } from '@simplewebauthn/server';

export const onRequestGet: PagesFunction = async (ctx) => {
  try {
    const url = new URL(ctx.request.url);
    const rpID = url.hostname;
    const username = (url.searchParams.get('username') || 'levi').toLowerCase();

    // userID must be bytes, not a string
    const userID = new TextEncoder().encode(username);

    const opts = await generateRegistrationOptions({
      rpName: 'Levi Admin',
      rpID,
      userID,           // Uint8Array
      userName: username,
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    });

    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', `wa_chal=${opts.challenge}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
    headers.append('Set-Cookie', `wa_user=${username}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
    return new Response(JSON.stringify(opts), { headers });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500, headers: { 'Content-Type': 'application/json' }
    });
  }
};
