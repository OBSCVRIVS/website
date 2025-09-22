// functions/webauthn/register/options.ts
import { generateRegistrationOptions } from '@simplewebauthn/server';

const VERSION = 'register-options-v3';

// bytes from plain string
const strToBytes = (s: string) => new TextEncoder().encode(s);

export const onRequestGet: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;

  try {
    const url = new URL(ctx.request.url);
    const username = (url.searchParams.get('username') || '').toLowerCase().trim();
    if (!username) return json({ error: 'missing_username', VERSION }, 400);
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SERVICE_ROLE) return json({ error: 'missing_env', VERSION }, 500);

    const rpID = url.hostname;
    const rpName = 'Levi Admin';

    const options = await generateRegistrationOptions({
      rpID,
      rpName,
      userName: username,
      userID: strToBytes(username),        // <— Uint8Array, NOT string
      userDisplayName: '',
      attestationType: 'none',
      authenticatorSelection: {
        requireResidentKey: false,
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      supportedAlgorithmIDs: [-8, -7, -257],
    });

    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', `wa_chal=${options.challenge}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300`);
    headers.append('Set-Cookie', `wa_user=${encodeURIComponent(username)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300`);

    return new Response(JSON.stringify({ ...options, VERSION }), { headers });
  } catch (err: any) {
    return json({ error: String(err), VERSION }, 500);
  }
};

function json(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
