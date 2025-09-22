// functions/webauthn/register/options.ts
import { generateRegistrationOptions } from '@simplewebauthn/server';

const VERSION = 'register-options-v2';

// helper: make base64url bytes from a short string
const strToB64uBytes = (s: string) => {
  const b64 = (typeof btoa !== 'undefined' ? btoa(s) : Buffer.from(s, 'utf8').toString('base64'));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

export const onRequestGet: PagesFunction = async (ctx) => {
  // Cloudflare Pages injects env here. Do NOT hardcode keys.
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;

  try {
    const url = new URL(ctx.request.url);
    const username = (url.searchParams.get('username') || '').toLowerCase().trim();
    if (!username) return json({ error: 'missing_username', VERSION }, 400);
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SERVICE_ROLE) return json({ error: 'missing_env', VERSION }, 500);

    // RP values from request host
    const rpID = url.hostname;
    const rpName = 'Levi Admin';

    // Build WebAuthn registration options
    const options = await generateRegistrationOptions({
      rpID,
      rpName,
      userName: username,
      // user.id must be bytes (base64url is fine for the browser to decode)
      userID: strToB64uBytes(username),
      userDisplayName: '',
      attestationType: 'none',
      authenticatorSelection: {
        requireResidentKey: false,
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      supportedAlgorithmIDs: [-8, -7, -257], // EdDSA, ES256, RS256
    });

    // Set short-lived cookies for verification step
    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append(
      'Set-Cookie',
      `wa_chal=${options.challenge}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300`
    );
    headers.append(
      'Set-Cookie',
      `wa_user=${encodeURIComponent(username)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300`
    );

    return new Response(JSON.stringify({ ...options, VERSION }), { headers });
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
