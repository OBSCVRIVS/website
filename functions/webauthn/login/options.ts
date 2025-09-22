// functions/webauthn/login/options.ts
// PURPOSE: Issue WebAuthn authentication (login) options.
// REQUIREMENTS (set in Cloudflare Pages → Settings → Variables):
//   SUPABASE_URL          = https://<your-project-ref>.supabase.co        <-- ADD in CF Pages UI
//   SUPABASE_ANON_KEY     = <your Supabase anon public key>                <-- ADD in CF Pages UI
//   SERVICE_ROLE          = <your Supabase service role key>               <-- ADD in CF Pages UI
//
// You do NOT paste keys here. The code reads them from ctx.env at runtime.

import { generateAuthenticationOptions } from '@simplewebauthn/server';

export const onRequestGet: PagesFunction = async (ctx) => {
  // rpID must match your domain (derived from incoming request). No change needed.
  const url = new URL(ctx.request.url);
  const rpID = url.hostname;

  // Change "levi" if you want a default username. You can also pass ?username=foo in the URL.
  const username = (url.searchParams.get('username') || 'levi').toLowerCase();

  try {
    // ⬇️ DO NOT hard-code keys here. Ensure these three variables exist in Cloudflare Pages env.
    const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;

    // --- SAFETY CHECKS (helpful errors if envs are missing) ---
    if (!SUPABASE_URL)  throw new Error('Missing env SUPABASE_URL');
    if (!SUPABASE_ANON_KEY) throw new Error('Missing env SUPABASE_ANON_KEY');
    if (!SERVICE_ROLE)  throw new Error('Missing env SERVICE_ROLE');

    // 1) Look up the user by username (uses anon key for `apikey`, service role for `Authorization`)
    const uRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${encodeURIComponent(username)}`,
      {
        headers: {
          // ⬇️ EXACTLY AS REQUIRED: anon key in `apikey`, service role as Bearer in `Authorization`
          apikey: SUPABASE_ANON_KEY,
          Authorization: `Bearer ${SERVICE_ROLE}`,
        },
      }
    );
    if (!uRes.ok) throw new Error(`user lookup ${uRes.status}`);
    const users = await uRes.json();
    const user = users[0];
    if (!user) {
      // If you see this, register first to create the user row.
      return new Response('no user', { status: 404 });
    }

    // 2) Fetch the user's registered credentials (ids). Same header pattern as above.
    const cRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_credentials?select=id,user_id&user_id=eq.${encodeURIComponent(
        user.id
      )}`,
      {
        headers: {
          apikey: SUPABASE_ANON_KEY,
          Authorization: `Bearer ${SERVICE_ROLE}`,
        },
      }
    );
    if (!cRes.ok) throw new Error(`creds lookup ${cRes.status}`);
    const creds = await cRes.json();

    // 3) Build WebAuthn authentication options
    const opts = await generateAuthenticationOptions({
      rpID,
      allowCredentials: Array.isArray(creds)
        ? creds.map((c: any) => ({ id: c.id, type: 'public-key' }))
        : [],
      userVerification: 'preferred',
    });

    // 4) Return options + short-lived cookies to bind the challenge
    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', `wa_chal=${opts.challenge}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
    headers.append('Set-Cookie', `wa_user=${username}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);

    return new Response(JSON.stringify(opts), { headers });
  } catch (err: any) {
    // If something goes wrong (e.g., 401 from Supabase), you’ll see it here.
    // Common causes:
    //  - wrong SUPABASE_URL (must be https://<project-ref>.supabase.co)
    //  - wrong keys or missing variables in Cloudflare Pages
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
