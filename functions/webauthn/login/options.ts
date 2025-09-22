import { generateAuthenticationOptions } from '@simplewebauthn/server';

export const onRequestGet: PagesFunction = async (ctx) => {
  const url = new URL(ctx.request.url);
  const rpID = url.hostname;
  const username = (url.searchParams.get('username') || 'levi').toLowerCase();

  try {
    const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;

    // user lookup
    const uRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_users?select=id,username&username=eq.${encodeURIComponent(username)}`,
      {
        headers: {
          apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im55eWhiaGp1a2h5eHNuYmRydGN1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTc4ODg0OTksImV4cCI6MjA3MzQ2NDQ5OX0.9-kU6rsSVKSpmAEssgRXpgoh_ptM4Bd7qP4PKVhziMw,
          Authorization: `Bearer ${eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im55eWhiaGp1a2h5eHNuYmRydGN1Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1Nzg4ODQ5OSwiZXhwIjoyMDczNDY0NDk5fQ.WszA-LN3r_AV0bBqeNWyzXaA759bmoea39dqOByzRbI}`,
        },
      }
    );
    if (!uRes.ok) throw new Error(`user lookup ${uRes.status}`);
    const users = await uRes.json();
    const user = users[0];
    if (!user) return new Response('no user', { status: 404 });

    // credentials lookup
    const cRes = await fetch(
      `${SUPABASE_URL}/rest/v1/webauthn_credentials?select=id,user_id&user_id=eq.${encodeURIComponent(user.id)}`,
      {
        headers: {
          apikey: SUPABASE_ANON_KEY,
          Authorization: `Bearer ${SERVICE_ROLE}`,
        },
      }
    );
    if (!cRes.ok) throw new Error(`creds lookup ${cRes.status}`);
    const creds = await cRes.json();

    const opts = await generateAuthenticationOptions({
      rpID,
      allowCredentials: Array.isArray(creds)
        ? creds.map((c: any) => ({ id: c.id, type: 'public-key' }))
        : [],
      userVerification: 'preferred',
    });

    const headers = new Headers({ 'Content-Type': 'application/json' });
    headers.append('Set-Cookie', `wa_chal=${opts.challenge}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
    headers.append('Set-Cookie', `wa_user=${username}; HttpOnly; Secure; SameSite=Strict; Max-Age=300; Path=/`);
    return new Response(JSON.stringify(opts), { headers });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
