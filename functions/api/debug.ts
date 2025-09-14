export const onRequestGet: PagesFunction = async (ctx) => {
  const env = ctx.env as any;
  return new Response(JSON.stringify({
    has_SUPABASE_URL: !!env.SUPABASE_URL,
    has_SUPABASE_ANON_KEY: !!env.SUPABASE_ANON_KEY,
    has_SERVICE_ROLE: !!env.SUPABASE_SERVICE_ROLE_KEY,
    site_origin: env.SITE_ORIGIN || null,
  }), { headers: { "Content-Type": "application/json" }});
};
