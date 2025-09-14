export const onRequestGet: PagesFunction = async (context) => {
  const SUPABASE_URL = context.env.SUPABASE_URL;
  const SUPABASE_ANON_KEY = context.env.SUPABASE_ANON_KEY;

  const url = new URL(`${SUPABASE_URL}/rest/v1/notes`);
  url.searchParams.set("select", "id,body,created_at,likes");
  url.searchParams.set("order", "created_at.desc");
  url.searchParams.set("limit", "50");

  const res = await fetch(url.toString(), {
    headers: {
      apikey: SUPABASE_ANON_KEY,
      Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
    },
  });

  if (!res.ok) {
    return new Response(JSON.stringify({ error: "Failed to fetch notes" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }

  return new Response(await res.text(), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "s-maxage=120, stale-while-revalidate=600",
    },
  });
};
