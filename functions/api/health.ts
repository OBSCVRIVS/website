export const onRequestGet: PagesFunction = async () =>
  new Response(JSON.stringify({ ok: true }), {
    headers: { "Content-Type": "application/json" },
  });
