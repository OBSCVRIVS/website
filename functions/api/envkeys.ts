export const onRequestGet: PagesFunction = async (ctx) => {
  return new Response(JSON.stringify({ keys: Object.keys(ctx.env || {}) }), {
    headers: { "Content-Type": "application/json" },
  });
};
