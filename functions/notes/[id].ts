// functions/notes/[id].ts

/* -------------------------------- utilities -------------------------------- */
function j(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
async function readJSON<T = any>(req: Request): Promise<T | null> {
  try {
    return await req.json();
  } catch {
    return null;
  }
}
function mustEnv(env: any, keys: string[]) {
  for (const k of keys) if (!env[k]) throw new Error(`missing_env:${k}`);
}
function b64urlToBytes(s: string) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad), c => c.charCodeAt(0));
}
function tryDecodeBody(body: string): string {
  if (typeof body !== "string") return body as any;
  const looksBase64ish = /^[A-Za-z0-9+/_=-]+$/.test(body.trim());
  if (!looksBase64ish) return body;
  try {
    // try base64url then base64
    const txtDecoder = new TextDecoder();
    try { return txtDecoder.decode(b64urlToBytes(body.trim())); } catch {}
    const bin = atob(body.trim());
    return txtDecoder.decode(Uint8Array.from(bin, c => c.charCodeAt(0)));
  } catch {
    return body;
  }
}
const esc = (s: string) =>
  s.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

/* --------------------------------- GET HTML -------------------------------- */
export const onRequestGet: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SITE_ORIGIN } = ctx.env as any;
  const id = ctx.params.id as string;

  // fetch one note
  const url = new URL(`${SUPABASE_URL}/rest/v1/notes`);
  url.searchParams.set("select", "id,body,created_at,likes,tz,hidden");
  url.searchParams.set("id", `eq.${id}`);

  const r = await fetch(url.toString(), {
    headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SUPABASE_ANON_KEY}` },
  });
  if (!r.ok) return new Response("Upstream error", { status: 502 });

  const rows = (await r.json().catch(() => [])) as any[];
  const note = rows[0];
  if (!note) return new Response("Not found", { status: 404 });

  const decoded = tryDecodeBody(String(note.body ?? ""));
  const title = decoded.slice(0, 70);
  const desc = decoded.length > 160 ? decoded.slice(0, 157) + "…" : decoded;
  const canonical = `${SITE_ORIGIN}/notes/${note.id}`;

  const html = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(desc)}">
<meta property="og:type" content="article">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:url" content="${canonical}">
<meta property="og:image" content="${SITE_ORIGIN}/assets/img/avatar_anime_blue_hour.png">
<meta name="twitter:card" content="summary">
<link rel="stylesheet" href="${SITE_ORIGIN}/styles.css">
<link rel="canonical" href="${canonical}">
</head>
<body>
<header class="banner banner--short"><img src="${SITE_ORIGIN}/assets/img/banner_blue_hour.png" alt=""></header>
<nav class="site-nav" aria-label="Site"><div class="site-nav__inner">
  <a class="brand" href="${SITE_ORIGIN}/">Levi Carver</a>
  <a class="nav-link" href="${SITE_ORIGIN}/contact.html">Contact</a>
</div></nav>

<main class="feed" aria-label="Note">
  <article class="tweet expanded" id="${esc(String(note.id))}">
    <div class="tweet__avatar"><img src="${SITE_ORIGIN}/assets/img/avatar_anime_blue_hour.png" alt="" aria-hidden="true"></div>
    <div class="tweet__body">
      <header class="tweet__head">
        <span class="name">Levi Carver</span>
        <span class="dot" aria-hidden="true">·</span>
        <time datetime="${esc(String(note.created_at))}">${new Date(note.created_at).toLocaleString()}</time>
      </header>
      <div class="tweet__text">${esc(decoded).replace(/\n/g,"<br>")}</div>
      <div class="tweet__actions">
        <a class="permalink" href="${canonical}">Permalink</a>
        <a class="permalink" href="${SITE_ORIGIN}/">Back</a>
      </div>
    </div>
  </article>
</main>

<footer class="footer" role="contentinfo">
  <small>© 2025 Levi Carver · <a href="${SITE_ORIGIN}/contact.html">Contact</a></small>
</footer>
</body></html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
};

/* ------------------------------ PATCH / update ------------------------------ */
export const onRequestPatch: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;
  try {
    mustEnv(ctx.env, ["SUPABASE_URL", "SUPABASE_ANON_KEY", "SERVICE_ROLE"]);
    const id = ctx.params.id as string;
    const body = await readJSON(ctx.request);
    if (!id) return j({ error: "missing_id" }, 400);
    if (!body || typeof body !== "object") return j({ error: "invalid_body" }, 400);

    const patch: any = {};
    if ("hidden" in (body as any)) patch.hidden = !!(body as any).hidden;

    if (Object.keys(patch).length === 0) return j({ error: "no_mutations" }, 400);

    const url = `${SUPABASE_URL}/rest/v1/notes?id=eq.${encodeURIComponent(id)}`;
    const r = await fetch(url, {
      method: "PATCH",
      headers: {
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${SERVICE_ROLE}`,
        "Content-Type": "application/json",
        Prefer: "return=representation",
      },
      body: JSON.stringify(patch),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) return j({ error: "supabase_patch_failed", status: r.status, data }, 502);
    return j({ ok: true, note: data?.[0] ?? null });
  } catch (e: any) {
    return j({ error: String(e) }, 500);
  }
};

/* ------------------------------ DELETE / remove ----------------------------- */
export const onRequestDelete: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SERVICE_ROLE } = ctx.env as any;
  try {
    mustEnv(ctx.env, ["SUPABASE_URL", "SUPABASE_ANON_KEY", "SERVICE_ROLE"]);
    const id = ctx.params.id as string;
    if (!id) return j({ error: "missing_id" }, 400);

    const url = `${SUPABASE_URL}/rest/v1/notes?id=eq.${encodeURIComponent(id)}`;
    const r = await fetch(url, {
      method: "DELETE",
      headers: {
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${SERVICE_ROLE}`,
        Prefer: "return=minimal",
      },
    });
    if (!r.ok) return j({ error: "supabase_delete_failed", status: r.status }, 502);
    return j({ ok: true });
  } catch (e: any) {
    return j({ error: String(e) }, 500);
  }
};

/* -------- POST fallback to emulate update/delete when methods are blocked ---- */
export const onRequestPost: PagesFunction = async (ctx) => {
  const payload = await readJSON(ctx.request);
  const action = payload?.action;
  if (action === "update") {
    // emulate PATCH
    const req = new Request(ctx.request.url, { method: "PATCH", headers: ctx.request.headers, body: JSON.stringify(payload) });
    // @ts-ignore re-dispatch inside module
    return onRequestPatch({ ...ctx, request: req } as any);
  }
  if (action === "delete") {
    // emulate DELETE
    const req = new Request(ctx.request.url, { method: "DELETE", headers: ctx.request.headers });
    // @ts-ignore re-dispatch inside module
    return onRequestDelete({ ...ctx, request: req } as any);
  }
  return j({ error: "unsupported_post_action" }, 400);
};
