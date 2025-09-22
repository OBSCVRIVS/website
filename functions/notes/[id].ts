export const onRequestGet: PagesFunction = async (ctx) => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SITE_ORIGIN } = ctx.env as any;
  const id = ctx.params.id as string;

  // fetch one note
  const url = new URL(`${SUPABASE_URL}/rest/v1/notes`);
  url.searchParams.set("select", "id,body,created_at,likes");
  url.searchParams.set("id", `eq.${id}`);
  const r = await fetch(url.toString(), {
    headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SUPABASE_ANON_KEY}` },
  });
  const rows = await r.json().catch(() => []);
  const note = rows[0];
  if (!note) return new Response("Not found", { status: 404 });

  const esc = (s:string)=>s.replace(/[&<>"']/g,c=>({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;" }[c]!));
  const title = (note.body || "").slice(0, 70);
  const desc = note.body.length > 160 ? note.body.slice(0, 157) + "…" : note.body;
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
  <article class="tweet expanded" id="${esc(note.id)}">
    <div class="tweet__avatar"><img src="${SITE_ORIGIN}/assets/img/avatar_anime_blue_hour.png" alt="" aria-hidden="true"></div>
    <div class="tweet__body">
      <header class="tweet__head">
        <span class="name">Levi Carver</span>
        <span class="dot" aria-hidden="true">·</span>
        <time datetime="${esc(note.created_at)}">${new Date(note.created_at).toLocaleString()}</time>
      </header>
      <div class="tweet__text">${esc(note.body).replace(/\n/g,"<br>")}</div>
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
