/**
 * Interview Lock — transparent reverse proxy for the UBOS HR app.
 *
 * Serves https://www.ubos.org/uboshr/public/ under your own (Cloudflare) origin so
 * the page becomes same-origin. That lets us inject anti-cheat JS that the server
 * itself never has to know about (we can't touch its PHP source):
 *   - blocks copy / cut / paste / right-click / text-selection in the page
 *   - detects tab / app switching and shows an escalating warning, then a hard
 *     "blocked" screen after MAX_STRIKES.
 *
 * Enforcement only turns on AFTER the candidate logs in, and resets on logout /
 * next login — so the login screen (password managers, "save password" prompts)
 * is never affected, and each new candidate starts at zero.
 *
 * Events are logged to D1 (if bound) and viewable at /__lock/admin?key=ADMIN_KEY.
 *
 * All of the app's internal links are absolute paths (/uboshr/public/...), so by
 * proxying *every* path 1:1 to www.ubos.org they resolve back to us automatically.
 */

const UPSTREAM = "https://www.ubos.org";
const ENTRY = "/uboshr/public/";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = url.origin;
    const maxStrikes = parseInt(env.MAX_STRIKES || "10", 10);

    // ---- Integrity event log (POSTed by the injected guard) -------------------
    if (url.pathname === "/__lock/event" && request.method === "POST") {
      let data = {};
      try {
        data = await request.json();
      } catch (_) {}
      const ip = request.headers.get("cf-connecting-ip") || "";
      console.log("[interview-lock]", ip, JSON.stringify(data));
      if (env.DB) {
        try {
          await env.DB.prepare(
            "INSERT INTO events (ts, email, type, strikes, path, ip) VALUES (?, ?, ?, ?, ?, ?)"
          )
            .bind(
              Date.now(),
              String(data.email || "(unknown)").slice(0, 200),
              String(data.type || "?").slice(0, 40),
              parseInt(data.strikes, 10) || 0,
              String(data.url || "").slice(0, 300),
              ip.slice(0, 64)
            )
            .run();
        } catch (e) {
          console.log("[interview-lock] D1 insert failed:", e && e.message);
        }
      }
      return new Response("ok", { status: 200 });
    }

    // ---- Admin dashboard ------------------------------------------------------
    if (url.pathname === "/__lock/admin") {
      return renderAdmin(url, env);
    }

    // Send the bare root to the app entry point.
    if (url.pathname === "/" || url.pathname === "") {
      return Response.redirect(origin + ENTRY, 302);
    }

    // ---- Build the upstream request -------------------------------------------
    const upstreamUrl = UPSTREAM + url.pathname + url.search;

    // Forward only a safe, explicit set of headers. Cloning the whole inbound
    // Headers object (and overriding Host) makes the runtime reject the subrequest.
    const reqHeaders = new Headers();
    const passthrough = [
      "cookie",
      "user-agent",
      "accept",
      "accept-language",
      "content-type",
      "cache-control",
    ];
    for (const h of passthrough) {
      const v = request.headers.get(h);
      if (v) reqHeaders.set(h, v);
    }
    // NB: do NOT set Accept-Encoding — workerd manages compression itself and
    // rejects the subrequest if you try. It auto-decompresses for resp.text().
    const ref = request.headers.get("referer");
    if (ref) reqHeaders.set("referer", ref.replace(origin, UPSTREAM));
    reqHeaders.set("origin", UPSTREAM);

    const method = request.method;
    const init = {
      method,
      headers: reqHeaders,
      body: method === "GET" || method === "HEAD" ? undefined : request.body,
      redirect: "manual",
    };

    let resp;
    try {
      resp = await fetch(upstreamUrl, init);
    } catch (err) {
      console.log("[interview-lock] upstream fetch failed:", err && (err.stack || err));
      return new Response(
        "<h2>The interview site is temporarily unreachable.</h2><p>Please notify your supervisor.</p>",
        { status: 502, headers: { "content-type": "text/html; charset=utf-8" } }
      );
    }

    // ---- Rewrite the response -------------------------------------------------
    const respHeaders = new Headers(resp.headers);
    respHeaders.delete("X-Frame-Options");
    respHeaders.delete("Content-Security-Policy");
    respHeaders.delete("Content-Security-Policy-Report-Only");
    respHeaders.delete("Content-Encoding");
    respHeaders.delete("Content-Length");

    // Keep redirects on our origin.
    if (respHeaders.has("location")) {
      respHeaders.set("location", rewriteUrls(respHeaders.get("location"), origin));
    }

    // Re-bind cookies to our host (strip any explicit Domain attribute).
    const setCookies =
      typeof respHeaders.getSetCookie === "function" ? respHeaders.getSetCookie() : [];
    if (setCookies.length) {
      respHeaders.delete("set-cookie");
      for (const c of setCookies) {
        respHeaders.append("set-cookie", c.replace(/;\s*Domain=[^;]+/gi, ""));
      }
    }

    const ct = (respHeaders.get("content-type") || "").toLowerCase();
    const isHtml = ct.includes("text/html");
    const isText =
      isHtml ||
      ct.includes("javascript") ||
      ct.includes("text/css") ||
      ct.includes("application/json");

    if (!isText) {
      return new Response(resp.body, {
        status: resp.status,
        statusText: resp.statusText,
        headers: respHeaders,
      });
    }

    let body = await resp.text();
    body = rewriteUrls(body, origin);
    if (isHtml) {
      const p = url.pathname.toLowerCase();
      const isLogout = /logout|signout/.test(p);
      const isAuthPage =
        isLogout ||
        p === ENTRY.toLowerCase() ||
        /\/users\/login|\/login\b|\/signup|\/auth\//.test(p);
      // Pages where we DON'T count switches (e.g. the pre-interview waiting room
      // candidates sit on for a while). Strikes are preserved, not reset.
      const exemptPaths = (env.EXEMPT_PATHS || "/interview/audience")
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      const isExempt = exemptPaths.some((s) => p.includes(s));
      // Geofence: on exempt pages (the pre-interview waiting room) warn if the
      // candidate's IP isn't one of the approved on-site addresses. Empty list
      // = no geofencing (never breaks if the var is unset).
      const clientIp = request.headers.get("cf-connecting-ip") || "";
      const allowedIps = (env.ALLOWED_IPS || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const ipAllowed = allowedIps.length === 0 || allowedIps.includes(clientIp);
      const ipWarn = isExempt && !ipAllowed;
      // Results / completion pages: log when a candidate reaches them (= finished).
      const resultsPaths = (env.RESULTS_PATHS || "/interview/audience/results")
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      const isResults = resultsPaths.some((s) => p.includes(s));
      body = injectGuard(body, {
        maxStrikes,
        isAuthPage,
        isLogout,
        isExempt,
        isResults,
        ipWarn,
        clientIp,
        supervisorPin: env.SUPERVISOR_PIN || "",
      });
    }

    return new Response(body, {
      status: resp.status,
      statusText: resp.statusText,
      headers: respHeaders,
    });
  },
};

function rewriteUrls(text, origin) {
  return text.replace(/https?:\/\/www\.ubos\.org/gi, origin);
}

function injectGuard(html, opts) {
  const snippet = GUARD.replace("__MAX_STRIKES__", String(opts.maxStrikes))
    .replace("__AUTH_PAGE__", opts.isAuthPage ? "true" : "false")
    .replace("__IS_LOGOUT__", opts.isLogout ? "true" : "false")
    .replace("__EXEMPT__", opts.isExempt ? "true" : "false")
    .replace("__IS_RESULTS__", opts.isResults ? "true" : "false")
    .replace("__IP_WARN__", opts.ipWarn ? "true" : "false")
    .replace("__CLIENT_IP__", JSON.stringify(opts.clientIp || ""))
    .replace("__SUPERVISOR_PIN__", JSON.stringify(opts.supervisorPin || ""));
  if (html.includes("</body>")) return html.replace("</body>", snippet + "</body>");
  if (html.includes("</html>")) return html.replace("</html>", snippet + "</html>");
  return html + snippet;
}

async function renderAdmin(url, env) {
  const key = url.searchParams.get("key") || "";
  if (!env.ADMIN_KEY || key !== env.ADMIN_KEY) {
    return new Response("Forbidden", { status: 403 });
  }
  if (!env.DB) {
    return html("<h2>No database bound</h2><p>Set up the D1 binding to log events.</p>");
  }
  let events = [];
  try {
    const r = await env.DB.prepare(
      "SELECT ts, email, type, strikes, path, ip FROM events ORDER BY ts DESC LIMIT 5000"
    ).all();
    events = r.results || [];
  } catch (e) {
    return html(`<h2>Query error</h2><pre>${esc(e && e.message)}</pre>
      <p>Did you create the table? See README → D1 setup.</p>`);
  }
  const payload = JSON.stringify(events).replace(/</g, "\\u003c");
  return new Response(adminDoc(payload), {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function adminDoc(payload) {
  return `<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Interview Lock — dashboard</title>
<style>
:root{--side:#111827;--accent:#2563eb;--line:#e5e7eb;--mut:#6b7280}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#1f2937;background:#f3f4f6}
.app{display:flex;min-height:100vh}
.side{width:230px;flex:0 0 230px;background:var(--side);color:#e5e7eb;padding:20px 0}
.brand{padding:0 20px 16px;border-bottom:1px solid #1f2937}
.brand b{font-size:16px}.brand span{display:block;font-size:12px;color:#9ca3af;margin-top:2px}
.nav{margin-top:14px}
.nav button{display:flex;justify-content:space-between;align-items:center;width:100%;background:none;border:0;color:#cbd5e1;text-align:left;padding:11px 20px;font-size:14px;cursor:pointer}
.nav button:hover{background:#1f2937;color:#fff}
.nav button.active{background:var(--accent);color:#fff}
.nav .badge{background:rgba(255,255,255,.18);border-radius:10px;padding:1px 8px;font-size:12px}
.main{flex:1;min-width:0;padding:24px 28px}
.head{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
.head h1{font-size:20px;margin:0}
.actions button{border:1px solid var(--line);background:#fff;border-radius:8px;padding:8px 14px;cursor:pointer;font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:22px}
.tile{background:#fff;border:1px solid var(--line);border-left:4px solid #cbd5e1;border-radius:12px;padding:16px 18px}
.tile .n{font-size:26px;font-weight:700}
.tile .l{font-size:12px;color:var(--mut);margin-top:4px;text-transform:uppercase;letter-spacing:.04em}
.tile.cand{border-left-color:#2563eb}.tile.cand .n{color:#2563eb}
.tile.done{border-left-color:#16a34a}.tile.done .n{color:#16a34a}
.tile.sw{border-left-color:#d97706}.tile.sw .n{color:#d97706}
.tile.paste{border-left-color:#ea580c}.tile.paste .n{color:#ea580c}
.tile.off{border-left-color:#7c3aed}.tile.off .n{color:#7c3aed}
.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:12px}
.toolbar input{border:1px solid var(--line);border-radius:8px;padding:9px 12px;font-size:14px;flex:1;max-width:340px}
.toolbar .count{color:var(--mut);font-size:13px;margin-left:auto}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.chip{border:1px solid var(--line);background:#fff;border-radius:20px;padding:5px 12px;font-size:13px;cursor:pointer;display:inline-flex;gap:7px;align-items:center}
.chip:hover{background:#f8fafc}
.chip.active{background:#111827;color:#fff;border-color:#111827}
.chip .c{opacity:.65;font-size:12px}
.pill.ev{font-weight:600}
.ev-tab_switch{background:#fee2e2;color:#991b1b}
.ev-clipboard_blocked{background:#ffedd5;color:#9a3412}
.ev-offsite_warning{background:#ede9fe;color:#5b21b6}
.ev-supervisor_reset{background:#dbeafe;color:#1e40af}
.ev-results_reached{background:#dcfce7;color:#166534}
.ev-login{background:#f1f5f9;color:#475569}
.dash{color:#cbd5e1}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;overflow:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
thead th{background:#f9fafb;text-align:left;padding:11px 14px;font-size:12px;color:#374151;border-bottom:1px solid var(--line);cursor:pointer;white-space:nowrap;position:sticky;top:0}
thead th .ar{color:#9ca3af;font-size:11px}
tbody td{padding:10px 14px;border-bottom:1px solid #f1f5f9}
tbody tr:hover{background:#f8fafc}
.center{text-align:center}
.pill{display:inline-block;padding:2px 9px;border-radius:20px;font-size:12px;font-weight:600}
.pill.warn{background:#fef3c7;color:#92400e}.pill.bad{background:#fee2e2;color:#991b1b}.pill.ok{background:#dcfce7;color:#166534}
.empty{padding:40px;text-align:center;color:var(--mut)}
</style></head><body>
<div class="app">
  <aside class="side">
    <div class="brand"><b>Interview Lock</b><span>integrity dashboard</span></div>
    <nav class="nav">
      <button data-v="dashboard"><span>Dashboard</span><span class="badge" id="b-dashboard"></span></button>
      <button data-v="candidates"><span>Candidates</span><span class="badge" id="b-candidates"></span></button>
      <button data-v="completed"><span>Completed</span><span class="badge" id="b-completed"></span></button>
      <button data-v="events"><span>All events</span><span class="badge" id="b-events"></span></button>
      <button data-v="offsite"><span>Off-site warnings</span><span class="badge" id="b-offsite"></span></button>
      <button data-v="signins"><span>Sign-ins</span><span class="badge" id="b-signins"></span></button>
    </nav>
  </aside>
  <main class="main">
    <div class="head"><h1 id="title"></h1><div class="actions"><button onclick="location.reload()">&#8635; Refresh</button></div></div>
    <div class="tiles">
      <div class="tile cand"><div class="n" id="t-cand">0</div><div class="l">Candidates</div></div>
      <div class="tile done"><div class="n" id="t-done">0</div><div class="l">Completed</div></div>
      <div class="tile sw"><div class="n" id="t-sw">0</div><div class="l">Tab switches</div></div>
      <div class="tile paste"><div class="n" id="t-paste">0</div><div class="l">Paste blocks</div></div>
      <div class="tile off"><div class="n" id="t-off">0</div><div class="l">Off-site warnings</div></div>
    </div>
    <div class="toolbar">
      <input id="search" placeholder="Search...">
      <span class="count" id="count"></span>
    </div>
    <div class="chips" id="chips"></div>
    <div class="card"><table><thead id="thead"></thead><tbody id="tbody"></tbody></table></div>
  </main>
</div>
<script>
var DATA = ${payload};
var $ = function(s){return document.querySelector(s)};
function fmt(ts){ if(!ts) return ''; return new Date(ts).toISOString().replace('T',' ').slice(0,19); }
function esc(s){ s=(s==null?'':''+s); return s.replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }

var byEmail={};
DATA.forEach(function(e){
  var k=e.email||'(unknown)';
  var c=byEmail[k]||(byEmail[k]={email:k,max_strikes:0,switches:0,paste_blocks:0,offsite:0,completed:0,last_ip:'',last_ts:0});
  if((e.strikes||0)>c.max_strikes)c.max_strikes=e.strikes||0;
  if(e.type==='tab_switch')c.switches++;
  if(e.type==='clipboard_blocked'||(e.type&&e.type.indexOf('paste')>=0))c.paste_blocks++;
  if(e.type==='offsite_warning')c.offsite++;
  if(e.type==='results_reached')c.completed=1;
  if((e.ts||0)>c.last_ts)c.last_ts=e.ts||0;
  if(e.ip&&!c.last_ip)c.last_ip=e.ip;
});
var candidates=Object.keys(byEmail).map(function(k){return byEmail[k];});
var signins=DATA.filter(function(e){return e.type==='login';});
var offsite=DATA.filter(function(e){return e.type==='offsite_warning';});
var completed=DATA.filter(function(e){return e.type==='results_reached';});
var NOTABLE={tab_switch:1,clipboard_blocked:1,offsite_warning:1,supervisor_reset:1,results_reached:1};
var notable=DATA.filter(function(e){return NOTABLE[e.type];});

var LABELS={tab_switch:'Tab switch',clipboard_blocked:'Copy/paste blocked',offsite_warning:'Off-site network',supervisor_reset:'Supervisor reset',results_reached:'Reached results',login:'Sign-in'};
function label(t){ return LABELS[t]||t; }
function typePill(t){ return '<span class="pill ev ev-'+t+'">'+esc(label(t))+'</span>'; }
function donePill(v){ return v?'<span class="pill ok">&#10003; Finished</span>':'<span class="dash">&mdash;</span>'; }

function pill(v){ var cls=v>=5?'bad':(v>0?'warn':'ok'); return '<span class="pill '+cls+'">'+v+'</span>'; }

var VIEWS={
 dashboard:{title:'Notable events',rows:function(){return notable;},sort:{key:'ts',dir:-1},types:true,cols:[
   {key:'ts',label:'Time (UTC)',fmt:fmt},
   {key:'email',label:'Email'},
   {key:'type',label:'Event',fmt:typePill},
   {key:'strikes',label:'Strike#',align:'center'},
   {key:'ip',label:'IP'}]},
 candidates:{title:'Candidates',rows:function(){return candidates;},sort:{key:'last_ts',dir:-1},cols:[
   {key:'email',label:'Email'},
   {key:'completed',label:'Finished',align:'center',fmt:donePill},
   {key:'max_strikes',label:'Max strikes',align:'center',fmt:pill},
   {key:'switches',label:'Tab switches',align:'center'},
   {key:'paste_blocks',label:'Paste blocks',align:'center'},
   {key:'offsite',label:'Off-site',align:'center'},
   {key:'last_ip',label:'Last IP'},
   {key:'last_ts',label:'Last activity',fmt:fmt}]},
 completed:{title:'Completed (reached results)',rows:function(){return completed;},sort:{key:'ts',dir:-1},cols:[
   {key:'ts',label:'Time (UTC)',fmt:fmt},
   {key:'email',label:'Email'},
   {key:'strikes',label:'Strikes at finish',align:'center'},
   {key:'ip',label:'IP'}]},
 events:{title:'All events',rows:function(){return DATA;},sort:{key:'ts',dir:-1},types:true,cols:[
   {key:'ts',label:'Time (UTC)',fmt:fmt},
   {key:'email',label:'Email'},
   {key:'type',label:'Event',fmt:typePill},
   {key:'strikes',label:'Strike#',align:'center'},
   {key:'ip',label:'IP'},
   {key:'path',label:'Path'}]},
 offsite:{title:'Off-site warnings',rows:function(){return offsite;},sort:{key:'ts',dir:-1},cols:[
   {key:'ts',label:'Time (UTC)',fmt:fmt},
   {key:'email',label:'Email'},
   {key:'ip',label:'IP'},
   {key:'path',label:'Path'}]},
 signins:{title:'Sign-ins via this proxy',rows:function(){return signins;},sort:{key:'ts',dir:-1},cols:[
   {key:'ts',label:'Time (UTC)',fmt:fmt},
   {key:'email',label:'Email'},
   {key:'ip',label:'IP'}]}
};

var state={view:'candidates',sortKey:null,sortDir:-1,q:'',type:''};

function renderChips(v, all){
  var box=$('#chips');
  if(!v.types){ box.style.display='none'; box.innerHTML=''; return; }
  box.style.display='flex';
  var counts={}; all.forEach(function(r){counts[r.type]=(counts[r.type]||0)+1;});
  var ts=Object.keys(counts).sort();
  var h='<button class="chip'+(state.type===''?' active':'')+'" data-t="">All <span class="c">'+all.length+'</span></button>';
  h+=ts.map(function(t){ return '<button class="chip'+(state.type===t?' active':'')+'" data-t="'+esc(t)+'">'+typePill(t)+' <span class="c">'+counts[t]+'</span></button>'; }).join('');
  box.innerHTML=h;
  Array.prototype.forEach.call(box.querySelectorAll('.chip'),function(b){ b.onclick=function(){ state.type=b.getAttribute('data-t'); render(); }; });
}

function render(){
  var v=VIEWS[state.view];
  var all=v.rows();
  renderChips(v, all);
  var key=state.sortKey||v.sort.key, dir=state.sortDir;
  var rows=all.slice();
  if(v.types && state.type){ rows=rows.filter(function(r){return r.type===state.type;}); }
  if(state.q){ var q=state.q.toLowerCase(); rows=rows.filter(function(r){ return v.cols.some(function(c){ return (''+(r[c.key]==null?'':r[c.key])).toLowerCase().indexOf(q)>=0; }); }); }
  rows.sort(function(a,b){ var x=a[key],y=b[key]; if(typeof x==='number'||typeof y==='number'){x=+x||0;y=+y||0;} else {x=(''+(x||'')).toLowerCase();y=(''+(y||'')).toLowerCase();} return x<y?-dir:(x>y?dir:0); });
  var thead='<tr>'+v.cols.map(function(c){ var ar=(key===c.key)?(dir<0?'\\u25BC':'\\u25B2'):''; return '<th data-k="'+c.key+'" class="'+(c.align==='center'?'center':'')+'">'+esc(c.label)+' <span class="ar">'+ar+'</span></th>'; }).join('')+'</tr>';
  var body=rows.length? rows.map(function(r){ return '<tr>'+v.cols.map(function(c){ var val=r[c.key]; var disp=c.fmt?c.fmt(val):esc(val==null?'':val); return '<td class="'+(c.align==='center'?'center':'')+'">'+disp+'</td>'; }).join('')+'</tr>'; }).join('') : '<tr><td class="empty" colspan="'+v.cols.length+'">Nothing here yet</td></tr>';
  $('#title').textContent=v.title;
  $('#count').textContent=rows.length+' row'+(rows.length===1?'':'s');
  $('#thead').innerHTML=thead;
  $('#tbody').innerHTML=body;
  Array.prototype.forEach.call(document.querySelectorAll('.nav button'),function(b){ b.classList.toggle('active', b.getAttribute('data-v')===state.view); });
  Array.prototype.forEach.call(document.querySelectorAll('#thead th'),function(th){ th.onclick=function(){ var k=th.getAttribute('data-k'); var eff=state.sortKey||v.sort.key; if(k===eff){state.sortDir=-state.sortDir;}else{state.sortDir=-1;} state.sortKey=k; render(); }; });
}

function go(view){ state.view=view; state.sortKey=null; state.sortDir=VIEWS[view].sort.dir; state.q=''; state.type=''; $('#search').value=''; render(); }

Array.prototype.forEach.call(document.querySelectorAll('.nav button'),function(b){ b.onclick=function(){go(b.getAttribute('data-v'));}; });
$('#search').oninput=function(){state.q=this.value;render();};

$('#b-dashboard').textContent=notable.length;
$('#b-candidates').textContent=candidates.length;
$('#b-completed').textContent=completed.length;
$('#b-events').textContent=DATA.length;
$('#b-offsite').textContent=offsite.length;
$('#b-signins').textContent=signins.length;
$('#t-cand').textContent=candidates.length;
$('#t-done').textContent=completed.length;
$('#t-sw').textContent=candidates.reduce(function(s,c){return s+c.switches;},0);
$('#t-paste').textContent=candidates.reduce(function(s,c){return s+c.paste_blocks;},0);
$('#t-off').textContent=offsite.length;
go('dashboard');
</script></body></html>`;
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])
  );
}

function html(inner) {
  return new Response(
    `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
     <style>body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:24px;color:#222}
     h1{font-size:22px}h2{font-size:16px;margin-top:28px}
     table{border-collapse:collapse;width:100%;font-size:14px;margin-top:8px}
     th,td{border:1px solid #ddd;padding:6px 10px;text-align:left}
     th{background:#f4f4f4}tr:nth-child(even){background:#fafafa}</style>${inner}`,
    { headers: { "content-type": "text/html; charset=utf-8" } }
  );
}

const GUARD = `
<style id="lock-style">
  body.lock-on *:not(input):not(textarea):not([contenteditable="true"]) {
    -webkit-user-select: none !important;
    -ms-user-select: none !important;
    user-select: none !important;
    -webkit-touch-callout: none !important;
  }
  body.lock-on input, body.lock-on textarea, body.lock-on [contenteditable="true"] {
    -webkit-user-select: text !important;
    user-select: text !important;
  }
  #lock-overlay {
    position: fixed; inset: 0; z-index: 2147483647;
    display: none; align-items: center; justify-content: center;
    background: rgba(120,0,0,0.97); color: #fff;
    font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
    text-align: center; padding: 24px;
  }
  #lock-overlay .box { max-width: 560px; }
  #lock-overlay h1 { font-size: 28px; margin: 0 0 12px; }
  #lock-overlay p { font-size: 17px; line-height: 1.5; margin: 0 0 18px; opacity: .95; }
  #lock-overlay button {
    font-size: 16px; padding: 12px 28px; border: 0; border-radius: 8px;
    background: #fff; color: #900; font-weight: 700; cursor: pointer;
  }
  #lock-overlay.hard #lock-ack { display: none; }
  #lock-overlay .count { font-size: 14px; opacity: .85; }
  #lock-sup { margin-top: 26px; font-size: 13px; opacity: .9; }
  #lock-sup input {
    font-size: 15px; padding: 8px 10px; border: 0; border-radius: 6px;
    width: 150px; text-align: center;
  }
  #lock-sup button {
    font-size: 14px; padding: 9px 16px; background: rgba(255,255,255,.25);
    color: #fff; border: 1px solid rgba(255,255,255,.6);
  }
  #lock-sup-msg { display: block; margin-top: 8px; min-height: 16px; }
  #lock-ipwarn {
    position: fixed; inset: 0; z-index: 2147483646;
    display: none; align-items: center; justify-content: center;
    background: rgba(150,90,0,0.97); color: #fff;
    font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
    text-align: center; padding: 24px;
  }
  #lock-ipwarn .box { max-width: 560px; }
  #lock-ipwarn h1 { font-size: 26px; margin: 0 0 12px; }
  #lock-ipwarn p { font-size: 17px; line-height: 1.5; margin: 0 0 18px; }
  #lock-ipwarn button {
    font-size: 16px; padding: 12px 28px; border: 0; border-radius: 8px;
    background: #fff; color: #a35a00; font-weight: 700; cursor: pointer;
  }
  #lock-ipwarn .ip { font-size: 13px; opacity: .85; margin-top: 14px; }
</style>
<div id="lock-ipwarn" role="alertdialog" aria-live="assertive">
  <div class="box">
    <h1>⚠ Off-site network detected</h1>
    <p>You appear to be outside the conference hall.
       <strong>Any interview taken outside the conference hall will not be
       counted.</strong> This has been recorded — if this is a mistake,
       notify your supervisor.</p>
    <button id="lock-ipwarn-ok" type="button">I understand</button>
    <p class="ip">Your network address: <span id="lock-ipwarn-ip"></span></p>
  </div>
</div>
<div id="lock-overlay" role="alertdialog" aria-live="assertive">
  <div class="box">
    <h1 id="lock-title">⚠ Stay on this screen</h1>
    <p id="lock-msg"></p>
    <button id="lock-ack" type="button">I understand — continue</button>
    <p class="count" id="lock-count"></p>
    <div id="lock-sup">
      <label>Supervisor:
        <input id="lock-sup-pin" type="password" inputmode="numeric" placeholder="PIN" autocomplete="off">
      </label>
      <button id="lock-sup-btn" type="button">Reset</button>
      <span id="lock-sup-msg"></span>
    </div>
  </div>
</div>
<script>
(function () {
  if (window.__lockInstalled) return;
  window.__lockInstalled = true;

  var MAX = __MAX_STRIKES__;
  var AUTH_PAGE = __AUTH_PAGE__;   // login / signup / logout screen
  var IS_LOGOUT = __IS_LOGOUT__;
  var EXEMPT = __EXEMPT__;         // waiting room etc. — don't count switches
  var IS_RESULTS = __IS_RESULTS__; // results/completion page
  var IP_WARN = __IP_WARN__;       // candidate is off the approved network
  var CLIENT_IP = __CLIENT_IP__;
  var SUP_PIN = __SUPERVISOR_PIN__;
  var SK = "lock_strikes", AK = "lock_authed", EK = "lock_email", RK = "lock_results_done";
  var ss = window.sessionStorage;

  function beacon(obj) {
    try {
      navigator.sendBeacon(
        "/__lock/event",
        new Blob([JSON.stringify(obj)], { type: "application/json" })
      );
    } catch (e) {}
  }

  // ---- off-network warning (shows even on exempt pages like the waiting room) -
  if (IP_WARN) {
    var ipo = document.getElementById("lock-ipwarn");
    if (ipo) {
      document.getElementById("lock-ipwarn-ip").textContent = CLIENT_IP || "unknown";
      ipo.style.display = "flex";
      var ipok = document.getElementById("lock-ipwarn-ok");
      if (ipok) ipok.addEventListener("click", function () { ipo.style.display = "none"; });
      beacon({ type: "offsite_warning", email: ss.getItem(EK) || "(unknown)", strikes: 0, t: Date.now(), url: location.pathname });
    }
  }

  // ---- completion tracking (results page) -----------------------------------
  // Log once per session when an authenticated candidate reaches the results
  // page — that's our signal they finished. Runs even though results is exempt.
  if (IS_RESULTS && ss.getItem(AK) === "1" && !ss.getItem(RK)) {
    ss.setItem(RK, "1");
    beacon({ type: "results_reached", email: ss.getItem(EK) || "(unknown)", strikes: parseInt(ss.getItem(SK) || "0", 10), t: Date.now(), url: location.pathname });
  }

  // ---- session lifecycle ----------------------------------------------------
  if (IS_LOGOUT) { ss.removeItem(AK); ss.removeItem(EK); ss.removeItem(SK); ss.removeItem(RK); }

  if (AUTH_PAGE) {
    // Fresh start whenever we're on a login/signup screen.
    ss.setItem(SK, "0");
    // Capture the candidate's email + arm enforcement when they submit login.
    document.addEventListener("submit", function (e) {
      var form = e.target;
      if (!form || !form.querySelector) return;
      if (!form.querySelector('input[type="password"]')) return; // only the login form
      var emailEl =
        form.querySelector('input[name="email"]') ||
        form.querySelector('input[type="email"]') ||
        form.querySelector('input[type="text"]');
      var em = emailEl && emailEl.value ? emailEl.value.trim() : "";
      if (em) ss.setItem(EK, em);
      ss.setItem(AK, "1");
      ss.setItem(SK, "0");
      ss.removeItem(RK);
      // Record the sign-in so we can cross-check who came through the proxy.
      beacon({ type: "login", email: em || "(unknown)", strikes: 0, t: Date.now(), url: location.pathname });
    }, true);
    return; // no copy/paste blocking or switch detection on the login screen
  }

  // Exempt pages (e.g. the pre-interview waiting room): pause enforcement but
  // KEEP the current strike count so it carries into the interview itself.
  if (EXEMPT) return;

  // Past here = a normal (post-login) page. Only enforce if authenticated.
  if (ss.getItem(AK) !== "1") return;

  document.body.classList.add("lock-on");
  var strikes = parseInt(ss.getItem(SK) || "0", 10);
  var email = ss.getItem(EK) || "(unknown)";
  var leftAt = 0;

  var overlay = document.getElementById("lock-overlay");
  var title = document.getElementById("lock-title");
  var msg = document.getElementById("lock-msg");
  var ack = document.getElementById("lock-ack");
  var countEl = document.getElementById("lock-count");

  function log(type) {
    beacon({ type: type, strikes: strikes, email: email, t: Date.now(), url: location.pathname });
  }

  // ---- copy / paste / context-menu blocking --------------------------------
  ["copy", "cut", "paste", "contextmenu", "dragstart", "selectstart"].forEach(function (ev) {
    document.addEventListener(ev, function (e) {
      var t = e.target;
      var editable = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable);
      if ((ev === "selectstart" || ev === "contextmenu") && editable) return;
      e.preventDefault();
      e.stopPropagation();
      if (ev === "copy" || ev === "cut" || ev === "paste") log("clipboard_blocked");
      return false;
    }, true);
  });

  document.addEventListener("keydown", function (e) {
    var k = (e.key || "").toLowerCase();
    if ((e.ctrlKey || e.metaKey) && ["c", "x", "v", "a", "p", "s", "u"].indexOf(k) !== -1) {
      if (k === "v") log("clipboard_blocked");
      e.preventDefault();
      e.stopPropagation();
      return false;
    }
    if (k === "f12") { e.preventDefault(); return false; }
  }, true);

  // ---- tab / app switch detection ------------------------------------------
  // Use ONLY visibilitychange (document.hidden). Unlike blur/focus, it does NOT
  // fire for in-page browser UI — autofill dropdowns, "save password?" prompts,
  // the soft keyboard, or address-bar focus — which were causing false strikes.
  function showWarning() {
    var remaining = Math.max(0, MAX - strikes);
    if (strikes >= MAX) {
      overlay.classList.add("hard");
      title.textContent = "⛔ Interview locked";
      msg.innerHTML =
        "You left the interview screen too many times. This attempt has been flagged and locked. " +
        "Please contact your interview supervisor.";
      countEl.textContent = "Switches recorded: " + strikes;
    } else {
      title.textContent = "⚠ You left the interview screen";
      msg.innerHTML =
        "Switching tabs or apps during the interview is not allowed and is being recorded. " +
        "<strong>If this happens " + remaining + " more time" + (remaining === 1 ? "" : "s") +
        ", your interview will be blocked.</strong>";
      countEl.textContent = "Warning " + strikes + " of " + MAX;
    }
    overlay.style.display = "flex";
  }

  function registerSwitch() {
    strikes++;
    ss.setItem(SK, String(strikes));
    log("tab_switch");
    showWarning();
  }

  ack.addEventListener("click", function () {
    if (strikes < MAX) overlay.style.display = "none";
  });

  // ---- supervisor reset ----------------------------------------------------
  // Lets the on-site supervisor clear a candidate's strikes (incl. the hard
  // lock) by typing the PIN, without logging out or restarting the tablet.
  var supBtn = document.getElementById("lock-sup-btn");
  var supPin = document.getElementById("lock-sup-pin");
  var supMsg = document.getElementById("lock-sup-msg");
  function doSupReset() {
    if (!SUP_PIN) { supMsg.textContent = "No PIN configured."; return; }
    if (supPin.value === SUP_PIN) {
      strikes = 0;
      ss.setItem(SK, "0");
      overlay.classList.remove("hard");
      overlay.style.display = "none";
      supPin.value = "";
      supMsg.textContent = "";
      log("supervisor_reset");
    } else {
      supMsg.textContent = "Wrong PIN.";
      supPin.value = "";
    }
  }
  supBtn.addEventListener("click", doSupReset);
  supPin.addEventListener("keydown", function (e) {
    if ((e.key || "").toLowerCase() === "enter") { e.preventDefault(); doSupReset(); }
  });

  document.addEventListener("visibilitychange", function () {
    if (document.hidden) {
      leftAt = Date.now();
    } else if (leftAt) {
      var away = Date.now() - leftAt;
      leftAt = 0;
      if (away >= 350) registerSwitch(); // debounce transient hides
    }
  });

  // If they already hit the cap earlier this session, keep it locked.
  if (strikes >= MAX) showWarning();
})();
</script>
`;
