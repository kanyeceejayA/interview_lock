/**
 * Interview Lock — transparent reverse proxy for the UBOS HR app.
 *
 * Serves https://www.ubos.org/uboshr/public/ under your own (Cloudflare) origin so
 * the page becomes same-origin. That lets us inject anti-cheat JS that the server
 * itself never has to know about (we can't touch its PHP source):
 *   - blocks copy / cut / paste / right-click / text-selection in the page
 *   - detects tab / app switching (focus loss) and shows an escalating warning,
 *     then a hard "blocked" screen after MAX_STRIKES, and logs each event.
 *
 * All of the app's internal links are absolute paths (/uboshr/public/...), so by
 * proxying *every* path 1:1 to www.ubos.org they resolve back to us automatically.
 */

const UPSTREAM = "https://www.ubos.org";
const UPSTREAM_HOST = "www.ubos.org";
const ENTRY = "/uboshr/public/";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = url.origin;
    const maxStrikes = parseInt(env.MAX_STRIKES || "3", 10);

    // Lightweight logging beacon for switch events (visible via `wrangler tail`).
    if (url.pathname === "/__lock/event" && request.method === "POST") {
      try {
        const data = await request.json();
        console.log("[interview-lock]", JSON.stringify(data));
      } catch (_) {}
      return new Response("ok", { status: 200 });
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
      respHeaders.set(
        "location",
        rewriteUrls(respHeaders.get("location"), origin)
      );
    }

    // Re-bind cookies to our host (strip any explicit Domain attribute).
    const setCookies =
      typeof respHeaders.getSetCookie === "function"
        ? respHeaders.getSetCookie()
        : [];
    if (setCookies.length) {
      respHeaders.delete("set-cookie");
      for (const c of setCookies) {
        respHeaders.append(
          "set-cookie",
          c.replace(/;\s*Domain=[^;]+/gi, "")
        );
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
    if (isHtml) body = injectGuard(body, maxStrikes);

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

function injectGuard(html, maxStrikes) {
  const snippet = GUARD.replace("__MAX_STRIKES__", String(maxStrikes));
  if (html.includes("</body>")) return html.replace("</body>", snippet + "</body>");
  if (html.includes("</html>")) return html.replace("</html>", snippet + "</html>");
  return html + snippet;
}

const GUARD = `
<style id="lock-style">
  *:not(input):not(textarea):not([contenteditable="true"]) {
    -webkit-user-select: none !important;
    -ms-user-select: none !important;
    user-select: none !important;
    -webkit-touch-callout: none !important;
  }
  input, textarea, [contenteditable="true"] {
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
  #lock-overlay.hard button { display: none; }
  #lock-overlay .count { font-size: 14px; opacity: .85; }
</style>
<div id="lock-overlay" role="alertdialog" aria-live="assertive">
  <div class="box">
    <h1 id="lock-title">⚠ Stay on this screen</h1>
    <p id="lock-msg"></p>
    <button id="lock-ack" type="button">I understand — continue</button>
    <p class="count" id="lock-count"></p>
  </div>
</div>
<script>
(function () {
  if (window.__lockInstalled) return;
  window.__lockInstalled = true;

  var MAX = __MAX_STRIKES__;
  var KEY = "lock_strikes";
  var strikes = parseInt(sessionStorage.getItem(KEY) || "0", 10);
  var leftAt = 0;

  var overlay = document.getElementById("lock-overlay");
  var title = document.getElementById("lock-title");
  var msg = document.getElementById("lock-msg");
  var ack = document.getElementById("lock-ack");
  var countEl = document.getElementById("lock-count");

  function log(type, extra) {
    try {
      navigator.sendBeacon(
        "/__lock/event",
        new Blob(
          [JSON.stringify(Object.assign({ type: type, strikes: strikes, t: Date.now(), url: location.pathname }, extra || {}))],
          { type: "application/json" }
        )
      );
    } catch (e) {}
  }

  // ---- copy / paste / context-menu blocking --------------------------------
  ["copy", "cut", "paste", "contextmenu", "dragstart", "selectstart"].forEach(function (ev) {
    document.addEventListener(ev, function (e) {
      var t = e.target;
      // allow selection/typing inside fields, but never allow paste
      var editable = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable);
      if ((ev === "selectstart" || ev === "contextmenu") && editable) return;
      e.preventDefault();
      e.stopPropagation();
      if (ev === "copy" || ev === "cut" || ev === "paste") log("clipboard_blocked", { action: ev });
      return false;
    }, true);
  });

  document.addEventListener("keydown", function (e) {
    var k = (e.key || "").toLowerCase();
    if ((e.ctrlKey || e.metaKey) && ["c", "x", "v", "a", "p", "s", "u"].indexOf(k) !== -1) {
      // allow select-all/copy is fine to block; typing still works
      if (k === "v") log("paste_key_blocked");
      e.preventDefault();
      e.stopPropagation();
      return false;
    }
    if (k === "f12") { e.preventDefault(); return false; }
  }, true);

  // ---- tab / app switch detection ------------------------------------------
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
    sessionStorage.setItem(KEY, String(strikes));
    log("tab_switch");
    showWarning();
  }

  ack.addEventListener("click", function () {
    if (strikes < MAX) overlay.style.display = "none";
  });

  // Whichever of {focus, visibilitychange->visible} fires first on return counts
  // the switch and zeroes leftAt; the other then sees leftAt==0 and skips. This
  // dedupes the two events while still catching app-switches that only blur.
  function onReturn() {
    if (leftAt) {
      registerSwitch();
      leftAt = 0;
    }
  }
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) leftAt = leftAt || Date.now();
    else onReturn();
  });
  window.addEventListener("blur", function () { leftAt = leftAt || Date.now(); });
  window.addEventListener("focus", onReturn);

  // If they already hit the cap earlier in this session, keep it locked.
  if (strikes >= MAX) showWarning();
})();
</script>
`;
