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
      console.log("[interview-lock]", JSON.stringify(data));
      if (env.DB) {
        try {
          await env.DB.prepare(
            "INSERT INTO events (ts, email, type, strikes, path) VALUES (?, ?, ?, ?, ?)"
          )
            .bind(
              Date.now(),
              String(data.email || "(unknown)").slice(0, 200),
              String(data.type || "?").slice(0, 40),
              parseInt(data.strikes, 10) || 0,
              String(data.url || "").slice(0, 300)
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
      body = injectGuard(body, {
        maxStrikes,
        isAuthPage,
        isLogout,
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
  try {
    const summary = await env.DB.prepare(
      `SELECT email,
              MAX(strikes) AS max_strikes,
              SUM(CASE WHEN type='tab_switch' THEN 1 ELSE 0 END) AS switches,
              SUM(CASE WHEN type LIKE '%paste%' OR type='clipboard_blocked' THEN 1 ELSE 0 END) AS paste_blocks,
              MAX(ts) AS last_ts
       FROM events GROUP BY email ORDER BY last_ts DESC LIMIT 500`
    ).all();
    const recent = await env.DB.prepare(
      `SELECT ts, email, type, strikes, path FROM events ORDER BY ts DESC LIMIT 200`
    ).all();

    const rows = (summary.results || [])
      .map(
        (r) =>
          `<tr><td>${esc(r.email)}</td><td style="text-align:center">${r.max_strikes}</td>` +
          `<td style="text-align:center">${r.switches}</td>` +
          `<td style="text-align:center">${r.paste_blocks}</td>` +
          `<td>${new Date(r.last_ts).toISOString().replace("T", " ").slice(0, 19)} UTC</td></tr>`
      )
      .join("");
    const recentRows = (recent.results || [])
      .map(
        (r) =>
          `<tr><td>${new Date(r.ts).toISOString().replace("T", " ").slice(0, 19)}</td>` +
          `<td>${esc(r.email)}</td><td>${esc(r.type)}</td>` +
          `<td style="text-align:center">${r.strikes}</td><td>${esc(r.path)}</td></tr>`
      )
      .join("");

    return html(`
      <h1>Interview Lock — integrity log</h1>
      <h2>Per candidate</h2>
      <table><thead><tr><th>Email</th><th>Max strikes</th><th>Tab switches</th>
        <th>Paste blocks</th><th>Last activity</th></tr></thead><tbody>${rows || "<tr><td colspan=5>No data yet</td></tr>"}</tbody></table>
      <h2>Recent events (latest 200)</h2>
      <table><thead><tr><th>Time (UTC)</th><th>Email</th><th>Event</th><th>Strike#</th><th>Path</th></tr></thead>
        <tbody>${recentRows || "<tr><td colspan=5>No data yet</td></tr>"}</tbody></table>
    `);
  } catch (e) {
    return html(`<h2>Query error</h2><pre>${esc(e && e.message)}</pre>
      <p>Did you create the table? See README → D1 setup.</p>`);
  }
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
</style>
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
  var SUP_PIN = __SUPERVISOR_PIN__;
  var SK = "lock_strikes", AK = "lock_authed", EK = "lock_email";
  var ss = window.sessionStorage;

  // ---- session lifecycle ----------------------------------------------------
  if (IS_LOGOUT) { ss.removeItem(AK); ss.removeItem(EK); ss.removeItem(SK); }

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
      if (emailEl && emailEl.value) ss.setItem(EK, emailEl.value.trim());
      ss.setItem(AK, "1");
      ss.setItem(SK, "0");
    }, true);
    return; // no copy/paste blocking or switch detection on the login screen
  }

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
    try {
      navigator.sendBeacon(
        "/__lock/event",
        new Blob(
          [JSON.stringify({ type: type, strikes: strikes, email: email, t: Date.now(), url: location.pathname })],
          { type: "application/json" }
        )
      );
    } catch (e) {}
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
