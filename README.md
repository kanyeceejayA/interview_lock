# Interview Lock

A zero-install lockdown wrapper for the legacy UBOS HR interview app
(`https://www.ubos.org/uboshr/public/`), which we are not allowed to modify.

It's a **Cloudflare Worker reverse proxy**: it serves the real UBOS app under your
own domain so the page becomes *same-origin*, which lets us inject anti-cheat
JavaScript the server never has to know about. Candidates just **scan a QR code** —
nothing to install.

## What it does

- ✅ Serves the real login → interview flow, unchanged, under your domain
- ✅ Blocks **copy / cut / paste / right-click / text-selection** in the page
- ✅ Detects **tab / app switching** and shows an escalating warning, then a hard
  **"interview locked"** screen after `MAX_STRIKES` switches
- ✅ **Only enforces after login** — the login/signup/logout screens are untouched,
  so password managers and "save password" prompts never trigger a false strike
- ✅ **Auto-resets each candidate**: a new login starts at zero, logout clears it
  (built for the "30-min paper, then the next person signs in" flow)
- ✅ **Supervisor PIN reset** right on the lock screen — unlock a stuck candidate
  without restarting the tablet
- ✅ Logs every event **per candidate email**, viewable at a protected admin page

## What it cannot do (and why you still need Screen Pinning)

A browser tab has **no power to physically stop** someone from leaving it, nor to
read/clear the OS clipboard. It can only *detect* the return and warn/record.

So pair this with **Android Screen Pinning** (built-in, free, no install):
`Settings → Security → Screen pinning → On` + "Ask for PIN before unpinning".
Open this URL, then pin the app from Recents. Now there is nowhere to switch to,
and this web layer kills in-page copy/paste + records any attempt. Together that's
the strong setup.

## Deploy (≈2 minutes)

```bash
npm install
npx wrangler login          # opens browser, log into your Cloudflare account
npm run deploy              # deploys to https://interview-lock.<you>.workers.dev
```

`wrangler deploy` prints the live URL. That URL is the candidate entry point.

### Make the QR code

```bash
npm run qr -- https://interview-lock.<you>.workers.dev/
```

Prints a QR in the terminal and saves `interview-qr.png` (800px) to print.

### Supervisor reset (on the tablet)

When a candidate is warned or hard-locked, the lock screen has a **Supervisor PIN**
box. Type the `SUPERVISOR_PIN` and press Reset — strikes go back to zero and the
candidate continues. No logout or restart needed. Set the PIN in `wrangler.toml`.

### Seeing the logs

Two ways:

- **Live tail** (ephemeral, nothing stored): `npm run tail` → events print as
  `[interview-lock] {...}`.
- **Persistent per-candidate dashboard** (recommended): set up D1 (below), then open
  `https://<your-worker-url>/__lock/admin?key=<ADMIN_KEY>`. Shows a table of
  email → max strikes → tab switches → paste blocks → last activity, plus a recent
  events feed.

### Enable the persistent log (D1, free)

```bash
npx wrangler d1 create interview-lock-log          # prints a database_id
# paste that id into wrangler.toml and uncomment the [[d1_databases]] block
npx wrangler d1 execute interview-lock-log --remote --file schema.sql
npm run deploy
```

Without this the proxy still works — events just aren't stored (tail only).

## Configure (`wrangler.toml`)

| Var | What | Change before deploy? |
|-----|------|-----------------------|
| `MAX_STRIKES` | Switches allowed before the hard lock (default `10`) | optional |
| `SUPERVISOR_PIN` | PIN the supervisor types to reset a candidate | **yes** |
| `ADMIN_KEY` | Secret in the `/__lock/admin?key=` URL | **yes** |

## Local test

```bash
npm run dev --remote    # runs on Cloudflare's edge, full proxy works
```

> ⚠️ **Plain `npm run dev` (local mode) returns 502 for this site — that is expected
> and not a bug.** ubos.org serves an incomplete TLS certificate chain (it omits its
> intermediate cert). Browsers, curl, and Cloudflare's production edge complete the
> chain automatically (AIA fetching); the local `workerd` sandbox does not, so it
> can't verify the upstream cert. Use `--remote` (or just `npm run deploy`) to test —
> both run on the real edge where it works.

## How it works (for maintainers)

The app's internal links are all absolute paths (`/uboshr/public/...`), so the
Worker proxies **every** path 1:1 to `www.ubos.org` and they resolve back to us
automatically — almost no URL rewriting needed. The Worker:

1. forwards the request (method, headers, body, cookies) to `www.ubos.org`
2. strips `X-Frame-Options` / `Content-Security-Policy` from the response
3. rewrites any absolute `https://www.ubos.org` URLs + redirect `Location` to our origin
4. re-binds `Set-Cookie` to our host (PHP session works through the proxy)
5. injects the guard `<style>`+`<script>` before `</body>` on HTML responses

See [src/worker.js](src/worker.js).
