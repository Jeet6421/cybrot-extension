# CYBROT OSINT Scanner: browser extension (Chrome and Edge)

Click the CYBROT icon on any website. The popup detects the website's domain, asks the local CYBROT Python engine to scan it, shows whether the scan is running, completed or failed, and displays the results: domain details, DNS records, subdomains and SSL/TLS information.

The same folder works in Chrome and Microsoft Edge. Both use Manifest V3 and the same `chrome.*` APIs, so no changes are needed between the two.

## Files

| File | Purpose |
| --- | --- |
| `manifest.json` | Extension definition: popup, permissions, engine address. |
| `config.js` | Engine address, dashboard address and polling interval. |
| `popup.html` | Popup layout: idle, scanning, failed, completed and unsupported-page views. |
| `popup.css` | Popup styling. |
| `popup.js` | Domain detection, engine requests, progress, results, export. |
| `dev/engine_stub.py` | Test stand-in for the engine. Returns sample data only. |

## Install

### Google Chrome

1. Open `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and select the `cybrot-extension` folder.
4. Pin the CYBROT icon from the puzzle-piece menu so it stays visible.

### Microsoft Edge

1. Open `edge://extensions`.
2. Turn on **Developer mode** (left sidebar, or bottom left).
3. Click **Load unpacked** and select the `cybrot-extension` folder.
4. Pin the CYBROT icon from the extensions menu (puzzle icon) if you want it on the toolbar.

After editing any file, click the reload icon on the CYBROT card in `chrome://extensions` or `edge://extensions`.

## Using it

1. Open a website, for example `https://example.com`.
2. Click the CYBROT icon. The popup shows the detected domain (`example.com`).
3. Choose the scan modules (DNS records, Subdomains, SSL / TLS, WHOIS). Leave **Passive sources only** on unless you have permission for active checks.
4. Click **Start scan**. The popup shows progress and each module's status.
5. When the scan completes, the results appear. Use **Export JSON** to save them, or **Open in dashboard** to view them in the full CYBROT dashboard.

If you close the popup during a scan, reopen it on the same site and the scan picks up where it was. Scan state is stored in the browser, not in the popup.

## Connecting to the engine

The extension talks to the engine over HTTP on your own computer. The default address is `http://127.0.0.1:8000`.

Start the engine before opening the popup. If the engine is not running, the popup shows **Engine offline**. Click the status pill to check again.

### Endpoints the engine must provide

All responses are JSON. Errors use the same shape:

```json
{ "error": { "code": "INVALID_DOMAIN", "message": "'foo' is not a domain name." } }
```

| Method | Path | Purpose | Success response |
| --- | --- | --- | --- |
| GET | `/api/health` | Engine check. | `200` with `{"status": "ok"}` |
| POST | `/api/scans` | Start a scan. Body: `{"domain": "example.com", "modules": ["dns", "subdomains", "ssl", "whois"], "passive_only": true}` | `202` with `{"scan_id": "abc123"}` |
| GET | `/api/scans/{scan_id}` | Scan status and results. Polled every 1.5 s while running. | `200`, see below |
| POST | `/api/scans/{scan_id}/cancel` | Stop a running scan. | `200` |

The status response:

```json
{
  "scan_id": "abc123",
  "domain": "example.com",
  "status": "running",
  "progress": 58,
  "modules": {
    "dns": { "status": "done", "count": 9 },
    "whois": { "status": "done" },
    "subdomains": { "status": "running", "count": 41 },
    "ssl": { "status": "queued" }
  },
  "error": null
}
```

- `status`: `running`, `completed`, `failed` or `cancelled`.
- `progress`: 0 to 100.
- `modules[name].status`: `queued`, `running`, `done`, `failed` or `skipped`. `count` is optional.
- `error`: `{"code": "...", "message": "..."}` when `status` is `failed`, otherwise `null`.

When `status` is `completed`, the response also includes:

```json
{
  "finished_at": "2026-11-12T09:33:10+00:00",
  "duration_seconds": 134.2,
  "results": {
    "domain_details": {
      "registrar": "...",
      "created": "1995-08-14",
      "expires": "2027-08-13",
      "name_servers": ["ns1.example.net", "ns2.example.net"]
    },
    "dns": [ { "type": "A", "value": "192.0.2.10", "ttl": 300 } ],
    "subdomains": ["www.example.com", "mail.example.com"],
    "ssl": {
      "issuer": "...",
      "valid_until": "2027-02-03T00:00:00+00:00",
      "protocol": "TLS 1.3",
      "grade": "A"
    }
  }
}
```

Missing fields are shown as `—`, so the engine can leave out anything it does not collect.

The engine must allow requests from the extension. The browser allows this when the engine address is listed in `host_permissions` in `manifest.json`. The stub in `dev/` also sends CORS headers, so it works from a normal web page too.

### Changing the engine address

1. Change `engineUrl` (and `dashboardUrl`) in `config.js`.
2. Add the same origin to `host_permissions` in `manifest.json`, for example `"http://127.0.0.1:9000/*"`.
3. Reload the extension.

Without step 2 the browser blocks the requests, and the popup reports that it can't reach the engine.

## Testing without the real engine

```bash
python3 dev/engine_stub.py
```

The stub listens on `http://127.0.0.1:8000`. A scan takes about 12 seconds and returns sample data. Domains that start with `fail.` (for example `fail.example.com`) fail halfway, so you can check the failed view.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| "Engine offline" or "Can't reach the CYBROT engine" | Start the engine. Check that it listens on the address in `config.js`. Click the status pill. |
| "Can't scan this page" | The active tab is not an http or https website, for example `chrome://` or `edge://` pages, the new-tab page, or a local file. Also, IP addresses are not supported yet (see limits). |
| Popup shows the wrong site | Make sure the website is the active tab in the current window. Reopen the popup. |
| Requests blocked, but the engine is running | Check that the engine's address and port match `host_permissions` in `manifest.json`. |
| Changes to the code have no effect | Reload the extension on the extensions page. |

## Permissions and privacy

- **`tabs`**: needed to read the address of the active tab, so the domain can be detected. Chrome and Edge show a warning that the extension can read your browsing activity. The extension reads only the active tab, and only when you open the popup.
- **`storage`**: keeps the last scan so the popup can resume or show it.
- **Host permissions** (`127.0.0.1` and `localhost` on port 8000): the extension talks only to the local engine. What the engine does with the domain, including any external lookups, is up to the engine.
- Scans default to **passive sources only**.

## Known limits (first version)

- The extension scans the full hostname shown in the address bar. For example, on `https://www.example.com/` it scans `www.example.com`. Visit `https://example.com/` to scan the bare domain.
- IP addresses are not detected as targets yet.
- The popup uses system fonts and a dark theme only.
- The extension has no icon files yet. To add them, place 16, 32, 48 and 128 pixel PNGs in an `icons/` folder and add an `icons` entry to `manifest.json`, plus `default_icon` under `action`.
- Scans are not queued: starting a new scan on a site while another runs for it replaces the stored scan state in the popup.

## Packaging

To share a build, zip the contents of the `cybrot-extension` folder (the `manifest.json` must be at the top level of the zip). Chrome Web Store and Microsoft Edge Add-ons both accept Manifest V3 zips. Both stores require icons and a store listing, which are not part of this version.
