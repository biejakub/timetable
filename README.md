# Timetable proxy (RTT + TfL)
Proxy server for the TfL dashboard. It fetches departures from RTT and data
from TfL, applies caching and rate limiting, and exposes JSON for the frontend.

## TL;DR
- Local, privacy-friendly dashboard for departures near Alexandra Palace.
- Flask proxy enforces caching, rate limits, and compliance controls.
- Frontend is a single HTML file designed for always-on display.

## Project overview
This project is a lightweight local dashboard and proxy that aggregates
real-time departures from RTT and TfL, then renders a simple at-a-glance display
for a specific routine. The backend enforces caching, rate limits, and security
controls, while the frontend polls the proxy and presents arrivals in a clean,
large-format UI suitable for a wall-mounted tablet or kiosk.

## Architecture at a glance
- Frontend (`TfL.html`): static HTML/JS dashboard that polls the proxy.
- Backend (`rtt_proxy.py`): Flask service that calls RTT and TfL, applies caching,
  rate limiting, retry/backoff, and enforces compliance checks.
- Optional Redis: shared cache and shared rate limiter for multi-worker setups.

## Motivation
Every morning, my wife and I followed the same small ritual: checking how much time we had left to catch the metro, train, or bus. We relied on our favorite app, Citymapper - it works great. But one day a simple thought crossed my mind: what if this could be even simpler?

That question sparked the idea for this project. If an app can show real-time departures from nearby stops, why couldn't I build a lightweight, purpose-built display tailored exactly to our routine - especially with a bit of help from AI? What started as a curiosity quickly turned into a working solution.

Today, the project is stable, compliant, and does exactly what it was meant to do, so I'm sharing it publicly for others to adapt to their own needs. In our home, it runs as a local web page on an old tablet, permanently mounted near the door and powered directly (battery removed), always ready at a glance.

It's a small project, born from everyday life - and sometimes that's where the best ideas come from.

## Requirements
- Python 3.9+
- pip

## Install
```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Quick start (local display)
```bash
python rtt_proxy.py
```
In another terminal:
```bash
python -m http.server 8000
```
Open `http://localhost:8000/TfL.html` in your browser. If you prefer `file://`,
set `CORS_ALLOW_NULL_ORIGIN=1`.

## Configuration (.env)
Use `.env.example` as a safe template.

Required:
- `RTT_USER` - RTT username
- `RTT_PASS` - RTT password

Optional (recommended):
- `TFL_APP_ID` - TfL app_id
- `TFL_APP_KEY` - TfL app_key

Security and CORS:
- `CORS_ALLOWED_ORIGINS` - CSV allowlist (default: localhost)
- `CORS_ALLOW_NULL_ORIGIN` - `1/true` if the UI runs as `file://`
- `TRUST_PROXY_HEADERS` - `1/true` if a reverse proxy sets `X-Forwarded-*`
- `ENABLE_HSTS` - `1/true` only with end-to-end HTTPS
- `HSTS_MAX_AGE_SEC` - HSTS max-age, e.g. `15552000`

Limits and cache:
- `API_RATE_LIMIT_PER_MIN` - per-client (IP) limit, default 60
- `RTT_OUTBOUND_RATE_LIMIT_PER_MIN` - global outbound limit to RTT
- `TFL_OUTBOUND_RATE_LIMIT_PER_MIN` - global outbound limit to TfL
  (default 50 without keys, 500 with keys)
- `TRAIN_CACHE_MIN_TTL_SEC` - minimum TTL for `/api/trains` (default 30)
- `TRAIN_CACHE_STALE_SEC` - stale-while-revalidate for `/api/trains` (default 60)
- `TFL_CACHE_MIN_TTL_SEC` - minimum TTL for TfL proxy (default 30)
- `TFL_CACHE_STALE_SEC` - stale-while-revalidate for TfL proxy (default 60)

Redis (optional shared cache + rate limiting):
- `REDIS_URL` - Redis connection URL
- `REDIS_PREFIX` - key prefix (default `timetable_proxy`)
- `REDIS_LOCK_TTL_SEC` - lock TTL for background refresh (default 15)

Runtime:
- `APP_HOST` - default `127.0.0.1`
- `APP_PORT` - default `5010`
- `APP_ENV` or `FLASK_ENV` - set to `production` for production mode
- `DEBUG` - when explicitly set to `0/false`, production mode is enabled
- `WEB_CONCURRENCY` / `GUNICORN_WORKERS` - worker count for compliance checks

## Run (dev)
```bash
python rtt_proxy.py
```

## Run (prod)
Linux (WSGI):
```bash
pip install gunicorn
gunicorn -w 2 -b 0.0.0.0:5010 rtt_proxy:app
```

Windows (WSGI):
```bash
pip install waitress
waitress-serve --listen=127.0.0.1:5010 rtt_proxy:app
```

Run behind a reverse proxy with TLS. If a proxy sets `X-Forwarded-*`, set
`TRUST_PROXY_HEADERS=1` so `ProxyFix` can read the forwarded scheme and IP.
Add extra rate limiting on the proxy if needed.

If `REDIS_URL` is not set or Redis is unavailable, caching and rate limiting
fall back to in-memory per process.

## Production requirements (compliance)
- Multi-worker WSGI deployments must use Redis (`REDIS_URL`) so rate limiting
  and caching are shared across workers.
- Without Redis, run a single worker only (for example: `gunicorn -w 1 ...`)
  to keep TfL outbound limits compliant.
  In production, the app requires `WEB_CONCURRENCY` or `GUNICORN_WORKERS` to be
  set and will refuse to start if multi-worker is configured without Redis.
  Production mode is detected when `APP_ENV` or `FLASK_ENV` is `production`,
  or when `DEBUG` is explicitly set to `false/0`.

## Endpoints
`GET /api/trains`
- Departures from AAP with `via` as a list of CRS codes (ordered after AAP).
- Response: `services`, `fetched_at`, `cache_ttl_sec`.

`GET /api/tfl/stop/{stopId}/arrivals`
`GET /api/tfl/line/{lineId}/arrivals/{stopId}`
- TfL proxy data.
- Response: `data`, `fetched_at`, `cache_ttl_sec`.

## Fair-use and best practice
- The proxy honors `Cache-Control`, `Age`, and `Expires`.
- The frontend computes the polling interval from TTL with a 60s fallback.
- `stale-while-revalidate` is used (serve cache and refresh in background).
- Retry uses exponential backoff with jitter and honors `Retry-After`.

## Common issues
- App refuses to start in production: set `WEB_CONCURRENCY=1` or configure
  `REDIS_URL` for multi-worker deployments.
- CORS errors: add your origin to `CORS_ALLOWED_ORIGINS` or set
  `CORS_ALLOW_NULL_ORIGIN=1` if using `file://`.
- No RTT data: verify `RTT_USER` and `RTT_PASS` are set and valid.

## Official requirements (TfL + RTT)
- TfL Open Data requires a visible attribution label: `Powered by TfL Open Data`.
- TfL Open Data rate limits: 50 req/min without keys, 500 req/min with keys.
  Limits are enforced in the backend via `TFL_OUTBOUND_RATE_LIMIT_PER_MIN`.
- TfL API rate limits are published at https://api-portal.tfl.gov.uk/.
- RTT access is intended for personal, non-commercial use.
- Usage of these data sources is subject to their terms.

## Usage scope
This project is intended for personal, non-commercial use. RTT access is
intended for personal use only. Commercial use should be reviewed against
provider terms or confirmed with RTT before deployment. This project is not
affiliated with TfL or RTT.

## Attribution (TfL)
The UI shows a visible `Powered by TfL Open Data` label.

## Terms and conditions
Usage of these data sources is subject to their official terms and conditions:
- https://tfl.gov.uk/info-for/open-data-users/our-open-data
- https://tfl.gov.uk/corporate/terms-and-conditions/transport-data-service
- https://www.realtimetrains.co.uk/about/developer/
- https://www.realtimetrains.co.uk/legal/
- https://api.rtt.io/

## Security
- CORS is allowlist-only (ENV).
- Headers: `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`,
  `Content-Security-Policy`, `Permissions-Policy`.
- Secrets only from ENV; not returned in responses.

## Dependency audit
```bash
pip-audit -r requirements.txt
```

## Tests
```bash
pip install -r requirements-dev.txt
python -m pytest -q
```
