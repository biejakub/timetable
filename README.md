# Timetable proxy (RTT + TfL)

Proxy server for the TfL dashboard. It fetches departures from RTT and data
from TfL, applies caching and rate limiting, and exposes JSON for the frontend.

## Requirements
- Python 3.9+
- pip

## Install
```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration (.env)
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

## Endpoints
`GET /api/trains`
- Departures from AAP with `via` as a list of CRS codes (ordered after AAP).
- Response: `services`, `fetched_at`, `cache_ttl_sec`.

`GET /api/tfl/stop/{stopId}/arrivals`
`GET /api/tfl/line/{lineId}/arrivals/{stopId}`
- TfL proxy data.
- Response: `data`, `fetched_at`, `cache_ttl_sec`.

## Refresh and cache (compliance)
- The proxy honors `Cache-Control`, `Age`, and `Expires`.
- The frontend computes the polling interval from TTL with a 60s fallback.
- `stale-while-revalidate` is used (serve cache and refresh in background).
- Retry uses exponential backoff with jitter and honors `Retry-After`.

## Limits (TfL + RTT)
- TfL Open Data: 50 req/min without keys, 500 req/min with keys.
- Limits are enforced in the backend via `TFL_OUTBOUND_RATE_LIMIT_PER_MIN`.
- RTT outbound limit is controlled via `RTT_OUTBOUND_RATE_LIMIT_PER_MIN`.
- There is also a per-client IP limit: `API_RATE_LIMIT_PER_MIN`.

## Attribution (TfL)
The UI shows a visible `Powered by TfL Open Data` label.

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
pytest
```
