# Timetable proxy (RTT + TfL)

Serwer proxy dla dashboardu TfL. Pobiera odjazdy z RTT i dane z TfL, stosuje
cache + rate limiting, a następnie wystawia JSON dla frontendu.

## Wymagania
- Python 3.9+
- pip

## Instalacja
```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Konfiguracja (.env)
Wymagane:
- `RTT_USER` – login RTT
- `RTT_PASS` – hasło RTT

Opcjonalne (zalecane):
- `TFL_APP_ID` – TfL app_id
- `TFL_APP_KEY` – TfL app_key

Bezpieczeństwo i CORS:
- `CORS_ALLOWED_ORIGINS` – lista originów CSV (domyślnie localhost)
- `CORS_ALLOW_NULL_ORIGIN` – `1/true` jeśli UI działa jako `file://`
- `TRUST_PROXY_HEADERS` – `1/true` jeśli reverse proxy ustawia `X-Forwarded-For`
- `ENABLE_HSTS` – `1/true` tylko przy HTTPS end-to-end
- `HSTS_MAX_AGE_SEC` – czas HSTS, np. `15552000`

Limity i cache:
- `API_RATE_LIMIT_PER_MIN` – limit na klienta (IP), domyślnie 60
- `RTT_OUTBOUND_RATE_LIMIT_PER_MIN` – globalny limit outbound do RTT
- `TFL_OUTBOUND_RATE_LIMIT_PER_MIN` – globalny limit outbound do TfL  
  (domyślnie 50 bez kluczy, 500 z kluczami)
- `TRAIN_CACHE_MIN_TTL_SEC` – minimalny TTL dla /api/trains (domyślnie 30)
- `TRAIN_CACHE_STALE_SEC` – stale-while-revalidate dla /api/trains (domyślnie 60)
- `TFL_CACHE_MIN_TTL_SEC` – minimalny TTL dla proxy TfL (domyślnie 30)
- `TFL_CACHE_STALE_SEC` – stale-while-revalidate dla proxy TfL (domyślnie 60)

Uruchomienie:
- `APP_HOST` – domyślnie `127.0.0.1`
- `APP_PORT` – domyślnie `5010`

## Uruchomienie (dev)
```bash
python rtt_proxy.py
```

## Uruchomienie (prod)
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

Zalecane jest uruchamianie za reverse proxy z TLS. Jeśli używasz proxy,
ustaw `TRUST_PROXY_HEADERS=1` i dodaj własne rate limiting po stronie proxy.

## Endpointy
`GET /api/trains`
- Zwraca odjazdy z AAP przez HHY (kierunek AAP -> HHY).
- Odpowiedź: `services`, `fetched_at`, `cache_ttl_sec`.

`GET /api/tfl/stop/{stopId}/arrivals`  
`GET /api/tfl/line/{lineId}/arrivals/{stopId}`
- Proxy danych TfL.
- Odpowiedź: `data`, `fetched_at`, `cache_ttl_sec`.

## Odświeżanie i cache (compliance)
- Proxy respektuje `Cache-Control`, `Age` i `Expires`.
- Frontend oblicza minimalny polling na podstawie TTL i fallbacku 60s.
- Stosowany jest `stale-while-revalidate` (cache serwowany, odświeżanie w tle).
- Retry z exponential backoff + jitter; honorowany `Retry-After`.

## Limity (TfL + RTT)
- TfL Open Data: 50 req/min bez kluczy, 500 req/min z kluczami.
- Limity są egzekwowane w backendzie przez `TFL_OUTBOUND_RATE_LIMIT_PER_MIN`.
- RTT: limit outbound kontrolowany przez `RTT_OUTBOUND_RATE_LIMIT_PER_MIN`.
- Dodatkowo obowiązuje limit na klienta (IP): `API_RATE_LIMIT_PER_MIN`.

## Atrybucja (TfL)
W UI znajduje się widoczny tekst: `Powered by TfL Open Data`.

## Bezpieczeństwo
- CORS tylko z allowlisty (ENV).
- Nagłówki: `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`.
- Sekrety wyłącznie z ENV, brak zwracania w odpowiedziach.

## Audyt zależności
```bash
pip-audit -r requirements.txt
```

## Testy
```bash
pytest
```
