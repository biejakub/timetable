#!/usr/bin/env python3
# RTT proxy for TfL dashboard.

from flask import Flask, jsonify, request
import os, datetime, time
import requests
from dotenv import load_dotenv

# ============================================================
# CONFIG
# ============================================================
load_dotenv()

BASE = "https://api.rtt.io/api/v1"

RTT_USER = os.getenv("RTT_USER")
RTT_PASS = os.getenv("RTT_PASS")

if not RTT_USER or not RTT_PASS:
    raise RuntimeError("Missing RTT credentials: set RTT_USER and RTT_PASS")

HHY_TTL_SEC = 600     # TTL cache HHY per serviceUid (10 min)
MAX_CACHE = 2000      # failsafe limit
_hhy_cache = {}       # uid -> (bool, expires_at)

app = Flask(__name__)
session = requests.Session()  # re-use TCP/TLS for speed


# ============================================================
# CORS (manual, no extra installs)
# ============================================================
@app.after_request
def add_cors_headers(resp):
    """
    Pozwala frontendowi na fetch nawet gdy HTML jest uruchomiony jako file://
    (origin = "null") lub z localhost.
    """
    origin = request.headers.get("Origin")
    allowed = {
        "null",
        "http://127.0.0.1", "http://localhost",
        "http://127.0.0.1:8000", "http://localhost:8000",
    }

    if origin in allowed:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"

    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    return resp


# ============================================================
# RTT HTTP helper
# ============================================================
def rtt_get(path: str):
    """GET JSON from RTT with auth + timeout."""
    url = f"{BASE}{path}"
    r = session.get(url, auth=(RTT_USER, RTT_PASS), timeout=10)
    r.raise_for_status()
    return r.json()


# ============================================================
# Cache maintenance
# ============================================================
def prune_cache(now: float):
    """Usuń wygasłe wpisy z cache + failsafe limit rozmiaru."""
    if not _hhy_cache:
        return

    expired = [uid for uid, (_, exp) in _hhy_cache.items() if exp <= now]
    for uid in expired:
        _hhy_cache.pop(uid, None)

    # failsafe: jeśli cache mimo TTL urośnie za bardzo, czyścimy całość
    if len(_hhy_cache) > MAX_CACHE:
        _hhy_cache.clear()


# ============================================================
# HHY filter (service details) with TTL cache
# ============================================================
def service_calls_hhy(uid: str, run_date: str) -> bool:
    """
    True jeśli pociąg jedzie z AAP przez Highbury & Islington (HHY),
    tzn. HHY występuje w rozkładzie PO AAP (kierunek AAP → HHY).

    Wymaga RTT /service/{uid}/{yyyy}/{mm}/{dd}.
    Cache ogranicza liczbę requestów i ryzyko rate-limit.
    """
    now = time.time()
    cached = _hhy_cache.get(uid)
    if cached and cached[1] > now:
        return cached[0]

    ok = False
    try:
        # oczekiwany format YYYY-MM-DD
        parts = run_date.split("-")
        if len(parts) != 3:
            raise ValueError(f"Unexpected runDate: {run_date}")

        y, m, d = parts
        svc = rtt_get(f"/json/service/{uid}/{y}/{m}/{d}")

        locs = svc.get("locations") or []

        # znajdź indeks AAP i HHY w kolejności przystanków
        idx_aap = None
        idx_hhy = None

        for i, loc in enumerate(locs):
            crs = (loc.get("crs") or "").upper()
            if crs == "AAP" and idx_aap is None:
                idx_aap = i
            if crs == "HHY" and idx_hhy is None:
                idx_hhy = i

        # pociąg jest OK jeśli oba istnieją i HHY jest później niż AAP
        ok = (
            idx_aap is not None
            and idx_hhy is not None
            and idx_hhy > idx_aap
        )

    except Exception as e:
        # log do stderr ułatwia debug gdy RTT/format padnie
        print("HHY check failed:", e)
        ok = False

    _hhy_cache[uid] = (ok, now + HHY_TTL_SEC)
    return ok


# ============================================================
# MAIN ENDPOINT for frontend
# ============================================================
@app.route("/api/trains", methods=["GET", "OPTIONS"])
def trains_hhy():
    """
    Zwraca wszystkie odjazdy z AAP jadące przez HHY (w kierunku AAP → HHY).
    Frontend sortuje i wyświetla 5 najbliższych.
    """
    if request.method == "OPTIONS":
        return ("", 204)

    if not RTT_USER or not RTT_PASS:
        return jsonify({"services": [], "error": "RTT_USER/RTT_PASS not set"}), 500

    now = time.time()
    prune_cache(now)

    # 1) wszystkie odjazdy z AAP (dowolna destynacja)
    data = rtt_get("/json/search/AAP")
    services_out = []

    # 2) filtr: tylko przez HHY (we właściwym kierunku) + nie-anulowane
    for s in data.get("services", []):
        uid = s.get("serviceUid") or s.get("serviceUID")
        run_date = s.get("runDate")
        if not uid or not run_date:
            continue

        if not service_calls_hhy(uid, run_date):
            continue

        ld = s.get("locationDetail") or {}

        # anulowane wycinamy tutaj, żeby nie mogły wejść do top5
        if ld.get("displayAs") in ("CANCELLED_CALL", "CANCELLED_PASS"):
            continue

        dests = ld.get("destination") or []
        dest_name = dests[0].get("description") if dests else "—"

        std = ld.get("gbttBookedDeparture")
        etd = ld.get("realtimeDeparture") or std

        services_out.append({
            "destination": dest_name,
            "std": std,
            "etd": etd,
            "platform": ld.get("platform"),
            "runDate": run_date,
            "operator": s.get("atocName"),
            "trainId": s.get("trainIdentity"),
            "cancelled": False,
        })

    return jsonify({
        "services": services_out,
        "fetched_at": datetime.datetime.utcnow().isoformat() + "Z",
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5010)
