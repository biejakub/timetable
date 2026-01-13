#!/usr/bin/env python3
# RTT proxy for TfL dashboard.

from flask import Flask, jsonify, request, Response
import os, datetime, time
import requests
from dotenv import load_dotenv
from typing import Any, Dict, List, Optional, Tuple, Union, TypedDict, cast

# ============================================================
# CONFIG
# ============================================================
load_dotenv()

BASE = "https://api.rtt.io/api/v1"

rtt_user = os.getenv("RTT_USER")
rtt_pass = os.getenv("RTT_PASS")

if not rtt_user or not rtt_pass:
    raise RuntimeError("Missing RTT credentials: set RTT_USER and RTT_PASS")
RTT_AUTH: Tuple[str, str] = (rtt_user, rtt_pass)

HHY_TTL_SEC = 600     # TTL cache HHY per serviceUid (10 min)
MAX_CACHE = 2000      # failsafe limit
JsonDict = Dict[str, Any]


class ServiceLocation(TypedDict, total=False):
    crs: str


class ServiceResponse(TypedDict, total=False):
    locations: List[ServiceLocation]


class Destination(TypedDict, total=False):
    description: str


class LocationDetail(TypedDict, total=False):
    destination: List[Destination]
    displayAs: str
    gbttBookedDeparture: str
    realtimeDeparture: str
    platform: str


class Service(TypedDict, total=False):
    serviceUid: str
    serviceUID: str
    runDate: str
    locationDetail: LocationDetail
    atocName: str
    trainIdentity: str


_hhy_cache: Dict[str, Tuple[bool, float]] = {}       # uid -> (bool, expires_at)

app = Flask(__name__)
session = requests.Session()  # re-use TCP/TLS for speed


# ============================================================
# CORS (manual, no extra installs)
# ============================================================
@app.after_request
def add_cors_headers(resp: Response) -> Response:
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

    if origin is not None and origin in allowed:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"

    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    return resp


# ============================================================
# RTT HTTP helper
# ============================================================
def rtt_get(path: str) -> JsonDict:
    """GET JSON from RTT with auth + timeout."""
    url = f"{BASE}{path}"
    r = session.get(url, auth=RTT_AUTH, timeout=10)
    r.raise_for_status()
    return r.json()


# ============================================================
# Cache maintenance
# ============================================================
def prune_cache(now: float) -> None:
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
    tzn. HHY występuje w rozkładzie PO AAP (kierunek AAP -> HHY).

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
        svc = cast(ServiceResponse, rtt_get(f"/json/service/{uid}/{y}/{m}/{d}"))

        locs: List[ServiceLocation] = svc.get("locations") or []

        # znajdź indeks AAP i HHY w kolejności przystanków
        idx_aap: Optional[int] = None
        idx_hhy: Optional[int] = None

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
def trains_hhy() -> Union[Response, Tuple[Response, int], Tuple[str, int]]:
    """
    Zwraca wszystkie odjazdy z AAP jadące przez HHY (w kierunku AAP -> HHY).
    Frontend sortuje i wyświetla 5 najbliższych.
    """
    if request.method == "OPTIONS":
        return ("", 204)

    if not rtt_user or not rtt_pass:
        return jsonify({"services": [], "error": "RTT_USER/RTT_PASS not set"}), 500

    now = time.time()
    prune_cache(now)

    # 1) wszystkie odjazdy z AAP (dowolna destynacja)
    data = rtt_get("/json/search/AAP")
    services = cast(List[Service], data.get("services") or [])
    services_out: List[JsonDict] = []

    # 2) filtr: tylko przez HHY (we właściwym kierunku) + nie-anulowane
    for s in services:
        uid = s.get("serviceUid") or s.get("serviceUID")
        run_date = s.get("runDate")
        if not uid or not run_date:
            continue

        if not service_calls_hhy(uid, run_date):
            continue

        ld: LocationDetail = s.get("locationDetail") or {}

        # anulowane wycinamy tutaj, żeby nie mogły wejść do top5
        is_cancelled = ld.get("displayAs") in ("CANCELLED_CALL", "CANCELLED_PASS")

        dests: List[Destination] = ld.get("destination") or []
        if dests:
            desc = dests[0].get("description")
            dest_name = desc if desc is not None else "-"
        else:
            dest_name = "-"

        std = ld.get("gbttBookedDeparture")
        if is_cancelled:
            etd = "Anulowane"
        else:
            etd = ld.get("realtimeDeparture") or std

        services_out.append({
            "destination": dest_name,
            "std": std,
            "etd": etd,
            "platform": ld.get("platform"),
            "runDate": run_date,
            "operator": s.get("atocName"),
            "trainId": s.get("trainIdentity"),
            "cancelled": is_cancelled,
        })

    fetched_at = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    return jsonify({
        "services": services_out,
        "fetched_at": fetched_at,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5010)
