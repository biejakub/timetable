#!/usr/bin/env python3
# RTT + TfL proxy for the dashboard.

from collections import deque
import datetime
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import logging
import os
import random
import threading
import time
from typing import Any, Dict, Deque, List, Mapping, Optional, Tuple, TypedDict, cast

from dotenv import load_dotenv
from flask import Flask, jsonify, make_response, request, Response
import requests

load_dotenv()

log = logging.getLogger("timetable_proxy")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_csv(name: str, default: str) -> List[str]:
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


RTT_BASE = os.getenv("RTT_BASE_URL", "https://api.rtt.io/api/v1")
TFL_BASE = os.getenv("TFL_BASE_URL", "https://api.tfl.gov.uk")

RTT_USER = os.getenv("RTT_USER")
RTT_PASS = os.getenv("RTT_PASS")
RTT_AUTH: Optional[Tuple[str, str]] = (RTT_USER, RTT_PASS) if RTT_USER and RTT_PASS else None

TFL_APP_ID = os.getenv("TFL_APP_ID")
TFL_APP_KEY = os.getenv("TFL_APP_KEY")
TFL_HAS_KEYS = bool(TFL_APP_ID and TFL_APP_KEY)

CORS_ALLOWED_ORIGINS = set(
    env_csv(
        "CORS_ALLOWED_ORIGINS",
        "http://127.0.0.1,http://localhost,http://127.0.0.1:8000,http://localhost:8000",
    )
)
if env_bool("CORS_ALLOW_NULL_ORIGIN", False):
    CORS_ALLOWED_ORIGINS.add("null")

TRUST_PROXY_HEADERS = env_bool("TRUST_PROXY_HEADERS", False)

RATE_LIMIT_WINDOW_SEC = env_int("RATE_LIMIT_WINDOW_SEC", 60)
API_RATE_LIMIT_PER_MIN = env_int("API_RATE_LIMIT_PER_MIN", 60)
RTT_OUTBOUND_RATE_LIMIT_PER_MIN = env_int("RTT_OUTBOUND_RATE_LIMIT_PER_MIN", 120)
TFL_OUTBOUND_RATE_LIMIT_PER_MIN = env_int(
    "TFL_OUTBOUND_RATE_LIMIT_PER_MIN", 500 if TFL_HAS_KEYS else 50
)

RTT_CONNECT_TIMEOUT_SEC = env_float("RTT_CONNECT_TIMEOUT_SEC", 3.0)
RTT_READ_TIMEOUT_SEC = env_float("RTT_READ_TIMEOUT_SEC", 7.0)
RTT_MAX_RETRIES = env_int("RTT_MAX_RETRIES", 2)
RTT_BACKOFF_BASE_SEC = env_float("RTT_BACKOFF_BASE_SEC", 0.5)
RTT_BACKOFF_MAX_SEC = env_float("RTT_BACKOFF_MAX_SEC", 6.0)

TFL_CONNECT_TIMEOUT_SEC = env_float("TFL_CONNECT_TIMEOUT_SEC", 3.0)
TFL_READ_TIMEOUT_SEC = env_float("TFL_READ_TIMEOUT_SEC", 7.0)
TFL_MAX_RETRIES = env_int("TFL_MAX_RETRIES", 2)
TFL_BACKOFF_BASE_SEC = env_float("TFL_BACKOFF_BASE_SEC", 0.5)
TFL_BACKOFF_MAX_SEC = env_float("TFL_BACKOFF_MAX_SEC", 6.0)

TRAIN_CACHE_MIN_TTL_SEC = env_int("TRAIN_CACHE_MIN_TTL_SEC", 30)
TRAIN_CACHE_STALE_SEC = env_int("TRAIN_CACHE_STALE_SEC", 60)
TFL_CACHE_MIN_TTL_SEC = env_int("TFL_CACHE_MIN_TTL_SEC", 30)
TFL_CACHE_STALE_SEC = env_int("TFL_CACHE_STALE_SEC", 60)

HHY_TTL_SEC = env_int("HHY_TTL_SEC", 600)
MAX_CACHE = env_int("MAX_CACHE", 2000)

ENABLE_HSTS = env_bool("ENABLE_HSTS", False)
HSTS_MAX_AGE_SEC = env_int("HSTS_MAX_AGE_SEC", 15552000)

APP_HOST = os.getenv("APP_HOST", "127.0.0.1")
APP_PORT = env_int("APP_PORT", 5010)

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


@dataclass
class CacheEntry:
    data: Any
    expires_at: float
    stale_until: float
    fetched_at: str
    ttl_sec: int


class OutboundRateLimited(Exception):
    def __init__(self, retry_after: Optional[int]):
        super().__init__("outbound rate limited")
        self.retry_after = retry_after


class UpstreamRateLimited(Exception):
    def __init__(self, retry_after: Optional[int], status: int):
        super().__init__("upstream rate limited")
        self.retry_after = retry_after
        self.status = status


class UpstreamError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class MissingConfig(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_sec: int) -> None:
        self.limit = max(1, limit)
        self.window_sec = max(1, window_sec)
        self._events: Deque[float] = deque[float]()
        self._lock = threading.Lock()

    def allow(self) -> Tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            while self._events and self._events[0] <= now - self.window_sec:
                self._events.popleft()
            if len(self._events) >= self.limit:
                retry_after = int(self.window_sec - (now - self._events[0]))
                return False, max(1, retry_after)
            self._events.append(now)
            return True, 0


class PerKeyLimiter:
    def __init__(self, limit: int, window_sec: int) -> None:
        self.limit = max(1, limit)
        self.window_sec = max(1, window_sec)
        self._events: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> Tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            events = self._events.get(key)
            if events is None:
                events = deque[float]()
                self._events[key] = events
            while events and events[0] <= now - self.window_sec:
                events.popleft()
            if len(events) >= self.limit:
                retry_after = int(self.window_sec - (now - events[0]))
                return False, max(1, retry_after)
            events.append(now)
            return True, 0


_hhy_cache: Dict[str, Tuple[Optional[Tuple[str, ...]], float]] = {}
_hhy_lock = threading.Lock()

_trains_cache: Optional[CacheEntry] = None
_trains_lock = threading.Lock()
_trains_refreshing = False

_tfl_cache: Dict[str, CacheEntry] = {}
_tfl_lock = threading.Lock()
_tfl_refreshing: set[str] = set()

api_limiter = PerKeyLimiter(API_RATE_LIMIT_PER_MIN, RATE_LIMIT_WINDOW_SEC)
rtt_outbound_limiter = SlidingWindowLimiter(RTT_OUTBOUND_RATE_LIMIT_PER_MIN, RATE_LIMIT_WINDOW_SEC)
tfl_outbound_limiter = SlidingWindowLimiter(TFL_OUTBOUND_RATE_LIMIT_PER_MIN, RATE_LIMIT_WINDOW_SEC)

app = Flask(__name__)
session = requests.Session()


def get_client_ip() -> str:
    if TRUST_PROXY_HEADERS:
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def parse_retry_after(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return int(value)
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    delta = parsed - datetime.datetime.now(datetime.timezone.utc)
    return max(0, int(delta.total_seconds()))


def parse_cache_ttl(headers: Mapping[str, str]) -> Optional[int]:
    cache_control = headers.get("Cache-Control", "")
    max_age = None
    for part in cache_control.split(","):
        part = part.strip().lower()
        if part.startswith("max-age="):
            value = part.split("=", 1)[1]
            if value.isdigit():
                max_age = int(value)
                break
    if max_age is not None:
        try:
            age = int(headers.get("Age", "0"))
        except ValueError:
            age = 0
        return max(max_age - age, 0)

    expires = headers.get("Expires")
    if not expires:
        return None
    try:
        parsed = parsedate_to_datetime(expires)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    delta = parsed - datetime.datetime.now(datetime.timezone.utc)
    return max(0, int(delta.total_seconds()))


def compute_ttl(headers: Mapping[str, str], min_ttl: int) -> int:
    ttl = parse_cache_ttl(headers)
    if ttl is None:
        return max(1, min_ttl)
    return max(min_ttl, ttl)


def compute_backoff(attempt: int, base: float, maximum: float) -> float:
    delay = min(maximum, base * (2**attempt))
    return delay * (0.7 + random.random() * 0.6)


def request_json(
    url: str,
    *,
    auth: Optional[Tuple[str, str]] = None,
    params: Optional[Dict[str, str]] = None,
    timeout: Optional[Tuple[float, float]] = None,
    limiter: Optional[SlidingWindowLimiter] = None,
    max_retries: int = 0,
    backoff_base: float = 0.5,
    backoff_max: float = 6.0,
    service_name: str = "upstream",
) -> Tuple[Any, Mapping[str, str]]:
    attempt = 0
    while True:
        if limiter is not None:
            allowed, retry_after = limiter.allow()
            if not allowed:
                raise OutboundRateLimited(retry_after)

        try:
            resp = session.get(
                url,
                auth=auth,
                params=params,
                timeout=timeout,
                headers={"Accept": "application/json"},
            )
        except requests.RequestException as exc:
            if attempt >= max_retries:
                raise UpstreamError(504, f"{service_name} request failed") from exc
            time.sleep(compute_backoff(attempt, backoff_base, backoff_max))
            attempt += 1
            continue

        if resp.status_code in (420, 429):
            retry_after = parse_retry_after(resp.headers.get("Retry-After"))
            if attempt >= max_retries:
                raise UpstreamRateLimited(retry_after, resp.status_code)
            delay = retry_after if retry_after is not None else compute_backoff(
                attempt, backoff_base, backoff_max
            )
            time.sleep(delay)
            attempt += 1
            continue

        if 500 <= resp.status_code <= 599:
            if attempt >= max_retries:
                raise UpstreamError(resp.status_code, f"{service_name} upstream error")
            time.sleep(compute_backoff(attempt, backoff_base, backoff_max))
            attempt += 1
            continue

        if resp.status_code >= 400:
            raise UpstreamError(resp.status_code, f"{service_name} upstream error")

        try:
            return resp.json(), resp.headers
        except ValueError as exc:
            raise UpstreamError(502, f"{service_name} invalid JSON") from exc


def rtt_get_json(path: str) -> Tuple[JsonDict, Mapping[str, str]]:
    if RTT_AUTH is None:
        raise MissingConfig("RTT credentials not set")
    url = f"{RTT_BASE}{path}"
    return request_json(
        url,
        auth=RTT_AUTH,
        timeout=(RTT_CONNECT_TIMEOUT_SEC, RTT_READ_TIMEOUT_SEC),
        limiter=rtt_outbound_limiter,
        max_retries=RTT_MAX_RETRIES,
        backoff_base=RTT_BACKOFF_BASE_SEC,
        backoff_max=RTT_BACKOFF_MAX_SEC,
        service_name="RTT",
    )


def tfl_get_json(path: str) -> Tuple[Any, Mapping[str, str]]:
    params: Dict[str, str] = {}
    if TFL_APP_ID and TFL_APP_KEY:
        params["app_id"] = TFL_APP_ID
        params["app_key"] = TFL_APP_KEY
    url = f"{TFL_BASE}{path}"
    return request_json(
        url,
        params=params or None,
        timeout=(TFL_CONNECT_TIMEOUT_SEC, TFL_READ_TIMEOUT_SEC),
        limiter=tfl_outbound_limiter,
        max_retries=TFL_MAX_RETRIES,
        backoff_base=TFL_BACKOFF_BASE_SEC,
        backoff_max=TFL_BACKOFF_MAX_SEC,
        service_name="TfL",
    )


def add_cache_headers(resp: Response, ttl_sec: int, stale_sec: int) -> Response:
    cache_control = f"max-age={ttl_sec}"
    if stale_sec > 0:
        cache_control += f", stale-while-revalidate={stale_sec}"
    resp.headers["Cache-Control"] = cache_control
    resp.headers["X-Cache-Ttl-Seconds"] = str(ttl_sec)
    return resp


def error_response(
    status: int,
    code: str,
    message: str,
    *,
    empty_key: str,
    retry_after: Optional[int] = None,
) -> Response:
    empty_items: List[JsonDict] = []
    payload: Dict[str, Any] = {
        empty_key: empty_items,
        "fetched_at": utc_now_iso(),
        "cache_ttl_sec": 0,
        "error": {"code": code, "message": message},
    }
    resp = jsonify(payload)
    resp.status_code = status
    resp.headers["Cache-Control"] = "no-store"
    if retry_after is not None:
        resp.headers["Retry-After"] = str(retry_after)
    return resp


@app.before_request
def apply_rate_limit() -> Optional[Response]:
    if not request.path.startswith("/api/"):
        return None
    if request.method == "OPTIONS":
        return make_response("", 204)
    client_ip = get_client_ip()
    allowed, retry_after = api_limiter.allow(client_ip)
    if not allowed:
        return error_response(
            429,
            "rate_limited",
            "Too many requests",
            empty_key="services" if request.path.endswith("/trains") else "data",
            retry_after=retry_after,
        )
    return None


@app.after_request
def add_common_headers(resp: Response) -> Response:
    origin = request.headers.get("Origin")
    if origin and origin in CORS_ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        resp.headers["Access-Control-Expose-Headers"] = (
            "Cache-Control, Age, Expires, Retry-After, X-Cache-Ttl-Seconds"
        )
        resp.headers["Access-Control-Max-Age"] = "600"

    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "DENY")

    if ENABLE_HSTS and request.is_secure:
        resp.headers.setdefault(
            "Strict-Transport-Security",
            f"max-age={HSTS_MAX_AGE_SEC}; includeSubDomains",
        )
    return resp


# HHY cache bounds protect memory under request spikes.
def prune_hhy_cache(now: float) -> None:
    with _hhy_lock:
        if not _hhy_cache:
            return
        expired = [uid for uid, (_, exp) in _hhy_cache.items() if exp <= now]
        for uid in expired:
            _hhy_cache.pop(uid, None)
        if len(_hhy_cache) > MAX_CACHE:
            _hhy_cache.clear()


def service_via(uid: str, run_date: str) -> Optional[Tuple[str, ...]]:
    now = time.time()
    cache_key = f"{uid}:{run_date}"
    with _hhy_lock:
        cached = _hhy_cache.get(cache_key)
        if cached and cached[1] > now:
            return cached[0]

    via: Optional[Tuple[str, ...]] = None
    try:
        parts = run_date.split("-")
        if len(parts) != 3:
            raise ValueError(f"Unexpected runDate: {run_date}")
        y, m, d = parts
        svc = cast(ServiceResponse, rtt_get_json(f"/json/service/{uid}/{y}/{m}/{d}")[0])
        locs: List[ServiceLocation] = svc.get("locations") or []

        idx_aap: Optional[int] = None
        idx_hhy: Optional[int] = None
        idx_fpk: Optional[int] = None

        for i, loc in enumerate(locs):
            crs = (loc.get("crs") or "").upper()
            if crs == "AAP" and idx_aap is None:
                idx_aap = i
            if crs == "HHY" and idx_hhy is None:
                idx_hhy = i
            if crs == "FPK" and idx_fpk is None:
                idx_fpk = i

        if idx_aap is not None:
            candidates: List[Tuple[str, int]] = []
            if idx_hhy is not None and idx_hhy > idx_aap:
                candidates.append(("HHY", idx_hhy))
            if idx_fpk is not None and idx_fpk > idx_aap:
                candidates.append(("FPK", idx_fpk))
            if candidates:
                candidates.sort(key=lambda item: item[1])
                via = tuple(code for code, _ in candidates)
    except (UpstreamError, UpstreamRateLimited, MissingConfig) as exc:
        log.warning("HHY check failed: %s", exc)
        via = None
    except Exception as exc:
        log.warning("HHY check failed: %s", exc)
        via = None

    with _hhy_lock:
        _hhy_cache[cache_key] = (via, now + HHY_TTL_SEC)
    return via


def build_trains_payload(services_out: List[JsonDict], ttl_sec: int) -> Dict[str, Any]:
    return {
        "services": services_out,
        "fetched_at": utc_now_iso(),
        "cache_ttl_sec": ttl_sec,
    }


def fetch_trains() -> CacheEntry:
    now = time.time()
    data, headers = rtt_get_json("/json/search/AAP")
    ttl_sec = compute_ttl(headers, TRAIN_CACHE_MIN_TTL_SEC)

    prune_hhy_cache(now)

    services = cast(List[Service], data.get("services") or [])
    services_out: List[JsonDict] = []

    for s in services:
        uid = s.get("serviceUid") or s.get("serviceUID")
        run_date = s.get("runDate")
        if not uid or not run_date:
            continue

        via = service_via(uid, run_date)
        if via is None:
            continue

        ld: LocationDetail = s.get("locationDetail") or {}
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

        services_out.append(
            {
                "destination": dest_name,
                "std": std,
                "etd": etd,
                "platform": ld.get("platform"),
                "runDate": run_date,
                "operator": s.get("atocName"),
                "trainId": s.get("trainIdentity"),
                "cancelled": is_cancelled,
                "via": list(via),
            }
        )

    payload: Dict[str, Any] = build_trains_payload(services_out, ttl_sec)
    return CacheEntry(
        data=payload,
        expires_at=now + ttl_sec,
        stale_until=now + ttl_sec + TRAIN_CACHE_STALE_SEC,
        fetched_at=payload["fetched_at"],
        ttl_sec=ttl_sec,
    )


def refresh_trains_async() -> None:
    global _trains_cache, _trains_refreshing
    try:
        entry = fetch_trains()
        with _trains_lock:
            _trains_cache = entry
    except Exception as exc:
        log.warning("Train refresh failed: %s", exc)
    finally:
        with _trains_lock:
            _trains_refreshing = False


def get_trains_cached() -> CacheEntry:
    global _trains_cache, _trains_refreshing
    now = time.time()
    with _trains_lock:
        entry = _trains_cache
        if entry and now < entry.expires_at:
            return entry
        if entry and now < entry.stale_until:
            if not _trains_refreshing:
                _trains_refreshing = True
                threading.Thread(target=refresh_trains_async, daemon=True).start()
            return entry

    entry = fetch_trains()
    with _trains_lock:
        _trains_cache = entry
    return entry


def fetch_tfl(path: str) -> CacheEntry:
    now = time.time()
    data, headers = tfl_get_json(path)
    ttl_sec = compute_ttl(headers, TFL_CACHE_MIN_TTL_SEC)
    payload: Dict[str, Any] = {
        "data": data if data is not None else [],
        "fetched_at": utc_now_iso(),
        "cache_ttl_sec": ttl_sec,
    }
    return CacheEntry(
        data=payload,
        expires_at=now + ttl_sec,
        stale_until=now + ttl_sec + TFL_CACHE_STALE_SEC,
        fetched_at=payload["fetched_at"],
        ttl_sec=ttl_sec,
    )


def refresh_tfl_async(cache_key: str, path: str) -> None:
    try:
        entry = fetch_tfl(path)
        with _tfl_lock:
            _tfl_cache[cache_key] = entry
    except Exception as exc:
        log.warning("TfL refresh failed: %s", exc)
    finally:
        with _tfl_lock:
            _tfl_refreshing.discard(cache_key)


def get_tfl_cached(cache_key: str, path: str) -> CacheEntry:
    now = time.time()
    with _tfl_lock:
        entry = _tfl_cache.get(cache_key)
        if entry and now < entry.expires_at:
            return entry
        if entry and now < entry.stale_until:
            if cache_key not in _tfl_refreshing:
                _tfl_refreshing.add(cache_key)
                threading.Thread(
                    target=refresh_tfl_async, args=(cache_key, path), daemon=True
                ).start()
            return entry

    entry = fetch_tfl(path)
    with _tfl_lock:
        _tfl_cache[cache_key] = entry
    return entry


@app.route("/api/trains", methods=["GET", "OPTIONS"])
def trains_hhy() -> Response:
    if request.method == "OPTIONS":
        return make_response("", 204)

    if RTT_AUTH is None:
        return error_response(
            500,
            "missing_credentials",
            "RTT credentials not configured",
            empty_key="services",
        )

    try:
        entry = get_trains_cached()
    except MissingConfig as exc:
        return error_response(500, "missing_credentials", str(exc), empty_key="services")
    except OutboundRateLimited as exc:
        return error_response(
            503,
            "outbound_rate_limited",
            "Outbound RTT limit exceeded",
            empty_key="services",
            retry_after=exc.retry_after,
        )
    except UpstreamRateLimited as exc:
        return error_response(
            503,
            "upstream_rate_limited",
            "RTT rate limited",
            empty_key="services",
            retry_after=exc.retry_after,
        )
    except UpstreamError as exc:
        return error_response(502, "upstream_error", str(exc), empty_key="services")
    except Exception:
        return error_response(500, "internal_error", "Unexpected error", empty_key="services")

    resp = jsonify(entry.data)
    return add_cache_headers(resp, entry.ttl_sec, TRAIN_CACHE_STALE_SEC)


@app.route("/api/tfl/stop/<stop_id>/arrivals", methods=["GET", "OPTIONS"])
def tfl_stop_arrivals(stop_id: str) -> Response:
    if request.method == "OPTIONS":
        return make_response("", 204)

    path = f"/StopPoint/{stop_id}/Arrivals"
    cache_key = f"stop:{stop_id}"

    try:
        entry = get_tfl_cached(cache_key, path)
    except OutboundRateLimited as exc:
        return error_response(
            503,
            "outbound_rate_limited",
            "Outbound TfL limit exceeded",
            empty_key="data",
            retry_after=exc.retry_after,
        )
    except UpstreamRateLimited as exc:
        return error_response(
            503,
            "upstream_rate_limited",
            "TfL rate limited",
            empty_key="data",
            retry_after=exc.retry_after,
        )
    except UpstreamError as exc:
        return error_response(502, "upstream_error", str(exc), empty_key="data")
    except Exception:
        return error_response(500, "internal_error", "Unexpected error", empty_key="data")

    resp = jsonify(entry.data)
    return add_cache_headers(resp, entry.ttl_sec, TFL_CACHE_STALE_SEC)


@app.route("/api/tfl/line/<line_id>/arrivals/<stop_id>", methods=["GET", "OPTIONS"])
def tfl_line_arrivals(line_id: str, stop_id: str) -> Response:
    if request.method == "OPTIONS":
        return make_response("", 204)

    path = f"/Line/{line_id}/Arrivals/{stop_id}"
    cache_key = f"line:{line_id}:{stop_id}"

    try:
        entry = get_tfl_cached(cache_key, path)
    except OutboundRateLimited as exc:
        return error_response(
            503,
            "outbound_rate_limited",
            "Outbound TfL limit exceeded",
            empty_key="data",
            retry_after=exc.retry_after,
        )
    except UpstreamRateLimited as exc:
        return error_response(
            503,
            "upstream_rate_limited",
            "TfL rate limited",
            empty_key="data",
            retry_after=exc.retry_after,
        )
    except UpstreamError as exc:
        return error_response(502, "upstream_error", str(exc), empty_key="data")
    except Exception:
        return error_response(500, "internal_error", "Unexpected error", empty_key="data")

    resp = jsonify(entry.data)
    return add_cache_headers(resp, entry.ttl_sec, TFL_CACHE_STALE_SEC)


if __name__ == "__main__":
    app.run(host=APP_HOST, port=APP_PORT)
