#!/usr/bin/env python3
# RTT + TfL proxy for the dashboard.

from collections import deque
import datetime
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import importlib
import json
import logging
import os
import random
import re
import threading
import time
import uuid
from typing import Any, Dict, Deque, List, Mapping, Optional, Protocol, Tuple, TypedDict, cast

from dotenv import load_dotenv
from flask import Flask, jsonify, make_response, request, Response
import requests
from werkzeug.middleware.proxy_fix import ProxyFix

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


def env_optional_bool(name: str) -> Optional[bool]:
    value = os.getenv(name)
    if value is None:
        return None
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
TFL_MAX_RATE_LIMIT_PER_MIN = 500 if TFL_HAS_KEYS else 50

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
TFL_OUTBOUND_RATE_LIMIT_PER_MIN = min(
    env_int("TFL_OUTBOUND_RATE_LIMIT_PER_MIN", TFL_MAX_RATE_LIMIT_PER_MIN),
    TFL_MAX_RATE_LIMIT_PER_MIN,
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

APP_ENV = os.getenv("APP_ENV")
FLASK_ENV = os.getenv("FLASK_ENV")
DEBUG_FLAG = env_optional_bool("DEBUG")

REDIS_URL = os.getenv("REDIS_URL")
REDIS_PREFIX = os.getenv("REDIS_PREFIX", "timetable_proxy")
REDIS_LOCK_TTL_SEC = env_int("REDIS_LOCK_TTL_SEC", 15)

APP_HOST = os.getenv("APP_HOST", "127.0.0.1")
APP_PORT = env_int("APP_PORT", 5010)

TFL_LINE_ID_RE = re.compile(r"^[a-z0-9-]{2,32}$")
TFL_STOP_ID_RE = re.compile(r"^[A-Za-z0-9]{3,20}$")

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


class SlidingWindowLimiterLike(Protocol):
    def allow(self) -> Tuple[bool, int]:
        ...


class PerKeyLimiterLike(Protocol):
    def allow(self, key: str) -> Tuple[bool, int]:
        ...


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


REDIS_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retry = window
  if oldest[2] then
    retry = math.max(1, math.floor(window - (now - tonumber(oldest[2]))))
  end
  return {0, retry}
end
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, window + 1)
return {1, 0}
"""


class RedisSlidingWindowLimiter:
    def __init__(self, redis_client: Any, key: str, limit: int, window_sec: int) -> None:
        self.redis = redis_client
        self.key = key
        self.limit = max(1, limit)
        self.window_sec = max(1, window_sec)
        self._script = self.redis.register_script(REDIS_SLIDING_WINDOW_LUA)

    def allow(self) -> Tuple[bool, int]:
        now = time.time()
        member = f"{now}:{uuid.uuid4().hex}"
        allowed, retry_after = self._script(
            keys=[self.key],
            args=[now, self.window_sec, self.limit, member],
        )
        return bool(allowed), int(retry_after)


class RedisPerKeyLimiter:
    def __init__(self, redis_client: Any, key_prefix: str, limit: int, window_sec: int) -> None:
        self.redis = redis_client
        self.key_prefix = key_prefix
        self.limit = max(1, limit)
        self.window_sec = max(1, window_sec)
        self._script = self.redis.register_script(REDIS_SLIDING_WINDOW_LUA)

    def allow(self, key: str) -> Tuple[bool, int]:
        now = time.time()
        member = f"{now}:{uuid.uuid4().hex}"
        redis_key = f"{self.key_prefix}:{key}"
        allowed, retry_after = self._script(
            keys=[redis_key],
            args=[now, self.window_sec, self.limit, member],
        )
        return bool(allowed), int(retry_after)


class HybridSlidingWindowLimiter:
    def __init__(self, primary: Any, fallback: SlidingWindowLimiterLike) -> None:
        self.primary = primary
        self.fallback = fallback

    def allow(self) -> Tuple[bool, int]:
        try:
            return self.primary.allow()
        except Exception as exc:
            log.warning("Primary limiter failed, using fallback: %s", exc)
            return self.fallback.allow()


class HybridPerKeyLimiter:
    def __init__(self, primary: Any, fallback: PerKeyLimiterLike) -> None:
        self.primary = primary
        self.fallback = fallback

    def allow(self, key: str) -> Tuple[bool, int]:
        try:
            return self.primary.allow(key)
        except Exception as exc:
            log.warning("Primary limiter failed, using fallback: %s", exc)
            return self.fallback.allow(key)


_redis_client: Optional[Any] = None
_redis_lock = threading.Lock()


def redis_key(*parts: str) -> str:
    return ":".join([REDIS_PREFIX, *parts])


def get_redis_client() -> Optional[Any]:
    if not REDIS_URL:
        return None
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    with _redis_lock:
        if _redis_client is not None:
            return _redis_client
        try:
            redis_module: Any = cast(Any, importlib.import_module("redis"))
        except ImportError:
            log.warning("Redis URL set but redis package is missing; using in-memory cache.")
            return None
        try:
            _redis_client = redis_module.Redis.from_url(REDIS_URL, decode_responses=True)
        except Exception as exc:
            log.warning("Redis client init failed; using in-memory cache: %s", exc)
            _redis_client = None
        return _redis_client


def is_production_mode() -> bool:
    env_value = (APP_ENV or FLASK_ENV or "").strip().lower()
    if env_value in {"production", "prod"}:
        return True
    if DEBUG_FLAG is not None:
        return not DEBUG_FLAG
    return False


def get_configured_worker_count() -> Optional[int]:
    for name in ("WEB_CONCURRENCY", "GUNICORN_WORKERS"):
        raw = os.getenv(name)
        if not raw:
            continue
        try:
            count = int(raw)
        except ValueError as exc:
            raise RuntimeError(
                f"{name} must be a positive integer when running in production."
            ) from exc
        if count < 1:
            raise RuntimeError(f"{name} must be a positive integer when running in production.")
        return count
    return None


def is_redis_available() -> bool:
    client = get_redis_client()
    if client is None:
        return False
    try:
        client.ping()
    except Exception as exc:
        log.warning("Redis ping failed: %s", exc)
        return False
    return True


def enforce_production_compliance() -> None:
    if not is_production_mode():
        return
    worker_count = get_configured_worker_count()
    if worker_count is None:
        raise RuntimeError(
            "Production requires WEB_CONCURRENCY or GUNICORN_WORKERS. "
            "Set it to 1 or configure REDIS_URL for multi-worker deployments."
        )
    if worker_count > 1 and not is_redis_available():
        raise RuntimeError(
            "Multi-worker requires Redis for shared rate limiting/caching to stay within "
            "TfL global caps. Use REDIS_URL or run a single worker."
        )


def build_limiters() -> Tuple[PerKeyLimiterLike, SlidingWindowLimiterLike, SlidingWindowLimiterLike]:
    fallback_api = PerKeyLimiter(API_RATE_LIMIT_PER_MIN, RATE_LIMIT_WINDOW_SEC)
    fallback_rtt = SlidingWindowLimiter(RTT_OUTBOUND_RATE_LIMIT_PER_MIN, RATE_LIMIT_WINDOW_SEC)
    fallback_tfl = SlidingWindowLimiter(TFL_OUTBOUND_RATE_LIMIT_PER_MIN, RATE_LIMIT_WINDOW_SEC)
    redis_client = get_redis_client()
    if redis_client is None:
        return fallback_api, fallback_rtt, fallback_tfl

    api = HybridPerKeyLimiter(
        RedisPerKeyLimiter(
            redis_client, redis_key("rl", "api"), API_RATE_LIMIT_PER_MIN, RATE_LIMIT_WINDOW_SEC
        ),
        fallback_api,
    )
    rtt = HybridSlidingWindowLimiter(
        RedisSlidingWindowLimiter(
            redis_client,
            redis_key("rl", "rtt"),
            RTT_OUTBOUND_RATE_LIMIT_PER_MIN,
            RATE_LIMIT_WINDOW_SEC,
        ),
        fallback_rtt,
    )
    tfl = HybridSlidingWindowLimiter(
        RedisSlidingWindowLimiter(
            redis_client,
            redis_key("rl", "tfl"),
            TFL_OUTBOUND_RATE_LIMIT_PER_MIN,
            RATE_LIMIT_WINDOW_SEC,
        ),
        fallback_tfl,
    )
    return api, rtt, tfl


_hhy_cache: Dict[str, Tuple[Optional[Tuple[str, ...]], float]] = {}
_hhy_lock = threading.Lock()

_trains_cache: Optional[CacheEntry] = None
_trains_lock = threading.Lock()
_trains_refreshing = False

_tfl_cache: Dict[str, CacheEntry] = {}
_tfl_lock = threading.Lock()
_tfl_refreshing: set[str] = set()

enforce_production_compliance()
api_limiter, rtt_outbound_limiter, tfl_outbound_limiter = build_limiters()

app = Flask(__name__)
if TRUST_PROXY_HEADERS:
    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1
    )

_session_local = threading.local()


def get_session() -> requests.Session:
    sess = getattr(_session_local, "session", None)
    if sess is None:
        sess = requests.Session()
        _session_local.session = sess
    return sess


def redis_cache_key(kind: str, suffix: Optional[str] = None) -> str:
    if suffix:
        return redis_key("cache", kind, suffix)
    return redis_key("cache", kind)


def redis_lock_key(kind: str, suffix: Optional[str] = None) -> str:
    if suffix:
        return redis_key("lock", kind, suffix)
    return redis_key("lock", kind)


def redis_get_cache_entry(key: str) -> Optional[CacheEntry]:
    client = get_redis_client()
    if client is None:
        return None
    try:
        raw = client.get(key)
    except Exception as exc:
        log.warning("Redis read failed; using in-memory cache: %s", exc)
        return None
    if not raw:
        return None
    try:
        payload_obj = json.loads(raw)
    except ValueError:
        log.warning("Redis cache corrupted for key: %s", key)
        return None
    if not isinstance(payload_obj, dict):
        log.warning("Redis cache payload is not a dict for key: %s", key)
        return None
    payload = cast(Dict[str, Any], payload_obj)
    return CacheEntry(
        data=payload.get("data"),
        expires_at=float(payload.get("expires_at", 0)),
        stale_until=float(payload.get("stale_until", 0)),
        fetched_at=str(payload.get("fetched_at", "")),
        ttl_sec=int(payload.get("ttl_sec", 0)),
    )


def redis_set_cache_entry(key: str, entry: CacheEntry) -> None:
    client = get_redis_client()
    if client is None:
        return
    payload: Dict[str, Any] = {
        "data": entry.data,
        "expires_at": entry.expires_at,
        "stale_until": entry.stale_until,
        "fetched_at": entry.fetched_at,
        "ttl_sec": entry.ttl_sec,
    }
    ttl = max(1, int(entry.stale_until - time.time()))
    try:
        client.set(key, json.dumps(payload), ex=ttl)
    except Exception as exc:
        log.warning("Redis write failed; using in-memory cache: %s", exc)


def acquire_redis_lock(key: str) -> bool:
    client = get_redis_client()
    if client is None:
        return False
    try:
        return bool(client.set(key, "1", nx=True, ex=REDIS_LOCK_TTL_SEC))
    except Exception as exc:
        log.warning("Redis lock failed; continuing without lock: %s", exc)
        return False


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


def is_valid_tfl_line_id(value: str) -> bool:
    return bool(TFL_LINE_ID_RE.fullmatch(value))


def is_valid_tfl_stop_id(value: str) -> bool:
    return bool(TFL_STOP_ID_RE.fullmatch(value))


def request_json(
    url: str,
    *,
    auth: Optional[Tuple[str, str]] = None,
    params: Optional[Dict[str, str]] = None,
    timeout: Optional[Tuple[float, float]] = None,
    limiter: Optional[SlidingWindowLimiterLike] = None,
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
            resp = get_session().get(
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
    resp.headers.setdefault(
        "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
    )
    resp.headers.setdefault(
        "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
    )

    if ENABLE_HSTS and request.is_secure:
        resp.headers.setdefault(
            "Strict-Transport-Security",
            f"max-age={HSTS_MAX_AGE_SEC}; includeSubDomains",
        )
    return resp


# Via cache bounds protect memory under request spikes.
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
    now = time.monotonic()
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
        log.warning("Via check failed: %s", exc)
        via = None
    except Exception as exc:
        log.warning("Via check failed: %s", exc)
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


def fetch_trains_entry(now_expiry: float, now_mono: float) -> CacheEntry:
    data, headers = rtt_get_json("/json/search/AAP")
    ttl_sec = compute_ttl(headers, TRAIN_CACHE_MIN_TTL_SEC)

    prune_hhy_cache(now_mono)

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
        expires_at=now_expiry + ttl_sec,
        stale_until=now_expiry + ttl_sec + TRAIN_CACHE_STALE_SEC,
        fetched_at=payload["fetched_at"],
        ttl_sec=ttl_sec,
    )


def fetch_trains() -> CacheEntry:
    now = time.monotonic()
    return fetch_trains_entry(now, now)


def refresh_trains_async_memory() -> None:
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


def get_trains_cached_memory() -> CacheEntry:
    global _trains_cache, _trains_refreshing
    now = time.monotonic()
    with _trains_lock:
        entry = _trains_cache
        if entry and now < entry.expires_at:
            return entry
        if entry and now < entry.stale_until:
            if not _trains_refreshing:
                _trains_refreshing = True
                threading.Thread(target=refresh_trains_async_memory, daemon=True).start()
            return entry

    entry = fetch_trains()
    with _trains_lock:
        _trains_cache = entry
    return entry


def refresh_trains_async_redis(cache_key: str, lock_key: str) -> None:
    try:
        entry = fetch_trains_entry(time.time(), time.monotonic())
        redis_set_cache_entry(cache_key, entry)
    except Exception as exc:
        log.warning("Train refresh failed: %s", exc)
    finally:
        client = get_redis_client()
        if client is not None:
            try:
                client.delete(lock_key)
            except Exception as exc:
                log.warning("Redis lock release failed: %s", exc)


def get_trains_cached_redis() -> CacheEntry:
    cache_key = redis_cache_key("trains")
    lock_key = redis_lock_key("trains")
    now = time.time()
    entry = redis_get_cache_entry(cache_key)
    if entry and now < entry.expires_at:
        return entry
    if entry and now < entry.stale_until:
        if acquire_redis_lock(lock_key):
            threading.Thread(
                target=refresh_trains_async_redis, args=(cache_key, lock_key), daemon=True
            ).start()
        return entry
    entry = fetch_trains_entry(now, time.monotonic())
    redis_set_cache_entry(cache_key, entry)
    return entry


def get_trains_cached() -> CacheEntry:
    if get_redis_client() is not None:
        return get_trains_cached_redis()
    return get_trains_cached_memory()


def fetch_tfl_entry(now_expiry: float, path: str) -> CacheEntry:
    data, headers = tfl_get_json(path)
    ttl_sec = compute_ttl(headers, TFL_CACHE_MIN_TTL_SEC)
    payload: Dict[str, Any] = {
        "data": data if data is not None else [],
        "fetched_at": utc_now_iso(),
        "cache_ttl_sec": ttl_sec,
    }
    return CacheEntry(
        data=payload,
        expires_at=now_expiry + ttl_sec,
        stale_until=now_expiry + ttl_sec + TFL_CACHE_STALE_SEC,
        fetched_at=payload["fetched_at"],
        ttl_sec=ttl_sec,
    )


def fetch_tfl(path: str) -> CacheEntry:
    return fetch_tfl_entry(time.monotonic(), path)


def refresh_tfl_async_memory(cache_key: str, path: str) -> None:
    try:
        entry = fetch_tfl(path)
        with _tfl_lock:
            _tfl_cache[cache_key] = entry
    except Exception as exc:
        log.warning("TfL refresh failed: %s", exc)
    finally:
        with _tfl_lock:
            _tfl_refreshing.discard(cache_key)


def get_tfl_cached_memory(cache_key: str, path: str) -> CacheEntry:
    now = time.monotonic()
    with _tfl_lock:
        entry = _tfl_cache.get(cache_key)
        if entry and now < entry.expires_at:
            return entry
        if entry and now < entry.stale_until:
            if cache_key not in _tfl_refreshing:
                _tfl_refreshing.add(cache_key)
                threading.Thread(
                    target=refresh_tfl_async_memory, args=(cache_key, path), daemon=True
                ).start()
            return entry

    entry = fetch_tfl(path)
    with _tfl_lock:
        _tfl_cache[cache_key] = entry
    return entry


def refresh_tfl_async_redis(cache_key: str, path: str, lock_key: str) -> None:
    try:
        entry = fetch_tfl_entry(time.time(), path)
        redis_set_cache_entry(redis_cache_key("tfl", cache_key), entry)
    except Exception as exc:
        log.warning("TfL refresh failed: %s", exc)
    finally:
        client = get_redis_client()
        if client is not None:
            try:
                client.delete(lock_key)
            except Exception as exc:
                log.warning("Redis lock release failed: %s", exc)


def get_tfl_cached_redis(cache_key: str, path: str) -> CacheEntry:
    cache_key_full = redis_cache_key("tfl", cache_key)
    lock_key = redis_lock_key("tfl", cache_key)
    now = time.time()
    entry = redis_get_cache_entry(cache_key_full)
    if entry and now < entry.expires_at:
        return entry
    if entry and now < entry.stale_until:
        if acquire_redis_lock(lock_key):
            threading.Thread(
                target=refresh_tfl_async_redis, args=(cache_key, path, lock_key), daemon=True
            ).start()
        return entry
    entry = fetch_tfl_entry(now, path)
    redis_set_cache_entry(cache_key_full, entry)
    return entry


def get_tfl_cached(cache_key: str, path: str) -> CacheEntry:
    if get_redis_client() is not None:
        return get_tfl_cached_redis(cache_key, path)
    return get_tfl_cached_memory(cache_key, path)


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

    if not is_valid_tfl_stop_id(stop_id):
        return error_response(
            400,
            "invalid_parameter",
            "Invalid stop_id",
            empty_key="data",
        )

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

    line_id = line_id.lower()
    if not is_valid_tfl_line_id(line_id):
        return error_response(
            400,
            "invalid_parameter",
            "Invalid line_id",
            empty_key="data",
        )
    if not is_valid_tfl_stop_id(stop_id):
        return error_response(
            400,
            "invalid_parameter",
            "Invalid stop_id",
            empty_key="data",
        )

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
