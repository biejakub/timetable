import importlib
import sys

import pytest


_ENV_KEYS = [
    "APP_ENV",
    "FLASK_ENV",
    "DEBUG",
    "WEB_CONCURRENCY",
    "GUNICORN_WORKERS",
    "REDIS_URL",
    "RTT_USER",
    "RTT_PASS",
    "TFL_APP_ID",
    "TFL_APP_KEY",
    "TFL_OUTBOUND_RATE_LIMIT_PER_MIN",
    "CORS_ALLOWED_ORIGINS",
]


def load_module(monkeypatch, **env):
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    sys.modules.pop("rtt_proxy", None)
    import rtt_proxy
    return importlib.reload(rtt_proxy)


def import_module(monkeypatch, **env):
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    sys.modules.pop("rtt_proxy", None)
    return importlib.import_module("rtt_proxy")


def test_cors_allow_deny(monkeypatch):
    mod = load_module(
        monkeypatch,
        RTT_USER="user",
        RTT_PASS="pass",
        CORS_ALLOWED_ORIGINS="http://allowed.test",
    )
    monkeypatch.setattr(mod, "rtt_get_json", lambda path: ({"services": []}, {}))

    client = mod.app.test_client()
    resp = client.get("/api/trains", headers={"Origin": "http://allowed.test"})
    assert resp.headers.get("Access-Control-Allow-Origin") == "http://allowed.test"

    resp = client.get("/api/trains", headers={"Origin": "http://blocked.test"})
    assert "Access-Control-Allow-Origin" not in resp.headers


def test_rate_limit(monkeypatch):
    mod = load_module(monkeypatch, RTT_USER="user", RTT_PASS="pass", API_RATE_LIMIT_PER_MIN="1")
    monkeypatch.setattr(mod, "rtt_get_json", lambda path: ({"services": []}, {}))

    client = mod.app.test_client()
    assert client.get("/api/trains").status_code == 200

    resp = client.get("/api/trains")
    assert resp.status_code == 429
    data = resp.get_json()
    assert data["error"]["code"] == "rate_limited"


def test_upstream_error(monkeypatch):
    mod = load_module(monkeypatch, RTT_USER="user", RTT_PASS="pass")

    def boom(path):
        raise mod.UpstreamError(503, "RTT upstream error")

    monkeypatch.setattr(mod, "rtt_get_json", boom)

    client = mod.app.test_client()
    resp = client.get("/api/trains")
    assert resp.status_code == 502
    data = resp.get_json()
    assert data["services"] == []
    assert data["error"]["code"] == "upstream_error"


def test_secrets_not_leaked(monkeypatch):
    mod = load_module(monkeypatch, RTT_USER="secret_user", RTT_PASS="secret_pass")

    def boom(path):
        raise mod.UpstreamError(503, "RTT upstream error")

    monkeypatch.setattr(mod, "rtt_get_json", boom)

    client = mod.app.test_client()
    resp = client.get("/api/trains")
    body = resp.get_data(as_text=True)
    assert "secret_user" not in body
    assert "secret_pass" not in body


def test_tfl_validation(monkeypatch):
    mod = load_module(monkeypatch)
    client = mod.app.test_client()

    resp = client.get("/api/tfl/stop/invalid!id/arrivals")
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["error"]["code"] == "invalid_parameter"

    resp = client.get("/api/tfl/line/invalid!/arrivals/940GZZLUBDS")
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["error"]["code"] == "invalid_parameter"


def test_production_requires_worker_count(monkeypatch):
    with pytest.raises(RuntimeError, match="WEB_CONCURRENCY|GUNICORN_WORKERS"):
        import_module(monkeypatch, APP_ENV="production")


def test_production_multiworker_requires_redis(monkeypatch):
    with pytest.raises(RuntimeError, match="Multi-worker requires Redis"):
        import_module(monkeypatch, APP_ENV="production", WEB_CONCURRENCY="2")


def test_production_single_worker_without_redis_ok(monkeypatch):
    mod = load_module(monkeypatch, APP_ENV="production", WEB_CONCURRENCY="1")
    assert mod.is_production_mode() is True
    assert mod.get_configured_worker_count() == 1


def test_tfl_outbound_cap_anonymous(monkeypatch):
    mod = load_module(monkeypatch, TFL_OUTBOUND_RATE_LIMIT_PER_MIN="1000")
    assert mod.TFL_OUTBOUND_RATE_LIMIT_PER_MIN == 50


def test_tfl_outbound_cap_with_keys(monkeypatch):
    mod = load_module(
        monkeypatch,
        TFL_APP_ID="id",
        TFL_APP_KEY="key",
        TFL_OUTBOUND_RATE_LIMIT_PER_MIN="1000",
    )
    assert mod.TFL_OUTBOUND_RATE_LIMIT_PER_MIN == 500
