import importlib


def load_module(monkeypatch, **env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import rtt_proxy
    return importlib.reload(rtt_proxy)


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
