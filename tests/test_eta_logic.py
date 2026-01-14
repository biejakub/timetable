from pathlib import Path
import re


ETA_WALK_MIN = {"train": 8, "tube": 12, "bus": 4}
ETA_BUFFER_MIN = {"train": 4, "tube": 4, "bus": 2}
ETA_RED_SEC = 60
ETA_BLUE_MIN = 20


def get_eta_class(eta_sec, transport_type):
    if eta_sec is None:
        return "eta-blue"
    if eta_sec < ETA_RED_SEC:
        return "eta-red"
    if eta_sec >= ETA_BLUE_MIN * 60:
        return "eta-blue"
    walk_sec = ETA_WALK_MIN[transport_type] * 60
    buffer_sec = ETA_BUFFER_MIN[transport_type] * 60
    if eta_sec >= walk_sec + buffer_sec:
        return "eta-green"
    return "eta-yellow"


def test_eta_class_boundaries():
    cases = [
        ("train", 8, 4),
        ("tube", 12, 4),
        ("bus", 4, 2),
    ]
    for transport, walk_min, buffer_min in cases:
        walk_sec = walk_min * 60
        buffer_sec = buffer_min * 60
        assert get_eta_class(59, transport) == "eta-red"
        assert get_eta_class(60, transport) == "eta-yellow"
        assert get_eta_class(walk_sec - 1, transport) == "eta-yellow"
        assert get_eta_class(walk_sec, transport) == "eta-yellow"
        assert get_eta_class(walk_sec + buffer_sec - 1, transport) == "eta-yellow"
        assert get_eta_class(walk_sec + buffer_sec, transport) == "eta-green"
        assert get_eta_class(20 * 60 - 1, transport) == "eta-green"
        assert get_eta_class(20 * 60, transport) == "eta-blue"


def test_frontend_eta_constants():
    html = Path("TfL.html").read_text(encoding="utf-8")
    assert "function getEtaClass" in html
    assert "eta-badge" in html
    assert re.search(r"ETA_WALK_MIN\\s*=\\s*\\{[^}]*train\\s*:\\s*8", html)
    assert re.search(r"ETA_WALK_MIN\\s*=\\s*\\{[^}]*tube\\s*:\\s*12", html)
    assert re.search(r"ETA_WALK_MIN\\s*=\\s*\\{[^}]*bus\\s*:\\s*4", html)
    assert "ETA_BUFFER_MIN = { train: 4, tube: 4, bus: 2 }" in html
    assert "ETA_RED_SEC = 60" in html
    assert "ETA_BLUE_MIN = 20" in html
