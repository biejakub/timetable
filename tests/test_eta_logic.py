from pathlib import Path
import re


ETA_WALK_MIN = {"train": 8, "tube": 12, "bus": 4}
ETA_BUFFER_MIN = {"train": 4, "tube": 4, "bus": 2}
ETA_RED_SEC = 60
ETA_BLUE_MIN = 20


def get_eta_class(eta_sec, transport_type):
    if eta_sec is None:
        return "blue"
    if eta_sec < ETA_RED_SEC:
        return "red"
    if eta_sec >= ETA_BLUE_MIN * 60:
        return "blue"
    walk_sec = ETA_WALK_MIN[transport_type] * 60
    buffer_sec = ETA_BUFFER_MIN[transport_type] * 60
    if eta_sec >= walk_sec + buffer_sec:
        return "green"
    return "yellow"


def test_eta_class_boundaries():
    assert get_eta_class(59, "train") == "red"
    assert get_eta_class(8 * 60, "train") == "yellow"
    assert get_eta_class((8 + 4) * 60, "train") == "green"
    assert get_eta_class(20 * 60, "train") == "blue"

    assert get_eta_class(4 * 60, "bus") == "yellow"
    assert get_eta_class((4 + 2) * 60, "bus") == "green"
    assert get_eta_class(20 * 60, "bus") == "blue"

    assert get_eta_class(12 * 60, "tube") == "yellow"
    assert get_eta_class((12 + 4) * 60, "tube") == "green"


def test_frontend_eta_constants():
    html = Path("TfL.html").read_text(encoding="utf-8")
    assert "function getEtaClass" in html
    assert re.search(r"ETA_WALK_MIN\\s*=\\s*\\{[^}]*train\\s*:\\s*8", html)
    assert re.search(r"ETA_WALK_MIN\\s*=\\s*\\{[^}]*tube\\s*:\\s*12", html)
    assert re.search(r"ETA_WALK_MIN\\s*=\\s*\\{[^}]*bus\\s*:\\s*4", html)
    assert "ETA_BUFFER_MIN = { train: 4, tube: 4, bus: 2 }" in html
    assert "ETA_RED_SEC = 60" in html
    assert "ETA_BLUE_MIN = 20" in html
