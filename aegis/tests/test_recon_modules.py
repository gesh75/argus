"""Modules 4 & 5 — shadow-AI discovery and segmentation validator (offline)."""
import os

os.environ.setdefault("PENTEST_AUDIT_HMAC_KEY", "test")

from aegis.recon import segmentation, shadow_ai
from aegis.tools import Observation


# ---- Module 4: shadow AI ----------------------------------------------------
def test_ollama_port_detected():
    obs = [Observation("172.30.0.20", "service", "11434/tcp http")]
    out = shadow_ai.classify(obs)
    assert any("Ollama" in o.detail and o.kind == "ai-service" for o in out)


def test_jupyter_banner_detected():
    obs = [Observation("172.30.0.21", "web", "HTTP 200 :: Jupyter Notebook")]
    out = shadow_ai.classify(obs)
    assert any("Jupyter" in o.detail for o in out)


def test_non_ai_service_ignored():
    obs = [Observation("172.30.0.22", "service", "25/tcp smtp postfix")]
    assert shadow_ai.classify(obs) == []


def test_shadow_ai_dedupes_same_service():
    obs = [Observation("172.30.0.20", "service", "11434/tcp http"),
           Observation("172.30.0.20", "web", "HTTP 200 :: ollama")]
    out = shadow_ai.classify(obs)
    assert len([o for o in out if o.asset == "172.30.0.20"]) == 1


# ---- Module 5: segmentation -------------------------------------------------
def test_database_plane_flagged():
    obs = [Observation("172.30.0.30", "service", "3306/tcp mysql")]
    out = segmentation.validate(obs)
    assert out and out[0].kind == "segmentation" and "database" in out[0].detail


def test_management_plane_flagged():
    obs = [Observation("172.30.0.31", "service", "3389/tcp ms-wbt-server")]
    out = segmentation.validate(obs)
    assert any("management" in o.detail for o in out)


def test_benign_web_port_not_flagged():
    obs = [Observation("172.30.0.32", "service", "80/tcp http")]
    assert segmentation.validate(obs) == []


def test_segmentation_matrix_groups_by_asset():
    obs = [Observation("10.0.0.5", "service", "3306/tcp mysql"),
           Observation("10.0.0.5", "service", "22/tcp ssh"),
           Observation("10.0.0.6", "service", "389/tcp ldap")]
    m = segmentation.matrix(obs)
    assert set(m["10.0.0.5"]) >= {"database", "management"}
    assert m["10.0.0.6"] == ["directory"]
