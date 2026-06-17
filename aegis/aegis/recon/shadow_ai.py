"""Module 4 — Shadow-AI discovery (read-only).

Internal corporate networks increasingly run undocumented local LLMs, vector DBs,
notebooks, and agent UIs — the modern soft underbelly. This module classifies such
services from already-observed ports/banners (no new packets needed) AND offers an
optional read-only banner probe for confirmation.

Read-only: classification over existing Observations + optional GET to a known health
path. No prompt injection, no model interaction beyond an unauthenticated banner.
"""
from __future__ import annotations

from ..tools import Observation

# port -> (service, why-it-matters). Common default ports of local AI deployments.
AI_PORT_SIGNATURES: dict[int, tuple[str, str]] = {
    11434: ("Ollama", "local LLM server — open model pull/run, no auth by default"),
    1234: ("LM Studio", "local LLM server API"),
    8000: ("vLLM / OpenAI-compat", "model server (also generic) — check /v1/models"),
    8001: ("vLLM", "model server"),
    7860: ("Gradio", "ML demo UI — often unauthenticated"),
    8888: ("Jupyter", "notebook server — RCE if token disabled"),
    6006: ("TensorBoard", "training dashboard"),
    8501: ("Streamlit", "data/ML app UI"),
    6333: ("Qdrant", "vector database"),
    8108: ("Typesense", "search/vector engine"),
    19530: ("Milvus", "vector database"),
    3000: ("Open WebUI / Grafana", "LLM chat UI or dashboard — disambiguate via banner"),
}

# Substrings in a service banner/detail that confirm an AI service regardless of port.
AI_BANNER_HINTS = (
    ("ollama", "Ollama"), ("jupyter", "Jupyter"), ("gradio", "Gradio"),
    ("text-generation", "TGI"), ("vllm", "vLLM"), ("tensorboard", "TensorBoard"),
    ("qdrant", "Qdrant"), ("milvus", "Milvus"), ("streamlit", "Streamlit"),
    ("open-webui", "Open WebUI"), ("/v1/models", "OpenAI-compat LLM"),
)


def _port_of(detail: str) -> int | None:
    # service observations look like "11434/tcp http ..." — pull the leading port.
    head = detail.strip().split("/", 1)[0]
    return int(head) if head.isdigit() else None


def classify(observations: list[Observation]) -> list[Observation]:
    """Derive ai-service Observations from existing port/service/web observations."""
    out: list[Observation] = []
    for o in observations:
        if o.kind not in ("service", "port", "web", "exposure"):
            continue
        low = (o.detail + " " + o.raw).lower()
        hit: tuple[str, str] | None = None
        for sub, name in AI_BANNER_HINTS:
            if sub in low:
                hit = (name, "AI/ML service banner match")
                break
        if hit is None:
            port = _port_of(o.detail)
            if port in AI_PORT_SIGNATURES:
                hit = AI_PORT_SIGNATURES[port]
        if hit:
            out.append(Observation(o.asset, "ai-service",
                                   f"{hit[0]} on {o.asset} — {hit[1]}", o.detail[:160]))
    return _dedupe(out)


def _dedupe(obs: list[Observation]) -> list[Observation]:
    seen: set[tuple[str, str]] = set()
    keep: list[Observation] = []
    for o in obs:
        k = (o.asset, o.detail.split(" on ")[0])
        if k not in seen:
            seen.add(k)
            keep.append(o)
    return keep
