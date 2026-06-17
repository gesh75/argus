"""Module 1 — Web / API recon (read-only foothold discovery).

Internal networks leak through unauthenticated DevOps tooling, exposed VCS metadata,
config files, and undocumented API surfaces. This collector probes a CURATED, bounded
list of high-signal paths with read-only GET/HEAD only — no fuzzing storms, no auth,
no writes. Each hit becomes an Observation the AI engine triages.

Safety:
  * GET/HEAD only; bounded path list; per-request timeout; capped body read.
  * Transport is injectable (HttpTransport for live, FixtureTransport for offline tests),
    so the module is fully deterministic under test and never depends on a live target.
  * The Layer-7 sanitizer redacts any secret echoed in a matched body before it is stored.
"""
from __future__ import annotations

import urllib.request
from dataclasses import dataclass
from typing import Callable, Protocol

from ..tools import Observation

# Curated high-signal paths. (path, classification, why-it-matters)
SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    ("/.env", "secret", "environment file — often DB creds/API keys"),
    ("/.git/config", "vcs", "exposed git metadata — source/history disclosure"),
    ("/.git/HEAD", "vcs", "exposed git repo"),
    ("/config.json", "config", "application config — may hold secrets"),
    ("/appsettings.json", "config", ".NET config — connection strings"),
    ("/wp-config.php.bak", "secret", "WordPress config backup"),
    ("/.aws/credentials", "secret", "AWS credentials file"),
    ("/server-status", "info", "Apache mod_status — internal request disclosure"),
    ("/actuator/env", "devops", "Spring Boot actuator env — secrets/property dump"),
    ("/actuator/health", "devops", "Spring Boot actuator exposed"),
    ("/admin", "admin", "admin portal"),
    ("/admin/login", "admin", "admin login portal"),
    ("/.DS_Store", "info", "directory listing leak"),
    ("/phpinfo.php", "info", "phpinfo() — full environment disclosure"),
]

# API-documentation surfaces — finding these maps the unauthenticated API attack surface.
API_DOC_PATHS: list[tuple[str, str, str]] = [
    ("/swagger.json", "api-doc", "OpenAPI/Swagger spec — full API surface"),
    ("/swagger/v1/swagger.json", "api-doc", "Swagger spec"),
    ("/openapi.json", "api-doc", "OpenAPI spec"),
    ("/api-docs", "api-doc", "API documentation"),
    ("/v2/api-docs", "api-doc", "Springfox API docs"),
    ("/graphql", "api-doc", "GraphQL endpoint — introspection may be open"),
]

ALL_PATHS = SENSITIVE_PATHS + API_DOC_PATHS

# Bodies that indicate a *real* hit vs a generic 200 SPA/login page.
_POSITIVE_HINTS = {
    "secret": ("=", "key", "password", "secret", "token"),
    "vcs": ("[core]", "ref:", "repositoryformatversion"),
    "config": ("{", "connectionstring", "password", "apikey"),
    "devops": ("{", "profiles", "propertysources", "status"),
    "api-doc": ("swagger", "openapi", "\"paths\"", "__schema", "graphql"),
    "info": ("apache", "php version", "<directory", "ds_store"),
    "admin": ("login", "admin", "password", "username"),
}


@dataclass(frozen=True)
class HttpResult:
    status: int
    body: str
    server: str = ""


class Transport(Protocol):
    def get(self, url: str, timeout: int) -> HttpResult: ...


class HttpTransport:
    """Live read-only HTTP. GET only, capped body, follows up to a few redirects."""

    def __init__(self, max_body: int = 4096):
        self.max_body = max_body

    def get(self, url: str, timeout: int) -> HttpResult:
        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": "ECP-Aegis-Recon/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                body = resp.read(self.max_body).decode("utf-8", "replace")
                return HttpResult(resp.status, body, resp.headers.get("Server", ""))
        except urllib.error.HTTPError as exc:  # 401/403/404 still informative
            body = b""
            try:
                body = exc.read(self.max_body)
            except Exception:  # noqa: BLE001
                pass
            return HttpResult(exc.code, body.decode("utf-8", "replace"),
                              exc.headers.get("Server", "") if exc.headers else "")
        except Exception:  # noqa: BLE001 — connection refused/timeout = no service
            return HttpResult(0, "")


class SandboxTransport:
    """Read-only HTTP via curl inside a sandbox container — reaches `internal:` lab nets
    the host can't route to. Mirrors how host/AD collectors run through the sandbox."""

    def __init__(self, sandbox, max_body: int = 4096):
        self.sandbox = sandbox
        self.max_body = max_body

    def get(self, url: str, timeout: int) -> HttpResult:
        argv = ["curl", "-s", "-i", "-m", str(timeout), "-A",
                "ECP-Aegis-Recon/1.0", url]
        ex = self.sandbox.run(argv, timeout=timeout + 3)
        return self._parse(ex.stdout)

    def _parse(self, raw: str) -> HttpResult:
        if not raw:
            return HttpResult(0, "")
        head, _, body = raw.partition("\r\n\r\n")
        if not body:
            head, _, body = raw.partition("\n\n")
        status, server = 0, ""
        for line in head.splitlines():
            if line.startswith("HTTP/"):
                parts = line.split()
                if len(parts) > 1 and parts[1].isdigit():
                    status = int(parts[1])
            elif line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
        return HttpResult(status, body[:self.max_body], server)


class FixtureTransport:
    """Offline transport for tests: map of url-suffix -> HttpResult."""

    def __init__(self, responses: dict[str, HttpResult]):
        self._r = responses

    def get(self, url: str, timeout: int) -> HttpResult:
        for suffix, res in self._r.items():
            if url.endswith(suffix):
                return res
        return HttpResult(404, "")


def _is_real_hit(classification: str, res: HttpResult) -> bool:
    """A hit is real only if status is 200/401/403 AND the body looks like the thing."""
    if res.status not in (200, 401, 403):
        return False
    if res.status in (401, 403) and classification in ("admin", "devops", "api-doc"):
        return True  # protected-but-present is itself a useful surface finding
    body = res.body.lower()
    hints = _POSITIVE_HINTS.get(classification, ())
    return any(h in body for h in hints) if hints else res.status == 200


def probe(target: str, *, transport: Transport | None = None, scheme: str = "http",
          port: int | None = None, paths: list[tuple[str, str, str]] | None = None,
          timeout: int = 5) -> list[Observation]:
    """Read-only probe of curated paths on one target. Returns Observations."""
    tx = transport or HttpTransport()
    base = f"{scheme}://{target}" + (f":{port}" if port else "")
    out: list[Observation] = []
    for path, classification, why in (paths or ALL_PATHS):
        res = tx.get(base + path, timeout)
        if not _is_real_hit(classification, res):
            continue
        kind = "exposure" if classification in ("secret", "vcs", "config",
                                                "devops", "info") else "web"
        tag = "[PROTECTED] " if res.status in (401, 403) else ""
        srv = f" ({res.server})" if res.server else ""
        out.append(Observation(
            target, kind,
            f"{tag}{classification}: {base}{path} -> HTTP {res.status}{srv} — {why}",
            res.body[:200]))
    return out


class WebReconOrchestrator:
    """Authorize target scope, probe read-only, then run AI triage/correlation."""

    CATALOG = {"web_recon"}

    def __init__(self, guardrail, transport: Transport | None = None,
                 ai_provider: str | None = None, ai_ollama_model: str | None = None):
        self.guard = guardrail
        self.transport = transport
        self.ai_provider = ai_provider
        self.ai_ollama_model = ai_ollama_model

    def run(self, target: str, *, scheme: str = "http", port: int | None = None):
        from .. import ai_analyzer
        from ..orchestrator import ScanResult
        result = ScanResult()
        try:
            self.guard.authorize_host(target, "web_recon", self.CATALOG)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"web_recon {target}: DENIED {exc}")
            return result
        obs = probe(target, transport=self.transport, scheme=scheme, port=port)
        # Sanitize every stored detail/raw (Layer 7) before it leaves the collector.
        result.observations = [
            Observation(o.asset, o.kind, self.guard.sanitize(o.detail),
                        self.guard.sanitize(o.raw)) for o in obs]
        self.guard.record("web_recon", exit_code=0,
                          summary=f"{len(result.observations)} web exposures on {target}")
        result.findings = ai_analyzer.triage(
            result.observations, budget=self.guard.budget,
            provider=self.ai_provider, ollama_model=self.ai_ollama_model)
        result.correlation = ai_analyzer.correlate(
            result.findings, budget=self.guard.budget,
            provider=self.ai_provider, ollama_model=self.ai_ollama_model)
        return result
