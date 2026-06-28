"""Scan orchestrator — ties guardrail + sandbox + tools + AI analysis together."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import ai_analyzer
from .ai_analyzer import Finding
from .guardrail import Guardrail, GuardrailError
from .tools import PROFILES, REGISTRY, Observation


@dataclass
class ScanStep:
    tool_key: str
    target: str


@dataclass
class ScanResult:
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    correlation: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class Orchestrator:
    def __init__(self, guardrail: Guardrail, sandbox, per_tool_timeout: int = 300,
                 ai_provider: str | None = None, ai_ollama_model: str | None = None):
        self.guard = guardrail
        self.sandbox = sandbox
        self.timeout = per_tool_timeout
        self.ai_provider = ai_provider
        self.ai_ollama_model = ai_ollama_model

    def run(self, plan: list[ScanStep]) -> ScanResult:
        result = ScanResult()
        for step in plan:
            tool = REGISTRY.get(step.tool_key)
            if tool is None:
                result.errors.append(f"unknown tool {step.tool_key}")
                continue
            argv = tool.build(step.target)
            try:
                self.guard.authorize(tool.binary, argv, [step.target])
            except GuardrailError as exc:
                result.errors.append(f"{step.tool_key} {step.target}: DENIED {exc}")
                continue
            timeout = min(self.timeout, int(self.guard.budget.remaining_seconds()) or self.timeout)
            ex = self.sandbox.run(argv, timeout=timeout)
            self.guard.record(tool.binary, exit_code=ex.exit_code,
                              summary=self.guard.sanitize(ex.stdout[:300]))
            # Surface a missing binary so a tool never silently no-ops. The sandbox
            # sets tool_missing only when the binary was never launched — a tool that
            # ran and exited 127 is a real failure, not a missing tool, and is left to
            # parse/observe normally. (Don't match 'not found' in output — tools like
            # snmpwalk legitimately print that for empty results.)
            if ex.tool_missing:
                result.errors.append(f"{step.tool_key}: tool unavailable in sandbox (not installed)")
            obs = tool.parse(self.guard.sanitize(ex.stdout), step.target)
            result.observations.extend(obs)

        # Read-only enrichment passes (in-process inference, no new packets):
        # shadow-AI discovery, segmentation validation, credential-exposure detection.
        from .recon import cred_exposure, segmentation, shadow_ai
        snapshot = list(result.observations)
        result.observations.extend(shadow_ai.classify(snapshot))
        result.observations.extend(segmentation.validate(snapshot))
        result.observations.extend(
            cred_exposure.detect(snapshot, sanitize=self.guard.sanitize))

        # AI analysis: cheap triage, then strong correlation (provider/model selectable)
        result.findings = ai_analyzer.triage(
            result.observations, budget=self.guard.budget,
            provider=self.ai_provider, ollama_model=self.ai_ollama_model)
        result.correlation = ai_analyzer.correlate(
            result.findings, budget=self.guard.budget,
            provider=self.ai_provider, ollama_model=self.ai_ollama_model)

        # Deterministic chain reasoning augments correlation with proof-annotated paths.
        from .agent import chains
        derived = chains.derive_chains(result.findings)
        if derived:
            existing = result.correlation.setdefault("attack_paths", [])
            names = {p.get("name") for p in existing}
            for c in derived:
                if c.name not in names:
                    existing.append({"name": c.name, "severity": c.severity,
                                     "steps": c.steps, "mitre_tactics": c.mitre_tactics,
                                     "proof": c.proof, "assets": c.assets,
                                     "business_risk": c.business_risk})
        self.guard.audit.write({"event": "scan_complete",
                                "obs": len(result.observations),
                                "findings": len(result.findings),
                                "usd": round(self.guard.budget.usd, 4)})
        return result


def default_plan(targets: list[str], profile: str = "default") -> list[ScanStep]:
    """Build a read-only scan plan from a named profile across validated targets."""
    keys = PROFILES.get(profile, PROFILES["default"])
    return [ScanStep(k, t) for t in targets for k in keys]
