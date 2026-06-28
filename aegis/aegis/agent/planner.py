"""Module 3b — Agentic planner loop (read-only, guardrail-bounded).

The loop that makes Aegis *agentic*: observe -> decide the next read-only action -> have the
guardrail authorize it -> collect -> re-plan, until a stop condition. The agent only ever
PROPOSES; the Guardrail disposes — every chosen action is re-authorized, so the loop can
never escape scope, arm an exploit, or touch a denied tool no matter what it "reasons".

Decision policy is deterministic by default (evidence-driven heuristics) so it is testable
and reproducible; an LLM can be slotted in to rank candidate next-actions, but it never
gains authority — its choice is still a profile key that must pass the guardrail.

Stop conditions (fail-safe): goal/no-new-evidence | depth cap | budget | empty candidate set.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..tools import PROFILES, Observation

# Which follow-up profile each evidence signal suggests (read-only profiles only).
# signal-substring -> profile key
NEXT_ACTION_RULES: list[tuple[tuple[str, ...], str]] = [
    (("http", "https", "web", "80/tcp", "443/tcp", "8080"), "web"),
    (("445/tcp", "139/tcp", "smb", "netbios"), "ad-smb"),
    (("161/tcp", "snmp"), "snmp"),
    (("443/tcp", "ssl", "tls"), "tls"),
    (("ldap", "389/tcp", "636/tcp"), "ad-smb"),
]


@dataclass
class Step:
    profile: str
    target: str
    authorized: bool
    reason: str
    new_observations: int = 0


@dataclass
class PlanRun:
    steps: list[Step] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    stopped_because: str = ""


def _signature(o: Observation) -> str:
    return f"{o.asset}|{o.kind}|{o.detail}"


def _candidate_profiles(observations: list[Observation], done: set[str]) -> list[str]:
    """Suggest not-yet-run profiles based on what evidence we have."""
    blob = " ".join(f"{o.kind} {o.detail}".lower() for o in observations)
    out: list[str] = []
    for signals, profile in NEXT_ACTION_RULES:
        if profile in done:
            continue
        if any(s in blob for s in signals) and profile not in out:
            out.append(profile)
    return out


class Planner:
    """Bounded autonomy over read-only collectors.

    `collect(profile, target) -> list[Observation]` is injected (wraps the Orchestrator in
    prod, a fixture in tests). `authorize(profile, target) -> (bool, reason)` defaults to the
    guardrail's target-scope + profile-exists check.
    """

    def __init__(self, guardrail, collect, *, max_depth: int = 4,
                 rank=None):
        self.guard = guardrail
        self.collect = collect
        self.max_depth = max_depth
        self.rank = rank  # optional LLM/heuristic ranker: (candidates, obs) -> ordered list

    def _authorize(self, profile: str, target: str) -> tuple[bool, str]:
        if profile not in PROFILES:
            return False, f"unknown profile {profile}"
        d = self.guard.check_target(target)
        if not d.allowed:
            return False, d.reason
        return True, "scope+profile ok"

    def run(self, target: str, seed_profile: str = "discovery") -> PlanRun:
        run = PlanRun()
        done: set[str] = set()
        seen: set[str] = set()
        queue: list[str] = [seed_profile]

        depth = 0
        while queue and depth < self.max_depth:
            try:
                self.guard.budget.check()
            except Exception as exc:  # noqa: BLE001
                run.stopped_because = f"budget: {exc}"
                return run
            profile = queue.pop(0)
            if profile in done:
                continue
            ok, reason = self._authorize(profile, target)
            step = Step(profile, target, ok, reason)
            done.add(profile)
            if not ok:
                run.steps.append(step)
                continue
            depth += 1  # only authorized steps that actually collect consume depth
            obs = self.collect(profile, target) or []
            fresh = [o for o in obs if _signature(o) not in seen]
            for o in fresh:
                seen.add(_signature(o))
            step.new_observations = len(fresh)
            run.observations.extend(fresh)
            run.steps.append(step)
            # Re-plan: derive next candidate profiles from everything seen so far.
            candidates = _candidate_profiles(run.observations, done)
            if self.rank:
                candidates = self.rank(candidates, run.observations)
            for c in candidates:
                if c not in done and c not in queue:
                    queue.append(c)

        if depth >= self.max_depth:
            run.stopped_because = run.stopped_because or "max depth reached"
        elif not queue:
            run.stopped_because = run.stopped_because or "no new candidate actions"
        return run
