#!/usr/bin/env python3
"""Generate the deterministic Argus control dashboard from STATUS.json."""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable, Mapping
from html import escape
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
STATUS_PATH = REPO_ROOT / "docs" / "control" / "STATUS.json"
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "index.html"


def _text(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _e(value: object) -> str:
    return escape(_text(value), quote=True)


def _items(values: Iterable[object], *, ordered: bool = False) -> str:
    tag = "ol" if ordered else "ul"
    body = "".join(f"<li>{_e(value)}</li>" for value in values)
    return f"<{tag}>{body}</{tag}>"


def _flow(values: Iterable[object]) -> str:
    steps = "".join(
        f'<li><span class="step-index">{index:02d}</span><span>{_e(value)}</span></li>'
        for index, value in enumerate(values, start=1)
    )
    return f'<ol class="flow">{steps}</ol>'


def _badge(value: object) -> str:
    normalized = _text(value).lower()
    css = "ok" if normalized in {"passed", "merged", "baseline-passed"} else "warn"
    if normalized in {"failed", "blocked"}:
        css = "bad"
    return f'<span class="badge {css}">{_e(value)}</span>'


def _record_cards(records: Iterable[Mapping[str, object]]) -> str:
    cards: list[str] = []
    for record in records:
        state = record.get("state", "")
        cards.append(
            '<article class="milestone">'
            f"<header>{_badge(state)}<span>{_e(record.get('evidence'))}</span></header>"
            f"<h3>{_e(record.get('name'))}</h3>"
            "</article>"
        )
    return "".join(cards)


def _roadmap_columns(roadmap: Mapping[str, list[object]]) -> str:
    columns: list[str] = []
    for state in ("NOW", "NEXT", "LATER", "DEFERRED"):
        values = roadmap.get(state, [])
        columns.append(
            f'<article class="roadmap-column state-{state.lower()}">'
            f"<h3>{state}</h3>{_items(values)}</article>"
        )
    return "".join(columns)


def _blocker_rows(records: Iterable[Mapping[str, object]]) -> str:
    return "".join(
        "<tr>"
        f"<th>{_e(record.get('item'))}</th>"
        f"<td>{_badge(record.get('state'))}</td>"
        f"<td>{_e(record.get('impact'))}</td>"
        f"<td>{_e(record.get('owner'))}</td>"
        "</tr>"
        for record in records
    )


def _links(records: Iterable[Mapping[str, object]]) -> str:
    return "".join(
        f'<a class="control-link" href="{_e(record.get("href"))}">'
        f"{_e(record.get('label'))}</a>"
        for record in records
    )


def _test_evidence(status: Mapping[str, Any]) -> str:
    tests = status["test_results"]
    baseline = tests["baseline_full"]
    release = tests["release_closeout_full"]
    lint = status["lint_results"]
    cards = [
        ("Baseline tests", f"{baseline.get('passed', '—')} passed", baseline["status"]),
        ("Release tests", f"{release.get('passed', '—')} passed", release["status"]),
        ("Ruff", lint["status"], lint["status"]),
        ("Bandit", status["bandit"]["status"], status["bandit"]["status"]),
        (
            "Dependency audit",
            status["dependency_audit"]["status"],
            status["dependency_audit"]["status"],
        ),
        ("CodeQL", f"{status['codeql']['open_alerts']} open alerts", status["codeql"]["status"]),
    ]
    return "".join(
        '<article class="evidence-card">'
        f"<span>{_e(label)}</span><strong>{_e(value)}</strong>{_badge(state)}"
        "</article>"
        for label, value, state in cards
    )


def _load_status() -> dict[str, Any]:
    status = json.loads(STATUS_PATH.read_text())
    if status.get("schema_version") != 1:
        raise ValueError("unsupported STATUS.json schema")
    return status


def render(status: Mapping[str, Any]) -> str:
    unsupported = _items(status["unsupported_deployment_modes"])
    supported = _items(status["supported_deployment_modes"])
    milestones = _record_cards(status["completed_milestones"])
    roadmap = _roadmap_columns(status["roadmap"])
    blockers = _blocker_rows(status["blocker_matrix"])
    architecture = _flow(status["architecture"])
    v1_flow = _flow(status["v1_execution_flow"])
    v2_flow = _flow(status["v2_experimental_flow"])
    security = _items(status["security_evidence"])
    controls = _links(status["control_links"])
    evidence = _test_evidence(status)
    issue_count = len(status["open_issues"])
    pr_count = len(status["open_pull_requests"])
    blocker_count = len(status["blockers"])

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Argus release control dashboard">
  <title>Argus · Release Control</title>
  <style>
    :root {{
      --bg: #071017;
      --panel: #0d1b24;
      --panel-2: #112631;
      --line: #28414e;
      --text: #edf7f8;
      --muted: #9eb2ba;
      --cyan: #4cd7e8;
      --green: #65dc9a;
      --amber: #f6c760;
      --red: #ff7b72;
      --shadow: 0 24px 70px rgba(0, 0, 0, .32);
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0;
      color: var(--text);
      background:
        radial-gradient(circle at 80% -10%, rgba(76, 215, 232, .13), transparent 34rem),
        radial-gradient(circle at -10% 40%, rgba(101, 220, 154, .08), transparent 32rem),
        var(--bg);
      font: 15px/1.55 Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
    }}
    a {{ color: var(--cyan); }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
    .skip {{
      position: absolute;
      left: -9999px;
    }}
    .skip:focus {{
      left: 1rem;
      top: 1rem;
      z-index: 20;
      padding: .7rem 1rem;
      background: var(--text);
      color: var(--bg);
    }}
    .topbar {{
      position: sticky;
      top: 0;
      z-index: 10;
      display: flex;
      align-items: center;
      gap: 1.5rem;
      min-height: 64px;
      padding: .8rem clamp(1rem, 4vw, 4rem);
      border-bottom: 1px solid rgba(76, 215, 232, .2);
      background: rgba(7, 16, 23, .88);
      backdrop-filter: blur(16px);
    }}
    .brand {{ font-weight: 850; letter-spacing: .08em; text-transform: uppercase; }}
    .brand i {{ color: var(--cyan); font-style: normal; }}
    nav {{ display: flex; gap: 1rem; margin-left: auto; }}
    nav a {{ color: var(--muted); text-decoration: none; font-size: .85rem; }}
    .hero {{
      max-width: 1400px;
      margin: 0 auto;
      padding: clamp(4rem, 8vw, 8rem) clamp(1rem, 4vw, 4rem) 3rem;
    }}
    .eyebrow {{
      color: var(--cyan);
      font: 700 .75rem/1.2 ui-monospace, monospace;
      letter-spacing: .16em;
      text-transform: uppercase;
    }}
    h1 {{
      max-width: 18ch;
      margin: .7rem 0 1rem;
      font-size: clamp(2.6rem, 7vw, 6.6rem);
      line-height: .95;
      letter-spacing: -.06em;
    }}
    .lede {{ max-width: 75ch; color: var(--muted); font-size: 1.08rem; }}
    .warning {{
      margin-top: 2rem;
      padding: 1rem 1.2rem;
      border: 1px solid rgba(246, 199, 96, .45);
      border-left: 4px solid var(--amber);
      border-radius: .7rem;
      background: rgba(246, 199, 96, .07);
      color: #ffe4a3;
    }}
    main {{
      max-width: 1400px;
      margin: 0 auto;
      padding: 0 clamp(1rem, 4vw, 4rem) 6rem;
    }}
    section {{ padding: 3rem 0; border-top: 1px solid var(--line); }}
    .section-head {{
      display: grid;
      grid-template-columns: minmax(12rem, .7fr) minmax(18rem, 1.3fr);
      gap: 2rem;
      margin-bottom: 1.8rem;
    }}
    h2 {{ margin: 0; font-size: clamp(1.6rem, 3vw, 2.5rem); letter-spacing: -.035em; }}
    .section-head p {{ margin: .25rem 0 0; color: var(--muted); }}
    .status-grid, .evidence-grid, .milestone-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: .9rem;
    }}
    .status-card, .evidence-card, .milestone {{
      padding: 1.1rem;
      border: 1px solid var(--line);
      border-radius: .8rem;
      background: linear-gradient(160deg, var(--panel-2), var(--panel));
      box-shadow: var(--shadow);
    }}
    .status-card span, .evidence-card span {{
      display: block;
      color: var(--muted);
      font-size: .78rem;
      text-transform: uppercase;
      letter-spacing: .08em;
    }}
    .status-card strong, .evidence-card strong {{
      display: block;
      margin: .4rem 0 .7rem;
      overflow-wrap: anywhere;
    }}
    .badge {{
      display: inline-block;
      padding: .2rem .5rem;
      border: 1px solid currentColor;
      border-radius: 999px;
      font: 700 .68rem/1.2 ui-monospace, monospace;
      text-transform: uppercase;
    }}
    .badge.ok {{ color: var(--green); }}
    .badge.warn {{ color: var(--amber); }}
    .badge.bad {{ color: var(--red); }}
    .two-column, .flow-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 1rem;
    }}
    .boundary, .flow-panel {{
      padding: 1.2rem;
      border: 1px solid var(--line);
      border-radius: .8rem;
      background: var(--panel);
    }}
    .boundary h3, .flow-panel h3 {{ margin-top: 0; }}
    li {{ margin: .45rem 0; }}
    .roadmap-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: .8rem;
    }}
    .roadmap-column {{
      min-height: 230px;
      padding: 1rem;
      border: 1px solid var(--line);
      border-top: 4px solid var(--muted);
      border-radius: .8rem;
      background: var(--panel);
    }}
    .state-now {{ border-top-color: var(--green); }}
    .state-next {{ border-top-color: var(--cyan); }}
    .state-later {{ border-top-color: var(--amber); }}
    .state-deferred {{ border-top-color: #77838a; }}
    .roadmap-column h3 {{ margin: 0; font-family: ui-monospace, monospace; }}
    .roadmap-column ul {{ padding-left: 1.2rem; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); }}
    th, td {{ padding: .85rem; border-bottom: 1px solid var(--line); text-align: left; }}
    th {{ width: 22%; }}
    .flow {{ list-style: none; padding: 0; margin: 0; }}
    .flow li {{
      display: grid;
      grid-template-columns: 2.5rem 1fr;
      gap: .6rem;
      align-items: start;
      padding: .7rem 0;
      border-bottom: 1px solid var(--line);
    }}
    .step-index {{ color: var(--cyan); font: 700 .75rem/1.5 ui-monospace, monospace; }}
    .milestone header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      color: var(--muted);
      font-size: .75rem;
    }}
    .milestone h3 {{ margin-bottom: 0; }}
    .next-action {{
      padding: 1.5rem;
      border-radius: .8rem;
      background: linear-gradient(120deg, rgba(76, 215, 232, .13), rgba(101, 220, 154, .08));
      border: 1px solid var(--cyan);
      font-size: 1.05rem;
    }}
    .control-links {{ display: flex; flex-wrap: wrap; gap: .65rem; }}
    .control-link {{
      padding: .65rem .85rem;
      border: 1px solid var(--line);
      border-radius: .55rem;
      background: var(--panel);
      text-decoration: none;
    }}
    footer {{
      max-width: 1400px;
      margin: 0 auto;
      padding: 2rem clamp(1rem, 4vw, 4rem) 4rem;
      color: var(--muted);
      border-top: 1px solid var(--line);
    }}
    @media (max-width: 900px) {{
      nav {{ display: none; }}
      .section-head, .two-column, .flow-grid {{ grid-template-columns: 1fr; }}
      .roadmap-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    }}
    @media (max-width: 560px) {{
      .roadmap-grid {{ grid-template-columns: 1fr; }}
      th, td {{ display: block; width: 100%; }}
      tr {{ display: block; padding: .5rem 0; border-bottom: 1px solid var(--line); }}
      th, td {{ border: 0; padding: .25rem .6rem; }}
    }}
    @media (prefers-reduced-motion: reduce) {{
      html {{ scroll-behavior: auto; }}
    }}
  </style>
</head>
<body>
  <a class="skip" href="#project-status">Skip to project status</a>
  <header class="topbar">
    <div class="brand"><i>Argus</i> / Release Control</div>
    <nav aria-label="Dashboard">
      <a href="#project-status">Status</a>
      <a href="#roadmap">Roadmap</a>
      <a href="#architecture">Architecture</a>
      <a href="#evidence">Evidence</a>
      <a href="#operations">Operations</a>
    </nav>
  </header>

  <div class="hero">
    <div class="eyebrow">Evidence-gated defensive engineering</div>
    <h1>Supervised V1. Experimental V2.</h1>
    <p class="lede"><strong>Release target:</strong> {_e(status["release_target"])}.
      Argus is a fail-closed defensive assessment orchestrator for explicitly
      authorized, separately verified isolated labs.</p>
    <div class="warning"><strong>Maturity warning:</strong> {_e(status["maturity"])}.
      No unattended, production, regulated, network-exposed, multi-user, or 24/7
      operation is supported. The local JSON anchor is not WORM.</div>
  </div>

  <main>
    <section id="project-status">
      <div class="section-head">
        <div><div class="eyebrow">Control plane</div><h2>Project status</h2></div>
        <p>Repository, release, and evidence state from the deterministic
          machine-readable control snapshot.</p>
      </div>
      <div class="status-grid">
        <article class="status-card"><span>Repository</span><strong>{_e(status["repository"])}</strong>{_badge("tracked")}</article>
        <article class="status-card"><span>Release target</span><strong>{_e(status["release_target"])}</strong>{_badge("in progress")}</article>
        <article class="status-card"><span>Branch</span><strong>{_e(status["active_branch"])}</strong>{_badge("canonical")}</article>
        <article class="status-card"><span>Open PRs</span><strong>{pr_count}</strong>{_badge("clear" if pr_count == 0 else "review")}</article>
        <article class="status-card"><span>Open issues</span><strong>{issue_count}</strong>{_badge("tracked")}</article>
        <article class="status-card"><span>Release blockers</span><strong>{blocker_count}</strong>{_badge("clear" if blocker_count == 0 else "blocked")}</article>
      </div>
    </section>

    <section id="git-ci">
      <div class="section-head">
        <div><div class="eyebrow">Repository truth</div><h2>Git and CI state</h2></div>
        <p>Exact immutable identifiers and the current security-analysis state.</p>
      </div>
      <div class="status-grid">
        <article class="status-card"><span>Current main</span><strong><code>{_e(status["current_main_sha"])}</code></strong></article>
        <article class="status-card"><span>Generation HEAD</span><strong><code>{_e(status["head_sha"])}</code></strong></article>
        <article class="status-card"><span>Source commit</span><strong><code>{_e(status["source_commit"])}</code></strong></article>
        <article class="status-card"><span>CodeQL</span><strong>{_e(status["codeql"]["status"])}</strong>{_badge(status["codeql"]["status"])}</article>
      </div>
    </section>

    <section id="boundaries">
      <div class="section-head">
        <div><div class="eyebrow">Release contract</div><h2>Release target</h2></div>
        <p>What this candidate supports—and what it explicitly does not claim.</p>
      </div>
      <div class="two-column">
        <article class="boundary"><h3>Supported deployment boundary</h3>{supported}</article>
        <article class="boundary"><h3>Unsupported deployment modes</h3>{unsupported}</article>
      </div>
    </section>

    <section id="milestones">
      <div class="section-head">
        <div><div class="eyebrow">Delivered evidence</div><h2>Completed milestones</h2></div>
        <p>Milestones are tied to repository evidence, not roadmap checkboxes.</p>
      </div>
      <div class="milestone-grid">{milestones}</div>
    </section>

    <section id="roadmap">
      <div class="section-head">
        <div><div class="eyebrow">Evidence gates</div><h2>Phase roadmap</h2></div>
        <p>NOW closes before NEXT begins. LATER and DEFERRED do not imply current capability.</p>
      </div>
      <div class="roadmap-grid">{roadmap}</div>
    </section>

    <section id="blockers">
      <div class="section-head">
        <div><div class="eyebrow">Decision pressure</div><h2>Blocker matrix</h2></div>
        <p>Release gates and deferred constraints are separated so future scope
          cannot masquerade as a current blocker.</p>
      </div>
      <table>
        <thead><tr><th>Item</th><th>State</th><th>Impact</th><th>Owner</th></tr></thead>
        <tbody>{blockers}</tbody>
      </table>
    </section>

    <section id="next-action">
      <div class="section-head">
        <div><div class="eyebrow">Operator queue</div><h2>Next exact action</h2></div>
        <p>One executable action owns the NOW gate.</p>
      </div>
      <div class="next-action">{_e(status["next_action"])}</div>
    </section>

    <section id="architecture">
      <div class="section-head">
        <div><div class="eyebrow">System boundary</div><h2>Architecture</h2></div>
        <p>Supported V1 architecture from operator input through transactional audit.</p>
      </div>
      <article class="flow-panel">{architecture}</article>
    </section>

    <section id="execution-flows">
      <div class="section-head">
        <div><div class="eyebrow">Truthful execution</div><h2>V1 execution flow</h2></div>
        <p>V1 is operator-invoked and bounded. V2 remains incomplete and opt-in experimental.</p>
      </div>
      <div class="flow-grid">
        <article class="flow-panel"><h3>V1 execution flow</h3>{v1_flow}</article>
        <article class="flow-panel"><h3>V2 experimental flow</h3>{v2_flow}</article>
      </div>
    </section>

    <section id="evidence">
      <div class="section-head">
        <div><div class="eyebrow">Verification</div><h2>Test and security evidence</h2></div>
        <p>Local and GitHub gates are visible without converting pending work into a claim.</p>
      </div>
      <div class="evidence-grid">{evidence}</div>
      <div class="boundary" style="margin-top:1rem">{security}</div>
    </section>

    <section id="decisions">
      <div class="section-head">
        <div><div class="eyebrow">Canonical sources</div><h2>Decisions</h2></div>
        <p>Release rationale, roadmap gates, operations, rollback, and recovery
          evidence live in the versioned control pack.</p>
      </div>
      <div class="control-links">{controls}</div>
    </section>

    <section id="operations">
      <div class="section-head">
        <div><div class="eyebrow">Safe use</div><h2>Operations and rollback</h2></div>
        <p>Use the runbook for release verification, audit recovery, Phase 1/V2
          incompatibility, and rollback. No deployment was performed.</p>
      </div>
      <div class="next-action">
        <a href="control/RUNBOOK.md">Open the release and operations runbook</a>
        · <a href="control/AGENT_HANDOFF.md">Review preserved worktree evidence</a>
      </div>
    </section>
  </main>

  <footer>
    <div><strong>Source commit:</strong> <code>{_e(status["source_commit"])}</code></div>
    <div><strong>Last updated:</strong> <time datetime="{_e(status["generated_at"])}">{_e(status["generated_at"])}</time></div>
    <div>Argus · authorized defensive assessment only · no deployment performed</div>
  </footer>
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(_load_status()), newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
