"""Aegis recon subpackage — read-only collectors that ride the guardrail.

Each collector mirrors the host/AD pattern: an injectable transport (so it is fully
offline-testable with fixtures), a normalized list[Observation] output, and a thin
orchestrator that authorizes target scope through the Guardrail before any I/O.
"""
