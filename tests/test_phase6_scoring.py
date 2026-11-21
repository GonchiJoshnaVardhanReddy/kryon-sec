"""Offline scoring must not promote a tool-confirmed lab observation."""

import importlib.util
from pathlib import Path


def _scorer():
    path = Path(__file__).resolve().parents[1] / "research/lab/phase6_scoring.py"
    spec = importlib.util.spec_from_file_location("phase6_scoring", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tool_confirmation_without_verification_is_only_observed():
    scorer = _scorer()
    challenges = [{"key": "redirectChallenge", "name": "redirect"}]
    nodes = [{"node_type": "finding", "label": "H1", "id": "n1",
              "properties": {"excerpt": "/redirect"}}]
    audit = [{"event": "finding_confirmed", "hypothesis_id": "H1"}]
    result = scorer.score(challenges, nodes, audit, "full", "lab", "non-human")
    assert result["rows"][0]["verdict"] == "OBSERVED"
    assert result["false_positives"] == []

    audit.append({"event": "finding_verified", "finding_id": "H1"})
    verified = scorer.score(challenges, nodes, audit, "full", "lab", "non-human")
    assert verified["rows"][0]["verdict"] == "CONFIRMED"


def test_lab_manifest_records_the_pinned_image_identity():
    """Keep the lab manifest auditable without importing its live harness."""
    path = Path(__file__).resolve().parents[1] / "research/lab/phase5_engagement_runs.py"
    text = path.read_text(encoding="utf-8")
    assert '"sandbox_image": cfg.sandbox_image,' in text
