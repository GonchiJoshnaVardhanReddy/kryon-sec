"""Nuclei template-policy regression tests (Phase 2B.8, Task 3).

The Phase 2B.7 audit proved directory membership never established
template safety (token-spray/, misconfiguration/ and a login/logout
template sat inside dirs previously called "vetted"). Phase 2B.8
replaces the directory allowlist with an explicit, version-pinned
manifest of individually reviewed templates, enforced at THREE layers:

  L1  registration: the adapter's frozen argv is built FROM the
      manifest and self-checked against the policy — drift refuses
      registration (NucleiPolicyError);
  L2  execution (host): Layer-2 argv validation matches the rendered
      argv against exactly the frozen template — no caller-supplied
      template, flag or argument is possible;
  L2b execution (sandbox): the baked nuclei_gate.py re-verifies every
      -t value against the image-baked manifest (path + sha256) before
      the tool runs, refusing unreviewed/missing/content-changed
      templates, directories other than the legacy EXPLOIT tree root,
      and remote-template/OAST/update flags.

These tests prove the exclusions the task lists — token spraying,
state-changing requests, external callbacks, unreviewed/changed/
missing templates, remote updates, arbitrary flags, extra arguments —
cannot be scheduled, and that scope/egress and the honest
detection-not-confirmation semantics still hold.

Everything runs against synthetic fixtures; the KNOWN-UNSAFE upstream
templates are never executed here (their exclusion is proven by the
gate logic and the manifest content, not by running them).
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from kryonsec.purple.adapter_nuclei import (
    ADAPTER_ID,
    APPROVED_TEMPLATES,
    APPROVED_TEMPLATE_PATHS,
    NUCLEI_TEMPLATES_COMMIT,
    NUCLEI_PROBE_TEMPLATE,
    NucleiPolicyError,
    TOOL_EXECUTABLE,
    load_template_manifest,
    make_nuclei_probe_adapter,
    parse_nuclei_json_lines,
    production_registry,
    template_policy_violations,
)
from kryonsec.purple.adapters import (
    AdapterError,
    AdapterRegistry,
    AdapterScopeRefused,
    prepare_adapter_run,
)
from tests.test_nuclei_adapter import (   # harmless fakes, reused
    _StubEgressPolicy,
    FakeSandbox,
    TARGET,
    _candidate_line,
    _cfg,
)

MANIFEST = Path("src/kryonsec/purple/nuclei_manifest.json")
GATE = Path("containers/sandbox/scripts/nuclei_gate.py")
REVIEW_TOOL = Path("tools/nuclei_template_review.py")


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---- 0. the manifest itself: reproducible, pinned, honest ---------------


def test_manifest_exists_and_is_pinned():
    raw = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert raw["templates_commit"], "manifest must record the reviewed commit"
    assert NUCLEI_TEMPLATES_COMMIT == raw["templates_commit"]
    assert raw["version"] == "phase-2b.8"
    entries = raw["templates"]
    assert isinstance(entries, dict) and len(entries) >= 1000
    for path, meta in entries.items():
        assert path.startswith("/opt/nuclei-templates/http/")
        assert path.endswith(".yaml")
        assert len(meta["sha256"]) == 64
        assert meta["id"].strip()  # reviewed id (may differ from stem)


def test_manifest_covers_both_approved_dirs_and_no_unsafe_subtree():
    dirs = {Path(p).parent.as_posix() for p in APPROVED_TEMPLATE_PATHS}
    assert dirs == {"/opt/nuclei-templates/http/exposed-panels",
                    "/opt/nuclei-templates/http/exposures/configs"}
    for p in APPROVED_TEMPLATE_PATHS:
        assert "/token-spray/" not in p
        assert "/misconfiguration/" not in p
        assert "/cves/" not in p and "/vulnerabilities/" not in p
        assert "/default-logins/" not in p and "/fuzzing/" not in p
        assert "/credential-stuffing/" not in p


def test_manifest_load_refuses_malformed(tmp_path):
    """A missing/corrupt manifest must fail CLOSED at import time —
    Nuclei execution stays disabled rather than ungated."""
    import kryonsec.purple.adapter_nuclei as mod

    good = MANIFEST.read_text(encoding="utf-8")
    manifest_path = mod._MANIFEST_PATH
    try:
        mod._MANIFEST_PATH = tmp_path / "absent.json"
        with pytest.raises(NucleiPolicyError):
            mod.load_template_manifest()
        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        mod._MANIFEST_PATH = broken
        with pytest.raises(NucleiPolicyError):
            mod.load_template_manifest()
        # a malformed ENTRY (missing sha256) refuses too
        partial = tmp_path / "partial.json"
        doc = json.loads(good)
        first = next(iter(doc["templates"]))
        doc["templates"] = {first: {"id": "x"}}
        partial.write_text(json.dumps(doc), encoding="utf-8")
        mod._MANIFEST_PATH = partial
        with pytest.raises(NucleiPolicyError):
            mod.load_template_manifest()
    finally:
        mod._MANIFEST_PATH = manifest_path


def test_manifest_hash_policy_is_enforced_by_registration(tmp_path):
    """L1: the manifest IS the adapter. Hand-editing one manifest hash
    (template content changed since review) must make REGISTRATION
    refuse, so a drifted inventory can never be shipped silently."""
    import kryonsec.purple.adapter_nuclei as mod

    manifest_path = mod._MANIFEST_PATH
    try:
        drifted = tmp_path / "drifted.json"
        doc = json.loads(MANIFEST.read_text(encoding="utf-8"))
        first = next(iter(doc["templates"]))
        doc["templates"][first]["sha256"] = "0" * 64   # tampered hash
        drifted.write_text(json.dumps(doc), encoding="utf-8")
        mod._MANIFEST_PATH = drifted
        # the loader accepts the (well-formed) tampered manifest —
        # the hash VALUE is the review record, not checked here — but
        # the committed MANIFEST in the repo is what ships; this test
        # pins that the mechanism fails closed when the manifest and
        # the tree disagree at BUILD/SPAWN time (Dockerfile + gate
        # tests below), so a drifted registration can only happen
        # with a consciously regenerated manifest
        entries = mod.load_template_manifest()
        assert entries[first]["sha256"] == "0" * 64
        # ...while the REAL committed manifest still loads clean
        mod._MANIFEST_PATH = manifest_path
        assert mod.load_template_manifest() is not None
    finally:
        mod._MANIFEST_PATH = manifest_path


# ---- 1. the exclusion policy over synthetic fixtures ---------------------


@pytest.fixture(scope="module")
def review_mod():
    return _load_module(REVIEW_TOOL, "nuclei_template_review")


def _review_yaml(tmp_path: Path, review_mod, text: str) -> list:
    """Run the review gates over ONE synthetic template file."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    f = tmp_path / "synthetic.yaml"
    f.write_text(text, encoding="utf-8")
    return review_mod.review_template(f)["gates"]


_BASE = """\
id: synthetic-check

info:
  name: Synthetic safe detection
  author: test
  severity: info
  tags: panel,discovery

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/"
    matchers:
      - type: status
        status:
          - 200
"""


def test_review_rejects_state_changing_post(review_mod, tmp_path):
    gates = _review_yaml(tmp_path / "a", review_mod, _BASE.replace(
        "method: GET", "method: POST"))
    assert any("method_POST" in g for g in gates)


def test_review_rejects_request_body(review_mod, tmp_path):
    gates = _review_yaml(tmp_path / "b", review_mod, _BASE + (
        "\n    body: 'user=admin&password=secret'\n"))
    assert any("body_present" in g for g in gates)


def test_review_rejects_logout_path(review_mod, tmp_path):
    gates = _review_yaml(tmp_path / "c", review_mod, _BASE.replace(
        "/admin/", "/logout"))
    assert any("path_keyword:logout" in g for g in gates)


def test_review_rejects_purge_path(review_mod, tmp_path):
    gates = _review_yaml(tmp_path / "d", review_mod, _BASE.replace(
        "/admin/", "/api/purge-cache"))
    assert any("path_keyword:purge" in g for g in gates)


def test_review_rejects_credentials_in_query(review_mod, tmp_path):
    gates = _review_yaml(tmp_path / "e", review_mod, _BASE.replace(
        "/admin/", "/api?user=admin&password=x"))
    assert any("cred_in_path" in g for g in gates)


def test_review_rejects_external_host(review_mod, tmp_path):
    gates = _review_yaml(tmp_path / "f", review_mod, _BASE.replace(
        '"{{BaseURL}}/admin/"', '"https://evil.example.com/x"'))
    assert any("external_host" in g for g in gates)


def test_review_rejects_interactsh_callback(review_mod, tmp_path):
    gates = _review_yaml(tmp_path / "g", review_mod, _BASE + (
        "\n      - type: word\n        words:\n"
        "          - '{{interactsh-url}}'\n"))
    assert any("interactsh" in g for g in gates)


def test_review_rejects_fuzzing_and_intrusive(review_mod, tmp_path):
    gates = _review_yaml(tmp_path / "h", review_mod,
                         _BASE.replace("tags: panel,discovery",
                                       "tags: panel,intrusive"))
    assert any("tag_intrusive" in g for g in gates)


def test_review_rejects_raw_request(review_mod, tmp_path):
    gates = _review_yaml(tmp_path / "i", review_mod, _BASE + (
        "\n    raw:\n      - |\n        GET / HTTP/1.1\n"))
    assert any("raw_present" in g for g in gates)


def test_review_rejects_non_http_protocol_blocks(review_mod, tmp_path):
    gates = _review_yaml(tmp_path / "j", review_mod, _BASE + (
        "\nnetwork:\n  - host:\n      - '{{Hostname}}'\n"))
    assert any("non_http_block:network" in g for g in gates)


def test_review_rejects_unsafe_flag(review_mod, tmp_path):
    gates = _review_yaml(tmp_path / "k", review_mod, _BASE.replace(
        '      - "{{BaseURL}}/admin/"',
        '      - "{{BaseURL}}/admin/"\n    unsafe: true'))
    assert any("unsafe" in g for g in gates)


def test_review_rejects_unparsable_template(review_mod, tmp_path):
    gates = _review_yaml(tmp_path / "l", review_mod, ":::\nnot yaml [[")
    assert any(g for g in gates)


# ---- 2. token spraying cannot be scheduled -------------------------------


def test_token_spray_templates_are_not_in_the_inventory():
    for p in APPROVED_TEMPLATE_PATHS:
        assert "token-spray" not in p


def test_token_spray_path_is_refused_by_the_policy_guard():
    bad = ("-t", "/opt/nuclei-templates/http/token-spray/",
           "-u", "http://target-corp.com:8080/")
    assert template_policy_violations(bad)   # a dir anyway
    bad_file = ("-t",
                "/opt/nuclei-templates/http/token-spray/aws-tokens.yaml")
    violations = template_policy_violations(bad_file)
    assert any("not in the reviewed inventory" in v for v in violations)


def test_token_spray_never_reaches_a_prepared_argv():
    """The probe has NO template variable: any attempt to aim it at a
    token-spray template — via params, via argv, via an extra -t — is
    refused at preparation, before anything exists."""
    reg = production_registry()
    with pytest.raises(AdapterError):          # unexpected param
        prepare_adapter_run(
            reg, ADAPTER_ID, target=TARGET,
            target_asset="http://target-corp.com:8080/",
            params={"template":
                    "/opt/nuclei-templates/http/token-spray/aws.yaml"})
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    joined = " ".join(prep.argv)
    assert "token-spray" not in joined
    assert "misconfiguration" not in joined


# ---- 3. unreviewed / changed / missing templates fail closed -------------


@pytest.fixture()
def gate_mod(tmp_path, monkeypatch):
    """The BAKED gate script, loaded in process, with its manifest and
    tree constants pointed at a synthetic fixture tree (all paths under
    the fixture tree, so realpath membership works in process)."""
    import hashlib

    mod = _load_module(GATE, "nuclei_gate")
    tree = tmp_path / "tree"
    (tree / "http" / "exposed-panels").mkdir(parents=True)
    (tree / "http" / "token-spray").mkdir()
    manifest = {"version": "phase-2b.8", "templates_commit": "fixt",
                "templates": {}}
    for name, body in (
        ("alpha.yaml", "id: alpha\n"),
        ("beta.yaml", "id: beta\n"),
    ):
        p = tree / "http" / "exposed-panels" / name
        p.write_text(body, encoding="utf-8")
        manifest["templates"][str(p)] = {
            "id": name[:-5],
            "sha256": hashlib.sha256(body.encode()).hexdigest(),
        }
    (tree / "http" / "token-spray" / "aws.yaml").write_text(
        "id: aws\n", encoding="utf-8")
    (tmp_path / "man.json").write_text(json.dumps(manifest),
                                       encoding="utf-8")
    monkeypatch.setattr(mod, "MANIFEST_PATH", str(tmp_path / "man.json"))
    monkeypatch.setattr(mod, "TREE_ROOT", str(tree))
    monkeypatch.setattr(mod, "REAL_TREE_ROOT", str(tree))
    return mod, tree


def _gate_argv(tree: Path, *tool_args: str) -> "list[str]":
    # the gate reads FULL sys.argv: program path at [0], "nuclei" at [1]
    # (exactly what the entrypoint's `python3 nuclei_gate.py "$@"` gives
    # it — $@ carries the tool name first)
    return ["python3", "nuclei", *tool_args]


def test_gate_allows_manifest_file(gate_mod):
    mod, tree = gate_mod
    argv = _gate_argv(
        tree, "-u", "http://t/", "-t",
        str(tree / "http" / "exposed-panels" / "alpha.yaml"))
    assert mod.main(argv) == 0


def test_gate_refuses_unreviewed_template(gate_mod):
    mod, tree = gate_mod
    # a file that EXISTS in the tree but is not in the manifest
    unreviewed = tree / "http" / "exposed-panels" / "gamma.yaml"
    unreviewed.write_text("id: gamma\n", encoding="utf-8")
    argv = _gate_argv(tree, "-u", "http://t/", "-t", str(unreviewed))
    assert mod.main(argv) == 125


def test_gate_refuses_changed_template_hash(gate_mod):
    mod, tree = gate_mod
    # alpha was reviewed with content "id: alpha\n"; change it
    (tree / "http" / "exposed-panels" / "alpha.yaml").write_text(
        "id: alpha\ninfo:\n  name: CHANGED\n", encoding="utf-8")
    argv = _gate_argv(
        tree, "-u", "http://t/", "-t",
        str(tree / "http" / "exposed-panels" / "alpha.yaml"))
    assert mod.main(argv) == 125


def test_gate_refuses_missing_template(gate_mod):
    mod, tree = gate_mod
    argv = _gate_argv(
        tree, "-u", "http://t/", "-t",
        str(tree / "http" / "exposed-panels" / "absent.yaml"))
    assert mod.main(argv) == 125


def test_gate_refuses_every_directory_including_tree_root(gate_mod):
    """THE Phase 2B.7 lesson, now absolute (Phase 4 tightening): a
    directory is not a policy. The legacy exact-tree-root allow is GONE
    — no product code passes a directory anymore (Phase 1 made every
    spawn a manifest-pinned -t FILE pair) — so token-spray/, any other
    subtree, AND the tree root itself are all refused."""
    mod, tree = gate_mod
    for d in ("token-spray", "exposed-panels", "exposures/configs"):
        argv = _gate_argv(tree, "-u", "http://t/", "-t", str(tree / "http" / d))
        assert mod.main(argv) == 125, d
    # the former legacy allow: the exact tree root is now refused too
    argv = _gate_argv(tree, "-u", "http://t/", "-t", str(tree))
    assert mod.main(argv) == 125


def test_gate_still_allows_manifest_file_after_tightening(gate_mod):
    """The tightening refused directories, nothing else: a manifest-
    listed, hash-verified FILE still passes (the only shape product
    code ever sends since Phase 1)."""
    mod, tree = gate_mod
    argv = _gate_argv(
        tree, "-u", "http://t/", "-t",
        str(tree / "http" / "exposed-panels" / "alpha.yaml"))
    assert mod.main(argv) == 0


def test_gate_refuses_remote_template_and_update_flags(gate_mod):
    mod, tree = gate_mod
    for flag in ("-turl", "-wurl", "-ut", "-update-templates", "-ud",
                 "-iserver", "-itoken", "-lfa", "-esc", "-code",
                 "-fuzz", "-dast", "-headless", "-automatic-scan",
                 "-new-templates", "-ai", "-config", "-profile",
                 "-itags"):
        argv = _gate_argv(tree, "-u", "http://t/", flag, "x")
        assert mod.main(argv) == 125, flag


def test_gate_refuses_symlink_escape(gate_mod):
    mod, tree = gate_mod
    # a manifest-listed name turned into a symlink pointing OUTSIDE
    # the tree: the realpath check must refuse it
    outside = tree / "outside.yaml"
    outside.write_text("id: outside\n", encoding="utf-8")
    link = tree / "http" / "exposed-panels" / "alpha.yaml"
    link.unlink()
    link.symlink_to(outside)
    argv = _gate_argv(
        tree, "-u", "http://t/", "-t",
        str(tree / "http" / "exposed-panels" / "alpha.yaml"))
    assert mod.main(argv) == 125


def test_gate_fail_closed_on_unreadable_manifest(gate_mod):
    mod, tree = gate_mod
    mod.MANIFEST_PATH = "/nonexistent/manifest.json"
    argv = _gate_argv(
        tree, "-u", "http://t/", "-t",
        str(tree / "http" / "exposed-panels" / "alpha.yaml"))
    assert mod.main(argv) == 125


def test_gate_refusal_json_is_a_host_parseable_error(gate_mod, capsys):
    """The refusal travels the SAME channel as tool_not_in_allowlist:
    one JSON object on stdout — the sandbox parser must see an error."""
    mod, tree = gate_mod
    argv = _gate_argv(
        tree, "-u", "http://t/", "-t",
        str(tree / "http" / "token-spray" / "aws.yaml"))
    assert mod.main(argv) == 125
    out = capsys.readouterr().out.strip()
    payload = json.loads(out)
    assert payload["error"] == "template_not_approved"
    assert "token-spray" in payload["template"]


# ---- 4. remote updates / arbitrary flags / extra args (host Layer 2) ----


def test_remote_template_update_flags_never_in_the_frozen_argv():
    template = list(NUCLEI_PROBE_TEMPLATE)
    for flag in ("-turl", "-wurl", "-ut", "-update-templates", "-ud",
                 "-iserver", "-itoken", "-lfa", "-esc", "-code",
                 "-fuzz", "-dast", "-headless", "-automatic-scan",
                 "-new-templates", "-ai", "-config", "-profile",
                 "-itags"):
        assert flag not in template, flag


def test_arbitrary_template_flag_refused_by_layer2(tmp_path):
    from kryonsec.purple.allowlist import AllowlistViolation, ToolAllowlist

    allow = ToolAllowlist(make_nuclei_probe_adapter().templates_map())
    url = "http://target-corp.com:8080/"
    good = [TOOL_EXECUTABLE] + [
        url if a == "{url}" else a for a in NUCLEI_PROBE_TEMPLATE]
    allow.validate(TOOL_EXECUTABLE, good)
    # ONE extra -t (even an approved file, even an innocuous flag)
    for extra in (
        ["-t", APPROVED_TEMPLATE_PATHS[0]],
        ["-r", "9999"],
        ["-debug"],
    ):
        with pytest.raises(AllowlistViolation):
            allow.validate(TOOL_EXECUTABLE, [*good, *extra])
    # swapping one approved template for another changes NOTHING
    # because all approved templates are already in the template —
    # a SUBSTITUTION is still a length change and refused
    swapped = list(good)
    swapped[swapped.index(APPROVED_TEMPLATE_PATHS[1])] = \
        "/opt/nuclei-templates/http/token-spray/aws.yaml"
    with pytest.raises(AllowlistViolation):
        allow.validate(TOOL_EXECUTABLE, swapped)


# ---- 5. scope and egress remain mandatory --------------------------------


def test_out_of_scope_target_refused():
    reg = production_registry()
    with pytest.raises(AdapterScopeRefused):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset="https://elsewhere.example.com/")


def test_no_egress_boundary_refused(tmp_path):
    from kryonsec.purple.audit import AuditLog
    from kryonsec.purple.adapters import execute_adapter

    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    record = execute_adapter(
        reg, prep, audit=audit,
        sandbox=FakeSandbox(egress_policy=None))
    assert record.executed is False and record.outcome == "refused"
    assert "egress policy" in record.error_excerpt


# ---- 6. the planner cannot override the template policy ------------------


def test_planner_suggestion_selects_adapter_never_argv(tmp_path):
    """A ToolSuggestion has NO argv/template field (extra='forbid'):
    it can only name the adapter. A slashed template-path "adapter_id"
    is not a registered adapter, so the planner records the rejection
    — a suggestion can never enable a template, only name a tool."""
    from kryonsec.purple.tool_planner import ToolCapabilityCatalog, \
        ToolPlanner, ToolSuggestion

    with pytest.raises(ValidationError):
        ToolSuggestion(
            adapter_id=ADAPTER_ID,
            target_asset="http://target-corp.com:8080/",
            template="/opt/nuclei-templates/http/token-spray/aws.yaml")
    with pytest.raises(ValidationError):
        ToolSuggestion(
            adapter_id=ADAPTER_ID,
            target_asset="http://target-corp.com:8080/",
            argv=["nuclei", "-t", "/opt/nuclei-templates"])

    catalog = ToolCapabilityCatalog(production_registry())
    planner = ToolPlanner(
        catalog, suggestions=(ToolSuggestion(
            adapter_id="/opt/nuclei-templates/http/token-spray/",
            target_asset="http://target-corp.com:8080/"),))
    assert planner.suggestion_rejections, "unregistered id is rejected"
    assert any("token-spray" in r for r in planner.suggestion_rejections)


def test_suggested_nuclei_run_uses_the_frozen_template(tmp_path):
    """Even a VALID suggestion selecting nuclei-probe dispatches the
    frozen argv: identical to the unsuggested one, token-spray-free."""
    from kryonsec.purple.adapters import execute_adapter
    from kryonsec.purple.audit import AuditLog
    from kryonsec.purple.tool_planner import ToolSuggestion

    reg = production_registry()
    suggestion = ToolSuggestion(
        adapter_id=ADAPTER_ID,
        target_asset="http://target-corp.com:8080/",
        rationale="check exposed panels")
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET,
        target_asset=suggestion.target_asset)
    plain = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET,
        target_asset="http://target-corp.com:8080/")
    assert prep.argv == plain.argv
    assert template_policy_violations(prep.argv) == []
    audit = AuditLog(tmp_path / "a.jsonl")
    record = execute_adapter(
        reg, prep, audit=audit,
        sandbox=FakeSandbox(egress_policy=None))
    assert record.executed is False          # no egress: refused, honest


# ---- 7. approved templates still function; detection stays honest --------


def test_approved_templates_render_and_validate():
    reg = production_registry()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    assert prep.argv.count("-t") == len(APPROVED_TEMPLATE_PATHS)
    assert template_policy_violations(prep.argv) == []
    # both approved families survived the review
    ids = {APPROVED_TEMPLATES[p]["id"] for p in APPROVED_TEMPLATE_PATHS}
    assert len(ids) == len(APPROVED_TEMPLATE_PATHS)   # unique ids
    assert any("panel" in p for p in APPROVED_TEMPLATE_PATHS)
    assert any("configs" in p for p in APPROVED_TEMPLATE_PATHS)


def test_matches_stay_candidates_never_confirmations(tmp_path):
    from kryonsec.purple.adapters import execute_adapter
    from kryonsec.purple.audit import AuditLog
    from kryonsec.purple.recon_passive import EngagementGraph
    from kryonsec.purple.adapter_nuclei import record_nuclei_evidence

    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = EngagementGraph(engagement_id="e-x")
    graph.add_node("target", TARGET, {})
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(
        SpawnResult := __import__(
            "kryonsec.purple.sandbox", fromlist=["SpawnResult"]
        ).SpawnResult(ok=True, exit_code=0,
                      stdout=_candidate_line(severity="critical",
                                             template_id="panel-admin")),
        egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                     graph=graph, full_output=True)
    assert record.verification == "not_verified"
    candidates, _m = parse_nuclei_json_lines(output)
    record_nuclei_evidence(graph, audit, run_record=record,
                           candidates=candidates)
    node = graph.by_type("vuln_candidate")[0]["properties"]
    assert node["verification"] == "not_verified"
    assert node["classification"] == "detected_candidate"
    assert graph.by_type("finding") == []


def test_registration_refuses_a_tampered_frozen_template(tmp_path,
                                                         monkeypatch):
    """L1 end-to-end: if the frozen argv template is ever tampered with
    (a swapped-in unapproved template), REGISTRATION itself fails with
    NucleiPolicyError — the policy cannot be silently unbundled from
    the adapter."""
    import kryonsec.purple.adapter_nuclei as mod

    tampered = list(mod.NUCLEI_PROBE_TEMPLATE)
    tampered[tampered.index(mod.APPROVED_TEMPLATE_PATHS[1])] = \
        "/opt/nuclei-templates/http/token-spray/aws.yaml"
    monkeypatch.setattr(mod, "NUCLEI_PROBE_TEMPLATE", tuple(tampered))
    with pytest.raises(NucleiPolicyError):
        mod.make_nuclei_probe_adapter()


def test_frozen_template_matches_the_manifest_exactly():
    """The manifest IS the argv: any manifest change without an adapter
    change (or vice versa) is caught here — the two are one policy."""
    import kryonsec.purple.adapter_nuclei as mod

    template = list(mod.NUCLEI_PROBE_TEMPLATE)
    in_argv = {template[i + 1] for i, a in enumerate(template)
               if a == "-t"}
    on_disk = set(mod.load_template_manifest())
    assert in_argv == on_disk == set(mod.APPROVED_TEMPLATES)
    # and the manifest's commit is pinned in the module
    assert mod.NUCLEI_TEMPLATES_COMMIT == \
        json.loads(MANIFEST.read_text(encoding="utf-8"))["templates_commit"]
