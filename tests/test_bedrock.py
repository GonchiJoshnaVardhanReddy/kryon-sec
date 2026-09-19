"""Tests for the AWS Bedrock provider layer: region probing (which is also
the key check), model listing, and litellm model-id formatting.

Everything is offline — the fake control plane below answers per region and
records the URLs and Authorization headers it was sent.
"""

import json
import re
import urllib.error

import pytest

from kryonsec.bedrock import (
    BEDROCK_KEY_HELP,
    BEDROCK_REGIONS,
    DEFAULT_REGION,
    format_model_id,
    list_bedrock_models,
    probe_regions,
)

_MODEL = {
    "modelId": "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "modelName": "Claude 3.5 Sonnet v2",
    "providerName": "Anthropic",
    "modelLifecycle": {"status": "ACTIVE"},
}
_LEGACY_MODEL = {
    "modelId": "old.model-v1:0",
    "modelName": "Old Model",
    "providerName": "Someone",
    "modelLifecycle": {"status": "LEGACY"},
}
_PROFILE = {
    "inferenceProfileId": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "inferenceProfileName": "Claude Sonnet 4.5",
    "type": "SYSTEM_DEFINED",
    "status": "ACTIVE",
}
_APP_PROFILE = {
    "inferenceProfileId": "my-own-profile",
    "inferenceProfileName": "Mine",
    "type": "APPLICATION",
    "status": "ACTIVE",
}


class _Resp:
    def __init__(self, body: dict):
        self.status = 200
        self._body = json.dumps(body).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeBedrock:
    """A stand-in Bedrock control plane.

    `accept` maps region -> {"models": [...], "profiles": [...]}. Regions
    absent from it answer `reject_status`, which is what a key that is not
    valid there (or an expired key) really does.
    """

    def __init__(
        self,
        accept: dict[str, dict] | None = None,
        reject_status: int = 403,
        deny_paths: set[str] | None = None,
        network_error: bool = False,
    ):
        self.accept = accept or {}
        self.reject_status = reject_status
        self.deny_paths = deny_paths or set()
        self.network_error = network_error
        self.calls: list[tuple[str, str, str | None]] = []  # region, path, auth
        self.urls: list[str] = []

    def __call__(self, req, timeout):
        match = re.match(
            r"https://bedrock\.([a-z0-9-]+)\.amazonaws\.com(\S*)", req.full_url
        )
        assert match, f"unexpected URL {req.full_url}"
        region, path = match.group(1), match.group(2)
        self.calls.append((region, path, req.get_header("Authorization")))
        self.urls.append(req.full_url)

        if self.network_error:
            raise OSError("no network")
        if region not in self.accept or any(path.startswith(p) for p in self.deny_paths):
            raise urllib.error.HTTPError(
                req.full_url, self.reject_status, "Forbidden", {}, None  # type: ignore[arg-type]
            )
        body = self.accept[region]
        if path.startswith("/inference-profiles"):
            return _Resp({"inferenceProfileSummaries": body.get("profiles", [])})
        return _Resp({"modelSummaries": body.get("models", [])})

    @property
    def regions_probed(self) -> set[str]:
        return {region for region, _, _ in self.calls}


@pytest.fixture()
def fake(monkeypatch):
    def install(**kwargs) -> FakeBedrock:
        server = FakeBedrock(**kwargs)
        monkeypatch.setattr(
            "kryonsec.bedrock.urllib.request.urlopen", server)
        return server

    return install


# ---- region probing (also the key check) ----------------------------------

def test_probe_regions_finds_the_keys_region(fake):
    server = fake(accept={"us-east-1": {"models": [_MODEL]}})
    assert probe_regions("ABSKtestkey") == ["us-east-1"]


def test_probe_regions_sends_the_key_as_a_bearer_token(fake):
    server = fake(accept={"eu-west-1": {}})
    probe_regions("ABSKtestkey")
    auths = {auth for _, _, auth in server.calls}
    assert auths == {"Bearer ABSKtestkey"}


def test_probe_regions_empty_key_makes_no_calls(fake):
    server = fake(accept={"us-east-1": {}})
    assert probe_regions("   ") == []
    assert server.calls == []


def test_probe_regions_rejected_everywhere_is_empty(fake):
    """A wrong/expired key gets 403 from every region — that is the signal
    the wizard turns into 'that key was rejected'."""
    fake(accept={})
    assert probe_regions("ABSKbad") == []


def test_probe_regions_network_failure_is_not_a_match(fake):
    """A dead network must read as 'no regions', never as success."""
    fake(network_error=True)
    assert probe_regions("ABSKwhatever") == []


def test_probe_regions_returns_canonical_order(fake):
    """Several regions can accept one key; the output order must be stable
    run to run, not the order the threads happened to finish in."""
    fake(accept={"ap-south-1": {}, "us-east-1": {}, "eu-central-1": {}})
    found = probe_regions("ABSKmulti")
    assert found == [
        r for r in BEDROCK_REGIONS if r in {"ap-south-1", "us-east-1", "eu-central-1"}
    ]
    assert found[0] == "us-east-1"  # the most common region leads


def test_probe_regions_honours_an_explicit_region_list(fake):
    server = fake(accept={"us-east-1": {}, "us-west-2": {}})
    assert probe_regions("ABSKx", regions=["us-west-2"]) == ["us-west-2"]
    assert server.regions_probed == {"us-west-2"}


# ---- model listing --------------------------------------------------------

def test_list_bedrock_models_returns_active_chat_models(fake):
    fake(accept={"us-east-1": {"models": [_MODEL]}})
    models = list_bedrock_models("ABSKx", "us-east-1")
    assert models is not None
    assert [m["id"] for m in models] == [_MODEL["modelId"]]
    assert models[0]["kind"] == "foundation-model"
    assert "Anthropic" in models[0]["label"]


def test_list_bedrock_models_drops_legacy(fake):
    fake(accept={"us-east-1": {"models": [_MODEL, _LEGACY_MODEL]}})
    models = list_bedrock_models("ABSKx", "us-east-1")
    assert [m["id"] for m in models] == [_MODEL["modelId"]]


def test_list_bedrock_models_asks_for_text_on_demand_only(fake):
    server = fake(accept={"us-east-1": {"models": []}})
    list_bedrock_models("ABSKx", "us-east-1")
    paths = [path for _, path, _ in server.calls]
    assert any(
        p.startswith("/foundation-models?")
        and "byOutputModality=TEXT" in p
        and "byInferenceType=ON_DEMAND" in p
        for p in paths
    )


def test_list_bedrock_models_puts_inference_profiles_first(fake):
    """Newer Anthropic models reject on-demand invocation by base model id,
    so the profile has to be the easy pick, not buried."""
    fake(accept={"us-east-1": {"models": [_MODEL], "profiles": [_PROFILE]}})
    models = list_bedrock_models("ABSKx", "us-east-1")
    assert [m["id"] for m in models] == [_PROFILE["inferenceProfileId"], _MODEL["modelId"]]
    assert models[0]["kind"] == "inference-profile"
    assert "cross-region profile" in models[0]["label"]


def test_list_bedrock_models_skips_application_profiles(fake):
    """APPLICATION profiles are the user's own; offering them would be
    guessing about an account we cannot see."""
    fake(accept={"us-east-1": {"models": [], "profiles": [_APP_PROFILE, _PROFILE]}})
    models = list_bedrock_models("ABSKx", "us-east-1")
    assert [m["id"] for m in models] == [_PROFILE["inferenceProfileId"]]


def test_list_bedrock_models_survives_a_denied_inference_profile_call(fake):
    """A key scoped to Bedrock *runtime* only cannot list profiles. That
    must degrade to base models, not break setup."""
    fake(
        accept={"us-east-1": {"models": [_MODEL]}},
        deny_paths={"/inference-profiles"},
    )
    models = list_bedrock_models("ABSKx", "us-east-1")
    assert [m["id"] for m in models] == [_MODEL["modelId"]]


def test_list_bedrock_models_none_when_the_catalog_is_unreadable(fake):
    """None = 'could not read', which the wizard turns into 'type the id
    manually' — distinct from [] = 'read fine, nothing matched'."""
    fake(accept={})
    assert list_bedrock_models("ABSKbad", "us-east-1") is None


def test_list_bedrock_models_empty_when_nothing_matches(fake):
    fake(accept={"us-east-1": {"models": [_LEGACY_MODEL]}})
    assert list_bedrock_models("ABSKx", "us-east-1") == []


# ---- model id formatting + help text --------------------------------------

def test_format_model_id_adds_the_litellm_prefix():
    """Without the bedrock/ prefix litellm treats the id as an OpenAI model
    and never applies the region or the bearer token."""
    assert format_model_id("anthropic.claude-v2") == "bedrock/anthropic.claude-v2"


def test_format_model_id_does_not_double_prefix():
    assert format_model_id("bedrock/anthropic.claude-v2") == "bedrock/anthropic.claude-v2"


def test_default_region_is_a_real_bedrock_region():
    assert DEFAULT_REGION in BEDROCK_REGIONS


# ---- discovery must stay on the control plane ------------------------------

def test_discovery_only_uses_the_control_plane(fake):
    """Regression guard on where discovery is allowed to go.

    Model discovery uses ListFoundationModels + ListInferenceProfiles on the
    Bedrock **control plane** (bedrock.<region>.amazonaws.com). Two other
    surfaces exist and neither is a discovery source:

    - ``bedrock-runtime.<region>`` serves inference only.
    - the OpenAI-compatible ``/v1/models`` endpoint belongs to the separate
      compatibility service, and says nothing about which model ids this
      account may actually invoke.

    Drifting onto either would silently give a wrong model list, so pin it.
    """
    server = fake(accept={"us-east-1": {"models": [_MODEL], "profiles": [_PROFILE]}})
    probe_regions("ABSKx", regions=["us-east-1"])
    list_bedrock_models("ABSKx", "us-east-1")

    # the WHOLE scan above succeeds against a regex that only matches
    # bedrock.<region>, i.e. nothing hit the runtime or a compat host
    assert server.urls
    for url in server.urls:
        assert url.startswith("https://bedrock.")
        assert "bedrock-runtime" not in url
        assert "/v1/models" not in url

    paths = {url.split(".com", 1)[1].split("?")[0] for url in server.urls}
    assert paths == {"/foundation-models", "/inference-profiles"}


def test_inference_profile_call_targets_the_control_plane(fake):
    """The profile lookup is the one most likely to be 'helpfully' pointed at
    the runtime host, so assert its host explicitly."""
    server = fake(accept={"eu-west-1": {"profiles": [_PROFILE]}})
    list_bedrock_models("ABSKx", "eu-west-1")
    profile_urls = [u for u in server.urls if "/inference-profiles" in u]
    assert profile_urls
    assert all(u.startswith("https://bedrock.eu-west-1.amazonaws.com") for u in profile_urls)


def test_key_help_tells_the_user_where_to_get_a_key():
    assert "Bedrock" in BEDROCK_KEY_HELP
    assert "ABSK" in BEDROCK_KEY_HELP  # what the key looks like
    assert "Model access" in BEDROCK_KEY_HELP  # the other way calls fail
