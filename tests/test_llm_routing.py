"""Tests for the LLM routing (spec §7.1, §6.4) — v1.1 strict provider
isolation: an openai config never calls Ollama and an ollama config never
calls a hosted API. Fallbacks stay inside the selected provider."""

from unittest.mock import patch

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.llm import (
    CompactionMustStayLocal,
    LlmUnavailable,
    SecretsMustStayLocal,
    _ollama_model_ok,
    build_call,
    chat,
    completion_kwargs,
    is_reasoning_model,
    litellm_model,
    reset_provider_cache,
    scrub_secrets,
    secrets_safe_prompt,
)
from secret_fixtures import aws_access_key


@pytest.fixture()
def cfg():
    reset_provider_cache()
    c = KryonsecConfig()
    c.provider = "openai"
    c.general_chat_model = "gpt-4o"  # a hosted chat model (default is ollama/)
    c.openai_api_key = "sk-test"  # hosted API available (.env no longer auto-loads)
    yield c
    reset_provider_cache()


@pytest.fixture()
def ollama_cfg():
    reset_provider_cache()
    c = KryonsecConfig()
    c.provider = "ollama"
    c.openai_api_key = None  # isolation: nothing hosted is even configured
    yield c
    reset_provider_cache()


@pytest.fixture()
def bedrock_cfg():
    reset_provider_cache()
    c = KryonsecConfig()
    c.provider = "bedrock"
    c.bedrock_api_key = "ABSKtest"
    c.bedrock_region = "us-east-1"
    c.general_chat_model = "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0"
    c.general_search_model = c.general_chat_model
    c.compaction_model = c.general_chat_model
    c.openai_api_key = None
    yield c
    reset_provider_cache()


def test_ollama_provider_dead_ollama_is_a_hard_error(ollama_cfg):
    """Ollama config + dead Ollama = clear error, NOT a hosted fallback."""
    with (
        patch("kryonsec.llm._complete", side_effect=RuntimeError("ollama down")),
        patch("kryonsec.llm._ollama_model_ok", return_value=False),
    ):
        with pytest.raises(LlmUnavailable, match="[Oo]llama"):
            chat(ollama_cfg, [], "ollama/llama3.1")


def test_ollama_provider_never_calls_hosted(ollama_cfg):
    """Even a gpt-style model name routes to the local model — never
    silently out to a third-party API."""
    with (
        patch("kryonsec.llm._complete", return_value="local answer") as fake,
        patch("kryonsec.llm._ollama_model_ok", return_value=True),
    ):
        assert chat(ollama_cfg, [], "gpt-4o-mini") == "local answer"
    assert fake.call_args[0][1].startswith("ollama/")


def test_ollama_provider_unpulled_model_is_a_hard_error(ollama_cfg):
    """Server up but model not pulled: /api/chat would hang — raise a clear
    error instead of falling back or timing out."""
    with (
        patch("kryonsec.llm._complete", side_effect=RuntimeError("hang")),
        patch("kryonsec.llm._ollama_model_ok",
              side_effect=lambda c, m: "llama3.1" not in m),
    ):
        with pytest.raises(LlmUnavailable, match="not pulled"):
            chat(ollama_cfg, [], "ollama/llama3.1")


def test_openai_provider_ollama_model_rerouted_to_chat_model(cfg):
    """OpenAI config + an ollama/ model name = use the configured chat
    model, never a silent local call."""
    with patch("kryonsec.llm._complete", return_value="hosted answer") as fake:
        assert chat(cfg, [], "ollama/llama3.1") == "hosted answer"
    assert fake.call_args[0][1] == cfg.general_chat_model


def test_openai_provider_falls_back_within_provider(cfg):
    """Chat model fails -> the cheap search model (same provider) answers."""
    calls = []

    def fake_complete(c, model, messages, **kw):
        calls.append(model)
        if model == cfg.general_chat_model:
            raise RuntimeError("primary down")
        return "search-model answer"

    with patch("kryonsec.llm._complete", side_effect=fake_complete):
        assert chat(cfg, [], cfg.general_chat_model) == "search-model answer"
    assert calls == [cfg.general_chat_model, cfg.general_search_model]


def test_openai_provider_no_key_is_a_clear_error(cfg):
    cfg.openai_api_key = None
    with pytest.raises(LlmUnavailable, match="setup"):
        chat(cfg, [], "gpt-4o-mini")


def test_local_only_refuses_third_party_when_local_down(cfg):
    cfg.openai_api_key = "sk-test"  # third party IS available

    with (
        patch("kryonsec.llm._complete", side_effect=RuntimeError("ollama down")),
        patch("kryonsec.llm._ollama_ok", return_value=False),
    ):
        with pytest.raises(CompactionMustStayLocal):
            chat(cfg, [], "gpt-4o-mini", local_only=True)  # secrets path


def test_local_only_uses_local_when_alive(cfg):
    with (
        patch("kryonsec.llm._complete", return_value="local answer") as fake,
        patch("kryonsec.llm._ollama_ok", return_value=True),
    ):
        assert chat(cfg, [], "gpt-4o-mini", local_only=True) == "local answer"
    assert fake.call_args[0][1].startswith("ollama/")


def test_ollama_model_ok_matches_base_name(cfg):
    with patch("kryonsec.llm._ollama_ok", return_value=True), patch(
        "kryonsec.llm._ollama_models", ["llama3.1:latest", "mistral:7b"]
    ):
        assert _ollama_model_ok(cfg, "ollama/llama3.1")
        assert not _ollama_model_ok(cfg, "ollama/llama3")
        assert not _ollama_model_ok(cfg, "ollama/gemma2")
        # non-ollama models are not our business here
        assert _ollama_model_ok(cfg, "gpt-4o-mini")


# ---- completion_kwargs: provider + reasoning-model quirks -------------------

def test_is_reasoning_model_prefixes():
    assert is_reasoning_model("gpt-6-astra")
    assert is_reasoning_model("openai/gpt-6-astra")
    assert is_reasoning_model("gpt-5.5")
    assert is_reasoning_model("o3-mini")
    assert not is_reasoning_model("gpt-4o-mini")
    assert not is_reasoning_model("ollama/llama3.1")


def test_completion_kwargs_plain_model_gets_temperature(cfg):
    kw = completion_kwargs(cfg, "gpt-4o-mini")
    assert kw["temperature"] == 0.0
    assert kw["api_key"] == "sk-test"
    assert "reasoning_effort" not in kw


def test_completion_kwargs_reasoning_model_no_temperature(cfg):
    kw = completion_kwargs(cfg, "gpt-6-astra")
    assert "temperature" not in kw
    assert kw["api_key"] == "sk-test"


def test_completion_kwargs_reasoning_with_tools_sets_effort_none(cfg):
    kw = completion_kwargs(cfg, "gpt-6-astra", tools=True)
    assert kw["reasoning_effort"] == "none"
    # litellm refuses to forward reasoning_effort without this
    assert kw["allowed_openai_params"] == ["reasoning_effort"]
    assert "temperature" not in kw


def test_completion_kwargs_plain_with_tools_no_effort(cfg):
    kw = completion_kwargs(cfg, "gpt-4o-mini", tools=True)
    assert kw["temperature"] == 0.0
    assert "reasoning_effort" not in kw


def test_completion_kwargs_ollama_gets_api_base(cfg):
    cfg.ollama_host = "localhost:11434"
    kw = completion_kwargs(cfg, "ollama/llama3.1")
    assert kw["api_base"].endswith(":11434")
    assert "api_key" not in kw


# ---- secrets gate (spec §6.4 / CLAUDE.md rule 4) --------------------------

def test_hosted_call_with_secrets_routes_to_local(cfg):
    """A message containing a secret never reaches the hosted provider —
    the call is re-routed to the local model (chat path, general form)."""
    messages = [{"role": "user", "content": f"my key is {aws_access_key()}"}]
    with (
        patch("kryonsec.llm._ollama_model_ok", return_value=True),
        patch("kryonsec.llm._complete", return_value="ok") as complete,
    ):
        out = chat(cfg, messages, "gpt-4o")
        assert out == "ok"
        assert complete.call_args[0][1].startswith("ollama/")  # model arg


def test_hosted_call_with_secrets_no_local_refuses(cfg):
    """Secrets + no local model = hard refusal, never a hosted call."""
    messages = [{"role": "user", "content": f"my key is {aws_access_key()}"}]
    with (
        patch("kryonsec.llm._ollama_model_ok", return_value=False),
        patch("kryonsec.llm._complete") as complete,
    ):
        with pytest.raises(SecretsMustStayLocal):
            chat(cfg, messages, "gpt-4o")
        complete.assert_not_called()


def test_hosted_call_without_secrets_unchanged(cfg):
    messages = [{"role": "user", "content": "what is XSS?"}]
    with (
        patch("kryonsec.llm._ollama_model_ok", return_value=True),
        patch("kryonsec.llm._complete", return_value="ok") as complete,
    ):
        chat(cfg, messages, "gpt-4o")
        assert complete.call_args[0][1] == "gpt-4o"


def test_local_call_with_secrets_unchanged(ollama_cfg):
    """Ollama never leaves the machine — secrets pass through fine."""
    messages = [{"role": "user", "content": f"my key is {aws_access_key()}"}]
    with (
        patch("kryonsec.llm._ollama_model_ok", return_value=True),
        patch("kryonsec.llm._complete", return_value="ok") as complete,
    ):
        chat(ollama_cfg, messages, "ollama/llama3.1")
        assert complete.call_args[0][1] == "ollama/llama3.1"


# ---- secrets_safe_prompt (the purple-team LLM-state gate, spec §6.4) --------

def test_secrets_safe_prompt_routes_to_local(cfg):
    """Secrets in engagement data + local model up -> local, prompt raw
    (it never leaves the machine)."""
    with patch("kryonsec.llm._ollama_model_ok", return_value=True):
        model, prompt = secrets_safe_prompt(
            cfg, "gpt-4o", "recon: password=hunter2secret")
    assert model.startswith("ollama/")
    assert prompt == "recon: password=hunter2secret"


def test_secrets_safe_prompt_redacts_when_no_local(cfg):
    """Secrets + no local model: never raises (a false-positive pattern
    must not kill an LLM state) — the prompt goes out redacted instead."""
    with patch("kryonsec.llm._ollama_model_ok", return_value=False):
        model, prompt = secrets_safe_prompt(
            cfg, "gpt-4o", "recon: password=hunter2secret")
    assert model == "gpt-4o"
    assert "hunter2secret" not in prompt
    assert "password=" in prompt  # label kept, value placeholdered


def test_secrets_safe_prompt_no_secrets_unchanged(cfg):
    model, prompt = secrets_safe_prompt(cfg, "gpt-4o", "what is XSS?")
    assert (model, prompt) == ("gpt-4o", "what is XSS?")


def test_secrets_safe_prompt_local_model_passes_through(ollama_cfg):
    model, prompt = secrets_safe_prompt(
        ollama_cfg, "ollama/llama3.1", "recon: password=hunter2secret")
    assert (model, prompt) == ("ollama/llama3.1", "recon: password=hunter2secret")


# ---- AWS Bedrock: same provider isolation + secrets gate as any hosted API --

def test_bedrock_routes_to_bedrocks_openai_endpoint(cfg):
    """bedrock/<id> becomes a litellm OpenAI-compatible call against the
    Bedrock runtime host for the configured region, carrying the Bedrock
    key — and nothing that would make litellm reach for SigV4."""
    cfg.bedrock_api_key = "ABSKtest"
    cfg.bedrock_region = "ap-south-1"
    call = build_call(cfg, "bedrock/anthropic.claude-v2")
    assert call["model"] == "openai/anthropic.claude-v2"
    assert call["api_base"] == (
        "https://bedrock-runtime.ap-south-1.amazonaws.com/openai/v1")
    assert call["api_key"] == "ABSKtest"
    # the SigV4 route's kwargs: any of these present and litellm picks the
    # Converse handler, which needs static credentials a bearer token is not
    for absent in ("aws_region_name", "aws_access_key_id",
                   "aws_secret_access_key", "aws_session_token"):
        assert absent not in call, absent


def test_bedrock_region_travels_in_the_url(cfg):
    """There is no aws_region_name to get wrong — the endpoint IS the region."""
    cfg.bedrock_api_key = "ABSKtest"
    cfg.bedrock_region = "eu-west-1"
    call = build_call(cfg, "bedrock/amazon.nova-pro-v1:0")
    assert "eu-west-1" in call["api_base"]
    assert call["model"] == "openai/amazon.nova-pro-v1:0"


def test_bedrock_prefix_is_the_only_thing_translated(cfg):
    """kryonsec's id format is unchanged — one prefix swap, nothing else.

    Inference-profile ids (`us.`, `global.`) and version suffixes like `:0`
    must survive verbatim; they are part of the model id AWS expects.
    """
    cfg.bedrock_api_key = "ABSKtest"
    assert litellm_model(cfg, "bedrock/global.anthropic.claude-fable-5") == \
        "openai/global.anthropic.claude-fable-5"
    assert litellm_model(cfg, "bedrock/us.anthropic.claude-sonnet-4-5-v1:0") == \
        "openai/us.anthropic.claude-sonnet-4-5-v1:0"
    # non-bedrock ids pass through untouched
    assert litellm_model(cfg, "gpt-4o") == "gpt-4o"
    assert litellm_model(cfg, "ollama/llama3.1") == "ollama/llama3.1"


def test_bedrock_without_a_key_refuses_before_building_the_call(cfg):
    """The dangerous shape: no api_key in the dict makes litellm fall back
    to OPENAI_API_KEY from the environment, which would put an OpenAI
    credential in a header aimed at AWS."""
    cfg.bedrock_api_key = None
    with pytest.raises(LlmUnavailable, match="Bedrock"):
        build_call(cfg, "bedrock/anthropic.claude-v2")


def test_bedrock_call_never_loses_its_bedrock_endpoint(cfg):
    """Whatever else changes, an `openai/` model with the Bedrock key must
    always carry the Bedrock api_base. Without it litellm sends the request
    to api.openai.com — the key leak this whole route exists to prevent."""
    cfg.bedrock_api_key = "ABSKtest"
    cfg.bedrock_region = "us-east-1"
    for model in ("bedrock/anthropic.claude-v2", "bedrock/amazon.nova-lite-v1:0"):
        call = build_call(cfg, model)
        assert call["model"].startswith("openai/")
        assert call["api_base"] == (
            "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1")
        assert "api.openai.com" not in call["api_base"]


def test_completion_kwargs_takes_kryonsecs_id_not_the_routed_one(cfg):
    """The trap build_call exists to close.

    completion_kwargs keys its branches off the prefix, so handing it the
    already-routed `openai/<id>` matches the OpenAI branch and attaches
    cfg.openai_api_key. build_call's contract is that callers pass
    kryonsec's id; this test pins the reason.
    """
    cfg.bedrock_api_key = "ABSKtest"
    cfg.openai_api_key = "sk-test"
    kw = completion_kwargs(cfg, "bedrock/anthropic.claude-v2")
    assert kw["api_key"] == "ABSKtest"  # bedrock's key, not OpenAI's
    assert "api.openai.com" not in kw["api_base"]
    # and the misuse it warns about, for the record:
    wrong = completion_kwargs(cfg, "openai/anthropic.claude-v2")
    assert wrong["api_key"] == "sk-test"
    assert "api_base" not in wrong


def test_complete_sends_the_translated_call_to_litellm(bedrock_cfg):
    """End to end through the real invocation layer: what litellm is
    actually handed for a `bedrock/<id>` model."""
    with patch("litellm.completion") as fake:
        fake.return_value.choices = [
            type("C", (), {"message": type("M", (), {"content": "hi",
                                                     "tool_calls": None})()})()]
        from kryonsec.llm import _complete

        _complete(bedrock_cfg, "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0",
                  [{"role": "user", "content": "hi"}])
    kwargs = fake.call_args.kwargs
    assert kwargs["model"] == "openai/anthropic.claude-3-5-sonnet-20241022-v2:0"
    assert kwargs["api_base"] == (
        "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1")
    assert kwargs["api_key"] == "ABSKtest"
    assert "aws_region_name" not in kwargs


def test_bedrock_config_reroutes_a_non_bedrock_model(bedrock_cfg):
    """Provider isolation: a bedrock config must never quietly call OpenAI
    just because the caller passed a gpt-style model name."""
    with patch("kryonsec.llm._complete", return_value="bedrock answer") as fake:
        assert chat(bedrock_cfg, [], "gpt-4o-mini") == "bedrock answer"
    assert fake.call_args[0][1] == bedrock_cfg.general_chat_model


def test_bedrock_config_keeps_its_own_model(bedrock_cfg):
    with patch("kryonsec.llm._complete", return_value="ok") as fake:
        chat(bedrock_cfg, [], bedrock_cfg.general_chat_model)
    assert fake.call_args[0][1] == bedrock_cfg.general_chat_model


def test_bedrock_config_falls_back_within_provider(bedrock_cfg):
    """Chat model fails -> the search model (same provider) answers. Nothing
    here may reach Ollama or OpenAI."""
    bedrock_cfg.general_search_model = "bedrock/amazon.nova-pro-v1:0"
    calls = []

    def fake_complete(c, model, messages, **kw):
        calls.append(model)
        if model == bedrock_cfg.general_chat_model:
            raise RuntimeError("bedrock down")
        return "nova answer"

    with patch("kryonsec.llm._complete", side_effect=fake_complete):
        assert chat(bedrock_cfg, [], bedrock_cfg.general_chat_model) == "nova answer"
    assert calls == [bedrock_cfg.general_chat_model, bedrock_cfg.general_search_model]


def test_bedrock_no_key_is_a_clear_error(bedrock_cfg):
    bedrock_cfg.bedrock_api_key = None
    with pytest.raises(LlmUnavailable, match="setup"):
        chat(bedrock_cfg, [], bedrock_cfg.general_chat_model)


def test_bedrock_error_names_bedrock_not_openai(bedrock_cfg):
    """The message has to point at the right key, or the user edits the
    wrong one."""
    bedrock_cfg.bedrock_api_key = None
    with pytest.raises(LlmUnavailable, match="Bedrock"):
        chat(bedrock_cfg, [], bedrock_cfg.general_chat_model)


def test_bedrock_call_with_secrets_routes_to_local(bedrock_cfg):
    """CLAUDE.md rule 4: AWS is a third party, so a secret-bearing message
    is re-routed to the local model exactly as it would be for OpenAI."""
    messages = [{"role": "user", "content": f"my key is {aws_access_key()}"}]
    with (
        patch("kryonsec.llm._ollama_model_ok", return_value=True),
        patch("kryonsec.llm._complete", return_value="ok") as complete,
    ):
        assert chat(bedrock_cfg, messages, bedrock_cfg.general_chat_model) == "ok"
    assert complete.call_args[0][1].startswith("ollama/")


def test_bedrock_call_with_secrets_and_no_local_refuses(bedrock_cfg):
    messages = [{"role": "user", "content": f"my key is {aws_access_key()}"}]
    with (
        patch("kryonsec.llm._ollama_model_ok", return_value=False),
        patch("kryonsec.llm._complete") as complete,
    ):
        with pytest.raises(SecretsMustStayLocal):
            chat(bedrock_cfg, messages, bedrock_cfg.general_chat_model)
        complete.assert_not_called()  # nothing left the machine


def test_bedrock_secrets_safe_prompt_redacts_when_no_local(bedrock_cfg):
    with patch("kryonsec.llm._ollama_model_ok", return_value=False):
        model, prompt = secrets_safe_prompt(
            bedrock_cfg, bedrock_cfg.general_chat_model,
            "recon: password=hunter2secret")
    assert model == bedrock_cfg.general_chat_model
    assert "hunter2secret" not in prompt


def test_openai_config_reroutes_a_bedrock_model(cfg):
    """The mirror case: before Bedrock existed, only an ollama/ prefix was
    treated as foreign, so a bedrock/ id would have escaped isolation."""
    with patch("kryonsec.llm._complete", return_value="hosted answer") as fake:
        assert chat(cfg, [], "bedrock/anthropic.claude-v2") == "hosted answer"
    assert fake.call_args[0][1] == cfg.general_chat_model


def test_unknown_provider_falls_back_to_openai_rules(cfg):
    """A hand-edited provider value must not become an unguarded call."""
    cfg.provider = "wat"
    with patch("kryonsec.llm._complete", return_value="ok") as fake:
        assert chat(cfg, [], "gpt-4o-mini") == "ok"
    assert fake.call_args[0][1] == "gpt-4o-mini"


# ---- the regression bar: OpenAI and Ollama must be untouched by the above ---

def test_openai_call_is_still_a_plain_openai_call(cfg):
    """Bedrock's translation must not have reached the OpenAI path: bare
    model id, OpenAI's key, and no api_base override — so litellm goes to
    api.openai.com exactly as it did before Bedrock existed."""
    cfg.openai_api_key = "sk-test"
    call = build_call(cfg, "gpt-4o-mini")
    assert call["model"] == "gpt-4o-mini"
    assert call["api_key"] == "sk-test"
    assert "api_base" not in call  # nothing redirects it off api.openai.com
    assert "aws_region_name" not in call


def test_openai_complete_sends_the_same_call_as_before(cfg):
    with patch("litellm.completion") as fake:
        fake.return_value.choices = [
            type("C", (), {"message": type("M", (), {"content": "hi",
                                                     "tool_calls": None})()})()]
        from kryonsec.llm import _complete

        _complete(cfg, "gpt-4o-mini", [{"role": "user", "content": "hi"}])
    kwargs = fake.call_args.kwargs
    assert kwargs["model"] == "gpt-4o-mini"
    assert kwargs["api_key"] == "sk-test"
    assert "api_base" not in kwargs


def test_openai_never_gets_the_bedrock_key(cfg):
    """Provider isolation, credential half: a Bedrock key sitting in
    config.toml must not ride along on an OpenAI call."""
    cfg.bedrock_api_key = "ABSKtest"
    cfg.openai_api_key = "sk-test"
    assert build_call(cfg, "gpt-4o-mini")["api_key"] == "sk-test"


def test_ollama_call_is_unchanged(cfg):
    """Ollama's branch is chosen first and untouched: the host, no key, no
    Bedrock endpoint, and the id is passed through as-is."""
    cfg.ollama_host = "localhost:11434"
    cfg.bedrock_api_key = "ABSKtest"
    call = build_call(cfg, "ollama/llama3.1")
    assert call["model"] == "ollama/llama3.1"
    assert call["api_base"].endswith(":11434")
    assert "api_key" not in call
    assert "amazonaws.com" not in call["api_base"]


def test_bedrock_key_never_reaches_a_log_line(cfg, caplog):
    """A failed call logs the provider's own error, and a provider error
    can quote the request back — Authorization header included."""
    cfg.bedrock_api_key = "ABSKtest"

    leak = RuntimeError(
        "litellm.APIError: Error code: 400 - "
        "{'error': {'message': 'bad request', 'headers': "
        "{'Authorization': 'Bearer ABSKtest'}}}")
    with patch("litellm.completion", side_effect=leak):
        from kryonsec.llm import _complete

        with caplog.at_level("WARNING"):
            with pytest.raises(RuntimeError):
                _complete(cfg, "bedrock/anthropic.claude-v2",
                          [{"role": "user", "content": "hi"}])
    assert "ABSKtest" not in caplog.text
    assert "«redacted»" in caplog.text


def test_bedrock_key_never_reaches_the_users_error_message(cfg):
    """provider_reason feeds the message the user reads — same scrub."""
    from kryonsec.llm import provider_reason

    exc = RuntimeError(
        "Error code: 403 - {'message': 'Operation not allowed', "
        "'x-amz-security-token': 'ABSKtest'}")
    reason = provider_reason(exc)
    assert "ABSKtest" not in reason
    assert "Operation not allowed" in reason  # the useful part survives


def test_scrub_secrets_covers_both_providers_keys():
    assert "ABSKtest" not in scrub_secrets("key=ABSKtest")
    assert "sk-test" not in scrub_secrets("key=sk-abcdefghijklmnop")
    # the scheme word is worth keeping — it says what was wrong
    assert scrub_secrets("Authorization: Bearer ABSKtest") == \
        "Authorization: Bearer «redacted»"
    assert scrub_secrets("no credentials here") == "no credentials here"
