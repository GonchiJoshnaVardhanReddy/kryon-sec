"""AWS Bedrock provider support: key check, region discovery, model listing.

Bedrock is a **hosted** (third-party) provider, so it falls under the same
secrets gate as OpenAI (spec §6.4 / CLAUDE.md rule 4). That gate keys off
`model.startswith("ollama/")` in llm.py, and every id this module returns
carries the `bedrock/` litellm prefix — so a Bedrock config can never be
mistaken for a local one and secrets still route to Ollama or get redacted.

Auth is a Bedrock **API key**: an opaque bearer token (``ABSK…``) created in
the Bedrock console. It carries no region — AWS selects the region from the
endpoint host — so the region is *discovered by probing* rather than read
out of the key. The standard env var is ``AWS_BEARER_TOKEN_BEDROCK``.

Everything here is stdlib-only (urllib), matching the wizard's OpenAI
helpers. litellm forwards ``api_key`` as the bearer token and
``aws_region_name`` as the region (see litellm/llms/bedrock/base_aws_llm.py).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

# Regions where Bedrock runs, most commonly used first: when several answer
# the probe, the user is shown them in this order.
BEDROCK_REGIONS = [
    "us-east-1",
    "us-west-2",
    "us-east-2",
    "us-west-1",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-southeast-3",
    "ca-central-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
    "eu-south-1",
    "sa-east-1",
]

DEFAULT_REGION = "us-east-1"

# litellm routes on this prefix; without it the model id is treated as an
# OpenAI model and the region/key kwargs are never applied.
MODEL_PREFIX = "bedrock/"

PROBE_TIMEOUT_S = 6
LIST_TIMEOUT_S = 15

# Shown by the wizard before asking for the key. Plain English, no jargon —
# this is the step users get stuck on.
BEDROCK_KEY_HELP = """\
How to get an AWS Bedrock API key:
  1. Sign in to the AWS Console, then open the Amazon Bedrock console.
  2. Pick the region you want to use (region selector, top right).
  3. Open "API keys" in the left menu.
  4. Click "Generate API key" and pick a long-term key, so it does not
     expire in a few hours like a short-term one.
  5. Copy the key now (it starts with ABSK) — AWS never shows it again.

Note: the model you choose must also be enabled for your account under
Bedrock > "Model access", otherwise calls fail with AccessDenied."""


def _endpoint(region: str) -> str:
    return f"https://bedrock.{region}.amazonaws.com"


def _get(
    region: str, path: str, query: str, api_key: str, timeout: int
) -> tuple[int, dict[str, Any] | None]:
    """GET a Bedrock control-plane path with the key as a bearer token.

    Returns (status, body). status is 0 when the request never completed
    (DNS/TLS/timeout), and the HTTP code otherwise — callers distinguish
    "this region rejected the key" (403) from "nothing answered" (0).
    """
    request = urllib.request.Request(
        f"{_endpoint(region)}{path}{query}",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return 0, None


def probe_regions(
    api_key: str,
    regions: list[str] | None = None,
    timeout: int = PROBE_TIMEOUT_S,
) -> list[str]:
    """Every region where ``api_key`` is accepted, in BEDROCK_REGIONS order.

    A Bedrock API key is opaque, so there is no region to decode — the only
    way to find it is to ask each regional endpoint. 200 means the key is
    good there; 403 means it is not.

    This doubles as the key check: an empty result means the key was
    rejected everywhere (wrong, revoked, or expired).
    """
    key = (api_key or "").strip()
    if not key:
        return []
    candidates = regions if regions is not None else BEDROCK_REGIONS
    if not candidates:
        return []

    found: set[str] = set()
    # Bounded fan-out: 18 sequential 6 s timeouts would take a minute and a
    # half, and setup must not feel broken.
    with ThreadPoolExecutor(max_workers=min(8, len(candidates))) as pool:
        futures = {
            pool.submit(
                _get, region, "/foundation-models", "", key, timeout
            ): region
            for region in candidates
        }
        for future in as_completed(futures):
            region = futures[future]
            try:
                status, _ = future.result()
            except Exception:  # pragma: no cover - future swallows already
                continue
            if status == 200:
                found.add(region)
    # canonical order, not completion order — the wizard's output must be
    # deterministic run to run
    return [r for r in candidates if r in found]


def format_model_id(model_id: str) -> str:
    """The litellm model string for a Bedrock model id."""
    model_id = model_id.strip()
    if model_id.startswith(MODEL_PREFIX):
        return model_id
    return f"{MODEL_PREFIX}{model_id}"


def _list_inference_profiles(
    api_key: str, region: str, timeout: int = LIST_TIMEOUT_S
) -> list[dict[str, Any]]:
    """System-defined cross-region inference profiles.

    Never raises and never fails the caller: a key scoped to Bedrock
    *runtime* only cannot call this, and that must not break setup.
    """
    status, body = _get(region, "/inference-profiles", "", api_key, timeout)
    if status != 200 or body is None:
        return []
    profiles: list[dict[str, Any]] = []
    for summary in body.get("inferenceProfileSummaries", []):
        if summary.get("type") != "SYSTEM_DEFINED":
            continue  # APPLICATION profiles are user-made; not ours to offer
        if summary.get("status") and summary["status"] != "ACTIVE":
            continue
        profile_id = summary.get("inferenceProfileId")
        if not profile_id:
            continue
        profiles.append({
            "id": profile_id,
            "label": (
                f"{summary.get('inferenceProfileName', profile_id)} "
                "(cross-region profile)"
            ),
            "kind": "inference-profile",
        })
    return profiles


def list_bedrock_models(
    api_key: str, region: str, timeout: int = LIST_TIMEOUT_S
) -> list[dict[str, Any]] | None:
    """Chat-capable models in ``region``: [{id, label, kind}].

    None means the catalog could not be read at all (bad key, wrong region,
    no network). [] means the call worked but nothing survived the filter.

    Inference profiles are listed FIRST. They are not a nicety: newer
    Anthropic models reject on-demand invocation by their base model id
    ("on-demand throughput isn't supported"), so the profile id is the only
    thing that actually works for them.
    """
    status, body = _get(
        region,
        "/foundation-models",
        "?byOutputModality=TEXT&byInferenceType=ON_DEMAND",
        api_key,
        timeout,
    )
    if status != 200 or body is None:
        return None

    models: list[dict[str, Any]] = []
    for summary in body.get("modelSummaries", []):
        lifecycle = (summary.get("modelLifecycle") or {}).get("status")
        if lifecycle and lifecycle != "ACTIVE":
            continue  # LEGACY models are on their way out; don't offer them
        model_id = summary.get("modelId")
        if not model_id:
            continue
        provider = summary.get("providerName", "")
        name = summary.get("modelName", model_id)
        models.append({
            "id": model_id,
            "label": f"{provider} {name}".strip(),
            "kind": "foundation-model",
        })

    return _list_inference_profiles(api_key, region, timeout) + models
