"""Read-only sandbox-image diagnosis and safe mismatch recovery.

The configured image can be wrong for reasons a tag cannot express: a stale
version label, the wrong architecture, an entrypoint that is not Kryonsec's,
or a root user.  This module answers three questions without changing
anything:

* where did the selected reference come from (environment, config, default)?
* is a compatible image already present locally, and does Docker already
  record a registry digest for it?
* is the developer registry a loopback-bound ``registry:2`` container that
  may be used to register a local build?

The repair planner turns those facts into auto/approval/manual actions.  No
version label is rewritten, no digest is fabricated, and a mutable tag is
never presented as a verified identity.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from ..config import KryonsecConfig, config_path
from ..purple import runtime_checks

SOURCE_ENV = "KRYONSEC_SANDBOX_IMAGE environment override"
SOURCE_CONFIG = "config.toml [sandbox].image"
SOURCE_DEFAULT = "Kryonsec's built-in sandbox default"

REGISTRY_CONTAINER = "kryon-release-registry"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
_LOOPBACK_REPO_HINTS = ("localhost:", "127.0.0.1:", "[::1]:")


def normalise_version(value: str) -> str:
    return runtime_checks._normalise_version(str(value or ""))


def normalise_arch(value: str) -> str:
    return runtime_checks._normalise_arch(str(value or ""))


# ---- selected reference ------------------------------------------------


def configured_image_source(cfg: KryonsecConfig) -> tuple[str, str]:
    """(selected reference, human-readable source) using the real precedence."""
    env = os.environ.get("KRYONSEC_SANDBOX_IMAGE", "").strip()
    if env:
        return env, SOURCE_ENV
    path = config_path(cfg.home)
    if path.is_file():
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            data = {}
        sandbox = data.get("sandbox") if isinstance(data, dict) else None
        value = sandbox.get("image") if isinstance(sandbox, dict) else None
        if isinstance(value, str) and value.strip():
            return value.strip(), SOURCE_CONFIG
    return cfg.sandbox_image, SOURCE_DEFAULT


# ---- local candidates ---------------------------------------------------


@dataclass(frozen=True)
class ImageCandidate:
    """One local image inspected read-only against the sandbox contract."""

    reference: str
    image_id: str = ""
    version: str = ""
    architecture: str = ""
    operating_system: str = ""
    entrypoint: tuple[str, ...] = ()
    user: str = ""
    repo_digests: tuple[str, ...] = ()
    digest_reference: str = ""
    created: str = ""
    compatible: bool = False
    reason: str = ""

    @property
    def needs_registration(self) -> bool:
        """A valid local build that Docker has no registry digest for yet."""
        return self.compatible and not self.digest_reference


@dataclass(frozen=True)
class RegistryStatus:
    """The developer registry container, verified before it is ever used."""

    container: str = REGISTRY_CONTAINER
    present: bool = False
    running: bool = False
    loopback: bool = False
    host: str = ""
    port: str = ""
    image: str = ""
    reason: str = ""

    @property
    def address(self) -> str:
        if not self.host or not self.port:
            return ""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    def reference(self, version: str) -> str:
        if not self.address:
            return ""
        return f"{self.address}/kryonsec/sandbox:{version}"


@dataclass(frozen=True)
class ImageDiagnosis:
    reference: str
    source: str
    version: str = ""
    reason: str = ""
    candidates: tuple[ImageCandidate, ...] = ()
    registry: RegistryStatus = field(default_factory=RegistryStatus)

    @property
    def best_candidate(self) -> ImageCandidate | None:
        for candidate in self.candidates:
            if candidate.compatible:
                return candidate
        return None


def _digest_preference(reference: str) -> int:
    value = reference.lower()
    score = 0
    # A canonical repository name survives the local developer registry being
    # stopped; a loopback digest is still immutable but less portable.
    if not any(hint in value for hint in _LOOPBACK_REPO_HINTS):
        score += 10
    if value.startswith("kryonsec/sandbox@"):
        score += 5
    if value.startswith("ghcr.io/"):
        score += 3
    return score


def best_digest(repo_digests: tuple[str, ...] | list[str]) -> str:
    """The most portable verified digest, never a synthesized one."""
    digests = [str(value) for value in repo_digests if "@sha256:" in str(value)]
    if not digests:
        return ""
    return max(digests, key=_digest_preference)


def inspect_candidate(
    reference: str,
    *,
    expected_version: str,
    server_architecture: str = "",
) -> ImageCandidate:
    """Inspect one local reference and grade it against the sandbox contract."""
    info = runtime_checks.image_inspect(reference)
    if info is None:
        return ImageCandidate(reference=reference, reason="image is not present")
    labels = info.labels or {}
    version = (
        labels.get("org.kryonsec.version")
        or labels.get("org.opencontainers.image.version")
        or ""
    )
    candidate = ImageCandidate(
        reference=reference,
        image_id=info.image_id,
        version=version,
        architecture=info.architecture,
        operating_system=info.operating_system,
        entrypoint=info.entrypoint,
        user=info.user,
        repo_digests=info.repo_digests,
        digest_reference=best_digest(info.repo_digests),
        created=info.created,
    )
    if not info.operating_system:
        return _rejected(candidate, "image OS metadata is missing")
    if info.operating_system.lower() != "linux":
        return _rejected(candidate, f"image OS is {info.operating_system}, not Linux")
    if info.entrypoint != runtime_checks.SANDBOX_ENTRYPOINT:
        return _rejected(
            candidate,
            "image entrypoint is not /entrypoint.sh; this is not a Kryonsec sandbox",
        )
    if not info.architecture:
        return _rejected(candidate, "image architecture metadata is missing")
    if server_architecture and (
        normalise_arch(info.architecture) != normalise_arch(server_architecture)
    ):
        return _rejected(
            candidate,
            f"image architecture {info.architecture} does not match the "
            f"selected Docker daemon architecture {normalise_arch(server_architecture)}",
        )
    if not version:
        return _rejected(
            candidate,
            "image has no Kryonsec release-version label",
        )
    if normalise_version(version) != normalise_version(expected_version):
        return _rejected(
            candidate,
            f"image version {version} does not match Kryonsec {expected_version}",
        )
    if not info.user or info.user in ("0", "root"):
        return _rejected(
            candidate,
            "image runs as root; the sandbox must use the non-root kryonsec-runner user",
        )
    return ImageCandidate(
        reference=candidate.reference,
        image_id=candidate.image_id,
        version=candidate.version,
        architecture=candidate.architecture,
        operating_system=candidate.operating_system,
        entrypoint=candidate.entrypoint,
        user=candidate.user,
        repo_digests=candidate.repo_digests,
        digest_reference=candidate.digest_reference,
        created=candidate.created,
        compatible=True,
    )


def _rejected(candidate: ImageCandidate, reason: str) -> ImageCandidate:
    return ImageCandidate(
        reference=candidate.reference,
        image_id=candidate.image_id,
        version=candidate.version,
        architecture=candidate.architecture,
        operating_system=candidate.operating_system,
        entrypoint=candidate.entrypoint,
        user=candidate.user,
        repo_digests=candidate.repo_digests,
        digest_reference=candidate.digest_reference,
        created=candidate.created,
        compatible=False,
        reason=reason,
    )


def _candidate_preference(
    candidate: ImageCandidate, expected_version: str
) -> tuple[int, int, int]:
    digest = int(bool(candidate.digest_reference))
    canonical = int(
        not any(hint in candidate.reference.lower() for hint in _LOOPBACK_REPO_HINTS)
    )
    # Prefer the plain release label over a ``v`` prefix; the newest build
    # wins the final tie.  Two local builds can both claim 1.3.11, and the
    # installer just produced the latest one.
    exact = int(candidate.version == expected_version)
    return digest, canonical, exact


def scan_candidates(
    *,
    expected_version: str,
    server_architecture: str = "",
) -> list[ImageCandidate]:
    """Every local labelled Kryonsec image, compatible ones first."""
    candidates: dict[str, ImageCandidate] = {}
    for reference in runtime_checks.list_sandbox_image_refs():
        candidate = inspect_candidate(
            reference,
            expected_version=expected_version,
            server_architecture=server_architecture,
        )
        if not candidate.image_id:
            continue
        current = candidates.get(candidate.image_id)
        if current is None or _candidate_preference(
            candidate, expected_version
        ) > _candidate_preference(current, expected_version):
            candidates[candidate.image_id] = candidate
    # Stable two-pass sort: newest local build first, then the safety order
    # (compatible, digest-pinned, exact release label).
    newest = sorted(
        candidates.values(), key=lambda item: item.created, reverse=True
    )
    return sorted(
        newest,
        key=lambda item: (
            not item.compatible,
            not bool(item.digest_reference),
            int(item.version != expected_version),
        ),
    )


# ---- developer registry -------------------------------------------------


def registry_status(container: str = REGISTRY_CONTAINER) -> RegistryStatus:
    """Verify the developer registry is a loopback-bound ``registry`` container."""
    data = runtime_checks.container_inspect(container)
    if data is None:
        return RegistryStatus(
            container=container,
            reason=f"local registry container {container} was not found",
        )
    state = data.get("State") or {}
    config = data.get("Config") or {}
    host_config = data.get("HostConfig") or {}
    image = str(config.get("Image") or "")
    running = bool(state.get("Running"))
    if "registry" not in image.lower():
        return RegistryStatus(
            container=container,
            present=True,
            running=running,
            image=image,
            reason="container is not a Docker registry image",
        )
    if str(host_config.get("NetworkMode") or "") == "host":
        return RegistryStatus(
            container=container,
            present=True,
            running=running,
            image=image,
            reason="registry uses host networking; its bind address cannot be verified as loopback",
        )
    bindings = host_config.get("PortBindings") or {}
    published: list[tuple[str, str, str]] = []
    for container_port, entries in bindings.items():
        for entry in entries or []:
            host_port = str(entry.get("HostPort") or "")
            host_ip = str(entry.get("HostIp") or "")
            if host_port:
                published.append((str(container_port), host_ip, host_port))
    if not published:
        return RegistryStatus(
            container=container,
            present=True,
            running=running,
            image=image,
            reason="registry has no published host port",
        )
    unsafe = [entry for entry in published if entry[1] not in LOOPBACK_HOSTS]
    if unsafe:
        addresses = ", ".join(
            f"{entry[1] or '0.0.0.0'}:{entry[2]}" for entry in unsafe
        )
        return RegistryStatus(
            container=container,
            present=True,
            running=running,
            image=image,
            reason=f"registry publishes on {addresses}; only loopback bindings are accepted",
        )
    container_port, host_ip, host_port = published[0]
    if not container_port.startswith("5000/"):
        return RegistryStatus(
            container=container,
            present=True,
            running=running,
            image=image,
            reason=(
                f"registry publishes container port {container_port}, not the "
                "registry API port 5000"
            ),
        )
    return RegistryStatus(
        container=container,
        present=True,
        running=running,
        loopback=True,
        host=host_ip,
        port=host_port,
        image=image,
    )


# ---- diagnosis ----------------------------------------------------------


def diagnose(
    cfg: KryonsecConfig,
    *,
    expected_version: str,
    validation_detail: str = "",
    server_architecture: str = "",
    scan: bool = True,
) -> ImageDiagnosis:
    """Read-only diagnosis; scanning is opt-in so ordinary checks stay cheap."""
    reference, source = configured_image_source(cfg)
    version = ""
    candidates: tuple[ImageCandidate, ...] = ()
    registry = RegistryStatus()
    if scan:
        candidates = tuple(
            scan_candidates(
                expected_version=expected_version,
                server_architecture=server_architecture,
            )
        )
        if any(item.compatible and item.needs_registration for item in candidates):
            registry = registry_status()
    if reference:
        info = runtime_checks.image_inspect(reference) if scan else None
        if info is not None:
            labels = info.labels or {}
            version = (
                labels.get("org.kryonsec.version")
                or labels.get("org.opencontainers.image.version")
                or ""
            )
    return ImageDiagnosis(
        reference=reference,
        source=source,
        version=version,
        reason=validation_detail,
        candidates=candidates,
        registry=registry,
    )


def explain(diagnosis: ImageDiagnosis, expected_version: str) -> str:
    """The user-facing mismatch explanation; no secrets, no invented facts."""
    parts = [f"Kryonsec {expected_version} requires a compatible sandbox."]
    if diagnosis.version:
        parts.append(
            f"The configured image {diagnosis.reference} is version "
            f"{diagnosis.version}."
        )
    elif diagnosis.reference:
        parts.append(f"The configured image {diagnosis.reference} failed verification.")
    parts.append(f"Selected via {diagnosis.source}.")
    best = diagnosis.best_candidate
    if best is not None:
        parts.append(
            f"A locally built {best.version} candidate was found: {best.reference}."
        )
    else:
        parts.append("No compatible local sandbox image was found.")
    return " ".join(parts)


__all__ = [
    "ImageCandidate",
    "ImageDiagnosis",
    "LOOPBACK_HOSTS",
    "REGISTRY_CONTAINER",
    "RegistryStatus",
    "SOURCE_CONFIG",
    "SOURCE_DEFAULT",
    "SOURCE_ENV",
    "best_digest",
    "configured_image_source",
    "diagnose",
    "explain",
    "inspect_candidate",
    "registry_status",
    "scan_candidates",
]
