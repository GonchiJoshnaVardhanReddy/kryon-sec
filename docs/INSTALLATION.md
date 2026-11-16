# Kryonsec installation and first-run guide

This is the operational guide for the installers in `install.sh` and
`install.ps1`. It describes what is supported, what is optional, and what the
installer refuses to change automatically.

## Support matrix

| Environment | Copilot | Purple Team | Notes |
|---|---:|---:|---|
| Linux x86-64, Python 3.11–3.13 | Supported | Supported when all runtime checks pass | Docker Engine, registered gVisor, and the release image are required for Zone B. |
| WSL2 x86-64 with a native Linux Docker Engine | Supported | Supported when all runtime checks pass | Run `install.sh` inside WSL2. Docker Desktop's selected daemon is not a gVisor host. |
| Windows host | Supported | Not supported | Use `install.ps1` for Copilot. Do not run Purple Team on the Windows host. |
| macOS | Supported | Not supported by this release | Use a supported Linux VM/WSL2 environment for Purple Team. |
| Linux ARM64 | Supported for Copilot | Not release-supported | The published sandbox tool set contains x86-64-only artifacts; do not claim Purple support until a verified ARM64 image is published. |
| Docker Desktop daemon | Supported for Copilot | Not supported as the Purple daemon | Kryonsec reports the selected context and never switches it. |
| Rootless Docker | Supported for Copilot | Not claimed | Purple support requires a real `doctor --deep` result with the selected daemon and runsc. |
| Remote Docker context | Supported for Copilot | Manual/unsupported by the installer | The daemon itself must have runsc registered and the image available. A local runsc binary is not enough. |

Python 3.14 may be detected, but dependency wheels are not guaranteed. Use
Python 3.12 or 3.13 for a release installation.

## What is required

### Copilot (Mode A)

* Python 3.11–3.13.
* A writable user home and network access to download the wheel, unless a
  locally supplied wheel is used.
* One configured LLM provider: Ollama, OpenAI, AWS Bedrock, or an
  OpenAI-compatible endpoint.
* Docker, gVisor, PostgreSQL, cloud credentials, and passive-recon API keys are
  optional for Copilot.

### Purple Team (Mode B)

In addition to Copilot:

* a Linux kernel (native Linux or WSL2);
* the selected Docker daemon must be reachable by the current user;
* the selected daemon must list `runsc` as a registered runtime;
* a release-matched sandbox image, pinned by registry digest;
* network access for image pulls and Zone A APIs.

No membership key or beta account is required in this development build — the
login, connect, and license checks are temporarily removed from the app (the
hosted installer's download gate still applies to the wheel it fetches). The
published release may differ.

The installer does not change Docker's default runtime. Kryonsec passes
`--runtime runsc` only to its sandbox workload. It never falls back to `runc`.

## Install

Download the script first so it can be reviewed. Do not pipe an unreviewed
remote response into a shell.

### Linux or WSL2

Copilot only, with no Docker or service changes:

```bash
curl -fsSL https://kryonsec.in/install.sh -o install.sh
less install.sh
KRYONSEC_KEY='KRYO-XXXX-XXXX-XXXX' bash install.sh --profile=copilot
```

Automatic optional Purple preparation is the default interactive profile:

```bash
KRYONSEC_KEY='KRYO-XXXX-XXXX-XXXX' bash install.sh --profile=auto
```

For a machine that must provide Purple Team, use the strict profile. It exits
non-zero unless the final deep preflight succeeds:

```bash
KRYONSEC_KEY='KRYO-XXXX-XXXX-XXXX' bash install.sh --profile=purple
```

The installer asks before installing packages, changing group membership,
editing Docker configuration, enabling/restarting services, or pulling the
large sandbox image. `--yes` is an explicit non-interactive approval and should
only be used after reviewing the planned changes.

Useful safe modes:

```bash
bash install.sh --dry-run --profile=auto
bash install.sh --repair --profile=copilot
```

`--dry-run` performs no downloads or writes. `--repair` preserves an incomplete
installer-owned virtualenv under a timestamped backup before recreating it. A
malformed existing `config.toml` is never replaced; repair it or move it aside
yourself after making a backup.

Beta users on Linux or macOS use the one-time `KRYONSEC_DOWNLOAD_URL` the
dashboard prints. Windows uses the short command below and browser approval
instead. A membership key, when used, is sent in `X-Kryonsec-Key`, not in the
download URL. Release responses include a SHA-256 header which both installers
verify before pip runs.

### Windows

Windows installs Copilot only:

```powershell
irm https://kryonsec.in/install.ps1 -OutFile "$env:TEMP\kryonsec-install.ps1"
powershell -ExecutionPolicy Bypass -File "$env:TEMP\kryonsec-install.ps1"
```

The command is stable and contains no credential. The installer posts to
`/api/beta/device/start`, prints and opens the approval page, and waits while a
signed-in, entitled member approves the machine. The resulting download link
is single-use and expires in 15 minutes; the wheel's `X-Kryonsec-Wheel-SHA256`
is checked against the bytes received, and a missing or mismatched hash stops
the install.

Both links the site returns — the approval page and the download link — must be
on the site the installer was told to use (`KRYONSEC_SITE`, by default
`kryonsec.in`). A link to another host stops the install before anything is
opened or downloaded; so does a refusal or an unreachable site, which is
reported as itself rather than as "sign-in unavailable". Only a site with no
sign-in route at all falls back to the membership-key prompt.

To skip browser approval, set `KRYONSEC_KEY` (or `KRYONSEC_LICENSE_KEY`) before
the second line (or let the installer prompt for it). Use `-DryRun` to inspect
the plan and `-Repair` to preserve an incomplete virtualenv before repair. Use
WSL2 and the Linux installer for Purple Team.

## First run and authentication

No account step exists in this development build: the wizard covers the LLM
provider, models, agent tools, MCP servers and workspace only, and Purple
Team starts without a key.

The setup wizard has one mandatory choice: a working LLM provider. The other
integrations are optional:

* Ollama is local and recommended for secret-safe processing, but it is not
  installed by the Kryonsec installer. Install it from its official source,
  pull a model, and rerun `kryonsec setup` if desired.
* OpenAI, Bedrock, and OpenAI-compatible endpoints require the credentials and
  endpoint details for that provider only. Selecting one does not require
  configuring another provider.
* Shodan, Censys, GitHub, PostgreSQL, and MCP servers are optional.

Older installs may still have a `[license] key` in `config.toml` or stale
`license.state.json` / `auth.json` files under `~/.kryonsec/`. They load fine;
the values are ignored. To clean them up by hand, delete the `[license]`
section from `config.toml` and remove `~/.kryonsec/license.state.json` and
`~/.kryonsec/auth.json` — Kryonsec never touches those files itself.

## Preflight and runtime validation

```bash
kryonsec doctor
kryonsec doctor --deep
kryonsec doctor --deep --strict
```

The report uses `PASS`, `FAIL`, `WARNING`, and `SKIPPED`. It reports the active
Docker context, a redacted endpoint, client/server versions, socket permission
errors, the selected daemon's runtime list, the image architecture/entrypoint/
release label/digest, and (with `--deep`) a harmless network-disabled container
that runs the packaged entrypoint with `runsc`.

`--strict` is the check used for a Purple installation. A green Copilot result
does not mean Purple is ready.

If Docker Desktop or multiple contexts are detected, choose the intended
daemon yourself and rerun. Kryonsec does not run `docker context use`, change
`DOCKER_HOST`, edit Docker Desktop settings, or inspect the daemon as root.

## Recovery and upgrade

Rerunning the installer is safe. A compatible virtualenv is reused, an already
installed matching wheel is not reinstalled, and existing configuration,
authentication, and engagement data are preserved. A release-matched image is
pulled by version and stored in configuration by its verified digest; `latest`
is not used as a compatibility fallback.

If an install is interrupted:

1. run `kryonsec doctor` or `bash install.sh --dry-run`;
2. repair the named prerequisite only;
3. rerun the same profile;
4. use `kryonsec doctor --deep --strict` before a Purple engagement.

Do not delete `~/.kryonsec` to recover. It contains configuration, possibly
stale auth/license files left by older installs (ignored by this build), and
engagement evidence. To uninstall Copilot, remove the
installer-managed PATH block and the virtualenv after backing up the directory;
delete engagement data only as a separate, deliberate operator action.

## Release requirements

A release is not ready for users until:

1. the wheel and sandbox image carry the same release version;
2. the sandbox workflow publishes the image for the release tag and records its
   digest;
3. a clean supported Linux host passes `kryonsec doctor --deep --strict`;
4. a harmless runner smoke test confirms the actual KryonSec path uses
   `--runtime runsc`, applies its limits, and cleans up the container;
5. the installer and landing download endpoint are deployed together so the
   header-based key and wheel hash contract match.
