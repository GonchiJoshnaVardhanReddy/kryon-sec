# Releasing Kryonsec

Kryonsec is commercial software. Distribution is gated by a membership key:
the release is a built wheel served by the download endpoint, and the Purple
Team sandbox image lives publicly on GHCR. The **source repository is public**
(verified 2026-11-15 — do not re-add "the repo is private" instructions; they
were true once and stopped being true), so releases, source and CI runs are
visible; the key list and the endpoint are what gate distribution.

## Why a two-stage process

An ordinary `v*` tag push must not ship anything. The old one-stage flows
(`release-wheel.yml`, `sandbox-image.yml`) published a wheel, created the
GitHub Release and moved the GHCR `latest` pointer straight off a tag push —
meaning a single unreviewed tag exposed an unvalidated wheel to members and
re-pointed production installs. Those workflows were removed and replaced:

- **Stage A — `release-candidate.yml`** builds the wheel and image from one
  exact commit and stores them as restricted artifacts. It never creates a
  tag, never publishes a release, never moves `latest`.
- **Gate** — the owner approves the exact wheel SHA-256, image digest and
  source commit.
- **Stage B — `release-promote.yml`** promotes the already-validated bytes
  behind the `release-production` environment: image by digest (no rebuild),
  release with the verified wheel, `latest` last and only on request.
- **`release-guard.yml`** fails loudly if a `v*` tag is pushed by hand. A tag
  created by Stage B's `GITHUB_TOKEN` does not trigger it.

## The one-time setup

1. **The source repository is public.** Nothing in the install path needs it
   to be private. Release assets are anonymously readable; if it ever goes
   private again, the download endpoint's token keeps working unchanged.

2. **The sandbox image stays publicly pullable.** Verified:
   `ghcr.io/gonchijoshnavardhanreddy/kryonsec-sandbox:latest` still answers an
   anonymous pull, so Purple Team installs keep working — **leave it that
   way.** If you ever do make it private, `install.sh` already reads
   `KRYONSEC_REGISTRY_TOKEN` / `KRYONSEC_REGISTRY_USER`, and members need to
   be sent a token.

3. **Create the `release-production` environment** — GitHub → repo →
   Settings → Environments → New environment → `release-production` →
   **Required reviewers** = the owner. This is what turns Stage B into a real
   auditable approval gate. Until it exists, Stage B runs on workflow_dispatch
   input verification alone — configure it **before** the first Stage B run.

4. **The download endpoint** (below). Until it exists, installs work through
   the `KRYONSEC_WHEEL` override, which is enough to hand a build to
   early-access members by email.

## Stage A — build and stage a candidate

Actions → **release-candidate** → Run workflow:

| Input | Value |
| --- | --- |
| `version` | e.g. `1.3.11` — must match `pyproject.toml` on the built commit (guard fails otherwise) |
| `ref` | **The exact frozen source commit SHA.** Strongly preferred over main HEAD, so wheel, image and tests all build identical source |
| `push_staging_image` | `true` to push the candidate image to GHCR as `:staging-<version>`; `false` keeps it artifact-only |

`push_staging_image` deserves care: the package is publicly pullable, so a
staging tag **is a public upload of candidate code**. Disclose the exact tag
(`:staging-<version>`) to the owner and get their OK **before** running Stage
A with it.

What Stage A produces (14-day retention, restricted artifacts):

- `wheel-<version>` — the wheel, content-checked (name/version, nuclei
  manifest, templates, no stray paths) and hashed; packaging tests run first.
- `sandbox-image-<version>` — the image, built with the Dockerfile's
  required-tool guard (a missing required tool fails the build) and
  tool-inventory-verified, saved as a tar artifact.
- `provenance-<version>` — a one-record manifest: version, source commit,
  wheel sha256, image digest, test-matrix result, run URL.

What Stage A never does: no tag, no GitHub Release, no `latest` move, no
production version tag. The run summary carries the manifest values — copy
them for the approval gate.

If `push_staging_image` was `false`, no registry digest exists and Stage B
cannot promote an image; a later Stage A run with the push enabled is needed.

## The gate — what the owner approves

Three values, all from the Stage A run summary:

1. `source_commit` — the frozen commit the artifacts were built from.
2. `wheel_sha256` — the candidate wheel's SHA-256.
3. `image_digest` — the `:staging-<version>` digest on GHCR.

Approval is explicit (e.g. "approve staging v1.3.11 with wheel `sha256:…` and
image `sha256:…`"). Nothing is inferred from a successful test run.

## Stage B — promote to production

Actions → **release-promote** → Run workflow with the approved manifest:
`version`, `source_sha`, `stage_run_id`, `wheel_sha256`,
`staging_image_digest`, plus `publish_release` (default on) and `move_latest`
(default **off** — `latest` moves only when explicitly asked, and the job
ordering guarantees it happens after the release exists).

Stage B re-verifies everything against reality before touching production:

- the Stage A run is a **successful** `release-candidate` dispatch run whose
  head SHA equals `source_sha`;
- the downloaded wheel artifact hashes to `wheel_sha256`, and the Stage A
  provenance record agrees on all three values;
- the version tag does not already exist with different content, the release
  does not exist, and the tag — once created — points at `source_sha`.

Then, in order, and without ever rebuilding:

1. **Image promotion** — pulls the candidate by its approved digest, tags it
   `:v<version>`, pushes, and verifies the registry digest still equals the
   approved one. Content-addressed: the published version tag is byte-for-byte
   the validated candidate.
2. **Release** — refuses any pre-existing tag/release (no rewriting, no
   `--clobber`), creates the tag at `source_sha` via `gh release create`,
   attaches the verified wheel, and re-downloads the published asset to
   re-verify its hash. Notes come from the matching `CHANGELOG.md` section —
   keep that section reviewed before running Stage B.
3. **`latest`** — only if `move_latest` was set, and only here: the same
   digest is re-tagged `:latest` and re-verified.

If the Stage A artifacts expired (14-day retention), re-run Stage A — but
wheel bytes are not guaranteed byte-identical across builds, so a fresh Stage
A run means a fresh approval gate.

## Failure and recovery

- A Stage B verification failure stops everything before production is
  touched. Fix the problem, re-run Stage A if needed, re-approve.
- If Stage B failed **after** creating the tag but **before** publishing the
  release, the tag is an orphan: delete it (`git push origin :refs/tags/v…`
  and/or via the UI), fix, and run Stage B again. If the release **was**
  published, never delete or rewrite it — fix forward with a new version
  (e.g. `v1.3.12`).
- A manually pushed `v*` tag trips `release-guard.yml` with instructions.
- Never force-push, never re-point a published version tag, never replace
  published wheel bytes. Older releases (e.g. v1.3.10) stay untouched so
  installed members keep their pinned, working version.

## Cutting a release — the checklist

1. Bump the version (`pyproject.toml`, `CHANGELOG.md` section, README badge)
   and commit to main; wait for CI green. That commit is the frozen source.
2. Disclose the staging plan to the owner and run **Stage A** from that SHA.
3. Verify the run summary values (build the wheel locally too if you want a
   hash cross-check — `rm -rf build dist *.egg-info` first).
4. Get explicit owner approval of the manifest.
5. Run **Stage B** with the approved manifest (requires the
   `release-production` environment reviewers configured).
6. Before announcing: fresh-install check with `kryonsec doctor --deep
   --strict` and confirm the download endpoint serves the new wheel with a
   matching `X-Kryonsec-Wheel-SHA256`.

## The download endpoint

No n8n. It is a Cloudflare Pages Function that deploys with the site you already
have: free, same domain, no server to run, and the two secrets never leave
Cloudflare.

The file is `kryonsec-landing/functions/api/download.js`, and Pages picks up
`functions/` automatically — there is nothing to configure for routing.

The current installers send the membership key in a header. The old query form
remains accepted for compatibility with older clients:

```
GET https://kryonsec.in/api/download?os=linux
X-Kryonsec-Key: KRYO-XXXX-XXXX-XXXX
```

| Result | Meaning |
| --- | --- |
| `200` + the wheel as the body | Key is good |
| `400` / `403` | No key, or a key that is not on the list |
| `502` | Configured wrong, or GitHub is unreachable |

Three things matter about the contract:

- **The body must be the wheel itself**, not a JSON wrapper — the installer
  hands what it downloads straight to `pip`, so a redirect to an HTML page or a
  `{"url": ...}` envelope fails as a corrupt archive.
- **A rejection must not be a `200`.** The installers use `curl -f` /
  `Invoke-WebRequest`, which treat a non-OK status as the failure. Returning
  `200` with an error page saves that page as `kryonsec.whl`.
- **A successful response must include `X-Kryonsec-Wheel-SHA256`.** Both
  installers compare the local artifact with this value before invoking pip.

### Setting it up (about 10 minutes, once)

1. **Create a GitHub token for reading the release.**
   GitHub → Settings → Developer settings → **Fine-grained tokens** → Generate
   new token.

   - Repository access: **Only select repositories** → `kryon-sec`
   - Permissions → Repository permissions → **Contents: Read-only**
   - Nothing else. This token can read one repo's releases and that is all.

   The repo is public, so release reads work anonymously; the token is
   belt-and-braces (and required if the repo ever goes private again). Keep it
   read-only and scoped to this one repo either way.

2. **Add the two secrets to Pages.**
   Cloudflare dashboard → Workers & Pages → your **kryonsec-landing** project →
   Settings → **Environment variables** → add these under **Production**, both
   as **encrypted**:

   | Variable | Value |
   | --- | --- |
   | `KRYONSEC_KEYS` | Your membership keys, comma-separated: `KRYO-AB2C-DE3F-GH4J,KRYO-…` |
   | `KRYONSEC_GITHUB_TOKEN` | The token from step 1 |

3. **Redeploy.** Environment variables only take effect on a new deployment, so
   push any commit to the landing repo (or use *Retry deployment*). The
   `functions/` directory has to be in that deploy.

4. **Check it.**

   ```bash
   # your real key: expect the wheel to download
    curl -fL -H 'X-Kryonsec-Key: KRYO-AB2C-DE3F-GH4J' \
      -o /tmp/k.whl "https://kryonsec.in/api/download?os=linux"
    file /tmp/k.whl    # expect: Zip archive data

   # a key that is not on the list: expect 403
   curl -s -o /dev/null -w "%{http_code}\n" \
      "https://kryonsec.in/api/download?os=linux" \
      -H 'X-Kryonsec-Key: KRYO-3333-3333-3333'
   ```

### Adding or removing a member

Edit `KRYONSEC_KEYS` and redeploy. That is the whole flow — the key list is one
setting, not a database.

`KRYONSEC_KEYS` is read at request time from the environment, so if the list ever
grows past a few hundred keys, move it to a KV namespace and read that instead
of redeploying per member. Nothing else changes.

## The installers are copied into the landing repo

`install.sh` and `install.ps1` must be publicly fetchable at
`https://kryonsec.in/install.sh`. The source repo is public, so the fetch
itself needs no token — but the landing repo still holds its own copy, and
**Cloudflare serves that copy**, so a change to the installer only reaches
members once it is copied over:

```bash
cp kryonsec/install.sh kryonsec/install.ps1 ../kryonsec-landing/
cd ../kryonsec-landing && node --test "tests/*.test.mjs"
```

The landing suite includes `tests/install-script.test.mjs`, which checks the
served `install.ps1` for embedded credentials, the browser-approval flow, and
fail-closed hash verification. The installer's behavior is covered here by
`py -3.13 -m pytest tests/test_install_ps1.py`.

The Windows installer depends on two live routes: `/api/beta/device/start` and
`/api/beta/device/poll` with `purpose: "download"`. Deploy the site first, then
copy the installer; an installer published against a site without those routes
falls back to the membership-key prompt instead of approving in the browser.

## Testing an install without the endpoint

Both installers take a wheel directly — a local path or a URL. This is how to
check an install end to end, and how to support a member whose network blocks
the site:

```bash
curl -fsSL https://kryonsec.in/install.sh | \
  KRYONSEC_WHEEL="$(pwd)/dist/kryonsec-X.Y.Z-py3-none-any.whl" bash
```

```powershell
$env:KRYONSEC_WHEEL = "C:\build\kryonsec-X.Y.Z-py3-none-any.whl"
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

## What members are told

Whatever you put in the early-access email. Review the script first, then run:

```bash
curl -fsSL https://kryonsec.in/install.sh -o install.sh
KRYONSEC_KEY=KRYO-XXXX-XXXX-XXXX bash install.sh --profile=auto
```

`KRYONSEC_LICENSE_KEY` works too — it is the name the app itself reads. The
installer saves the key to `~/.kryonsec/config.toml` under `[license]`, so
Purple Team does not ask for it again.
