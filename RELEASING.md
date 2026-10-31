# Releasing Kryonsec

Kryonsec is commercial, closed-source software. There is no public repository
and no public download: the release is a built wheel, and a membership key is
what unlocks it. This file is what you do when you cut a release, and the one
piece of infrastructure the installers depend on.

## The one-time setup

1. **The repository is private.** Done. Everything in the install path stopped
   using it, so nothing broke.

2. **The sandbox image stays publicly pullable.** Verified:
   `ghcr.io/gonchijoshnavardhanreddy/kryonsec-sandbox:latest` still answers an
   anonymous pull, so Purple Team installs keep working. Making the repo private
   did not take the package with it — **leave it that way.** If you ever do make
   it private, `install.sh` already reads `KRYONSEC_REGISTRY_TOKEN` /
   `KRYONSEC_REGISTRY_USER`, and members need to be sent a token.

3. **The download endpoint** (below). Until it exists, installs work through the
   `KRYONSEC_WHEEL` override, which is enough to hand a build to early-access
   members by email.

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

Two things matter about the contract:

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

   Copy it (`github_pat_…`). You will not see it again.

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

## Cutting a release

Tagging is what ships. `release-wheel.yml` builds the wheel and attaches it to
the release for that tag; the endpoint serves the newest release, so it needs no
change per release.

```bash
# 1. bump the version in pyproject.toml, then commit it
git commit -am "release: vX.Y.Z"

# 2. tag — this triggers release-wheel.yml and sandbox-image.yml
git tag vX.Y.Z
git push origin main --tags
```

Wait for both the test workflow and the wheel/image workflows. The sandbox job
must publish the same release version and its summary must record a digest.
Before announcing the release, run a clean supported Linux/WSL2 installation
with `kryonsec doctor --deep --strict`; the endpoint reads `/releases/latest`
only after those checks are green.

### The installers are copied into the landing repo

`install.sh` and `install.ps1` must be publicly fetchable at
`https://kryonsec.in/install.sh`, and this repo is private — so the landing
repo holds a copy, and **Cloudflare serves that copy**. A change to the
installer only reaches members once it is copied over:

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
