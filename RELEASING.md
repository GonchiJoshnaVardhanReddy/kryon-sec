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

`install.sh` and `install.ps1` both call it like this:

```
GET https://kryonsec.in/api/download?key=KRYO-XXXX-XXXX-XXXX&os=linux
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
   curl -fL -o /tmp/k.wl "https://kryonsec.in/api/download?key=KRYO-AB2C-DE3F-GH4J"
   file /tmp/k.wl    # expect: Zip archive data

   # a key that is not on the list: expect 403
   curl -s -o /dev/null -w "%{http_code}\n" \
     "https://kryonsec.in/api/download?key=KRYO-3333-3333-3333"
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
git commit -am "release: v1.3.3"

# 2. tag — this triggers release-wheel.yml and sandbox-image.yml
git tag v1.3.3
git push origin main --tags
```

After the wheel job goes green, the new version is live: the endpoint reads
`/releases/latest`, so there is nothing else to do.

### The installers are copied into the landing repo

`install.sh` and `install.ps1` must be publicly fetchable at
`https://kryonsec.in/install.sh`, and this repo is private — so the landing
repo holds a copy, and **Cloudflare serves that copy**. A change to the
installer only reaches members once it is copied over:

```bash
cp kryonsec/install.sh kryonsec/install.ps1 ../kryonsec-landing/
```

## Testing an install without the endpoint

Both installers take a wheel directly — a local path or a URL. This is how to
check an install end to end, and how to support a member whose network blocks
the site:

```bash
curl -fsSL https://kryonsec.in/install.sh | \
  KRYONSEC_WHEEL="$(pwd)/dist/kryonsec-1.3.3-py3-none-any.whl" bash
```

```powershell
$env:KRYONSEC_WHEEL = "C:\build\kryonsec-1.3.3-py3-none-any.whl"
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

## What members are told

Whatever you put in the early-access email. The command is:

```bash
curl -fsSL https://kryonsec.in/install.sh | KRYONSEC_KEY=KRYO-XXXX-XXXX-XXXX bash
```

`KRYONSEC_LICENSE_KEY` works too — it is the name the app itself reads. The
installer saves the key to `~/.kryonsec/config.toml` under `[license]`, so
Purple Team does not ask for it again.
