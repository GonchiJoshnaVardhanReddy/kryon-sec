# DocSafe — the vetted read-only MCP provider (Mode A)

DocSafe is Kryonsec's first vetted MCP provider (Phase 2B.1). It is a
fully auditable, in-repo, **read-only local file reader**: the assistant
can read text files and list directories **only inside roots the
operator has explicitly approved**. It ships **disabled** — it exists
only when you add a configuration row for it.

Code: `src/kryonsec/copilot/mcp_servers/docsafe.py`
(`python -m kryonsec.copilot.mcp_servers.docsafe ROOT [ROOT...]`).

---

## 1. Enabling it (explicitly, operator-only)

Nothing is on by default. Add a `[[mcp.servers]]` row to your
`config.toml` (path: `$KRYONSEC_HOME/config.toml`, default
`~/.kryonsec/config.toml`):

```toml
[[mcp.servers]]
name = "docsafe"                       # the connection name
command = "python3"                    # or the absolute .venv python path
args = [                               # run the provider module with
  "-m", "kryonsec.copilot.mcp_servers.docsafe",
  "/srv/notes",                        # approved ROOT 1
  "/srv/docs"                          # approved ROOT 2 (add as many as
]                                      # you want; no roots = no startup)
trust = "ask"                          # 'ask' = human approves each call
                                       # 'allow' = approved tools run
                                       # freely; 'disabled' = never start
allow_tools = ["list_directory", "read_file"]   # EXACT tool allowlist
path_roots = ["/srv/notes", "/srv/docs"]        # the resource scope
path_arguments = ["path"]                       # which args are paths
call_timeout_s = 30                    # 1..120
max_output_chars = 90000               # <= the configured ceiling
max_concurrent_calls = 2               # 1..8
```

- `trust = "ask"` prompts for every call (recommended first).
- `trust = "allow"` is reasonable after review — the tools are pure
  read-only. The startup gate still requires the tool allowlist; a
  `trust = "allow"` row **without** `allow_tools` is refused, never run.
- `trust` absent or `"disabled"` ⇒ the provider never starts.

## 2. How `path_roots` and `path_arguments` work

`path_arguments` names **exactly which arguments are filesystem
paths** (for docsafe: `path`), and `path_roots` is the only place those
paths may resolve. Two independent layers enforce this:

**Registry (before dispatch).** For every named path argument:

- NUL bytes, `..` traversal and `~` home expansion are refused.
- Absolute values are canonicalized with real-path semantics (every
  symlink — intermediate or final — is resolved) and must land inside
  one approved root; a symlink escaping the root is a refusal.
- The step is audited; refusals never reach the provider.

**Provider (inside docsafe).** The same rules are enforced again
independently, canonical-path only: relative values resolve against the
approved roots the same way; in-root symlinks are fine, escaping
symlinks are refused.

Neither layer is trusted alone; both are audited. What the assistant
*sees* about the scope is limited to `list_mcp_connections` /
`describe_mcp_connection`, which report the approved roots
(`path_scope`) and authorized tools.

### Safe read-only allowlist examples

- Approved root with your documentation: `path_roots =
  ["/srv/docs", "/srv/runbooks"]`
- Call `read_file` with `{"path": "docs/a.txt"}` (relative inside a
  root) or `{"path": "/srv/docs/docs/a.txt"}` (absolute inside).
- Call `list_directory` with `{"path": "docs"}` for a one-level,
  deny-list-filtered listing.

## 3. What is always refused (credential deny-list)

Even under an approved root, docsafe will not read or list:

- protected directories: `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`,
  `.kryonsec`, `.gcloud`
- key/keystore/tunnel suffixes: `.pem`, `.key`, `.p12`, `.pfx`,
  `.pkcs12`, `.kdbx`, `.jks`, `.keystore`, `.ovpn`, `.ppk`
- credential filenames: `.netrc`, `.git-credentials`, `.htpasswd`,
  `.npmrc`, `.pypirc`, `credentials`, `terraform.tfvars`, anything
  starting `.env` or `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`
- filenames containing `credential`, `password`, `secret` or `token`

Denied files are also **hidden** from `list_directory` output. Private
keys, credentials and Kryonsec secrets are unreachable even if you
accidentally put an approved root over a directory containing them.

## 4. Disabling it

Remove the `[[mcp.servers]]` row from `config.toml`, or set
`trust = "disabled"`, and restart the CLI. No process is started and
none of its tools are exposed to the assistant.

## 5. Known limitations (honest)

- **Read-only, but not a sandbox.** DocSafe is an ordinary local file
  reader on your host. It is *not* gVisor/Docker-sandboxed, and it
  never touches engagement (Zone B) data — pointing it at engagement
  material is out of scope by design.
- **Symlink races.** DocSafe resolves a path and then opens the
  resolved target. That is safe **only while nobody unauthorized can
  write to the approved roots**: an attacker who can write there can
  swap a symlink between the resolve step and the open (a classic
  TOCTOU race). Do **not** point docsafe at attacker-controlled or
  writable-by-others directories. Enforcing the guarantee against
  attacker-controlled writers would require an `openat2(RESOLVE_BENEATH)`
  / open-by-fd strategy rather than resolve-then-open; that hardening
  is not implemented in 2B.1.
- **UTF-8 text only.** Binary or non-UTF-8 files are refused (bounded
  256 KiB preview).
- **Listings are shallow.** One level per `list_directory` call.

## 6. Smoke check

A small, non-invasive smoke (builds the provider against a throwaway
temp root and exercises the path boundary; no process spawn, no
network):

```bash
python -c "from kryonsec.copilot.mcp_servers.docsafe import smoke; print(smoke())"
```
