# Kryonsec — Tool Inventory

Every tool Kryonsec can run, what it is for, and whether it actually runs in a
default engagement.

The authoritative source is `src/kryonsec/purple/allowlist.py`. This document
describes that file; if the two disagree, the file wins.

## How a tool gets to run

A tool only executes when **three** independent things agree. All three must
pass — none of them trusts the others.

1. **A fixed plan names it.** The subagent builds the argv as a constant list in
   Python. The LLM proposes *hypotheses*, never commands — it has no way to
   invoke a tool directly.
2. **The host allowlist validates it** (`ToolAllowlist`, safety Layer 2).
   `argv` must match the tool's template argument-for-argument: right count,
   each argument matching its pattern. Anything else raises
   `AllowlistViolation` and the spawn is skipped and audited.
3. **The sandbox entrypoint re-checks the tool name**
   (`containers/sandbox/entrypoint.sh`) as defense-in-depth, then runs it under
   a 300-second `timeout` inside gVisor.

Two rules that explain most of the shape below:

- **Allowlisted ≠ runs.** Adding a tool to the allowlist makes it *possible*.
  Only the fixed plans make it *happen*. Several tools below are allowlisted and
  baked into the image but deliberately absent from every plan.
- **`masscan` is deliberately NOT allowlisted** (spec v2.1.1 §9.1). It is faster
  than the safety canaries can react to, so it cannot be made safe by argv
  shaping. This is the allowlist-not-blocklist rule in action: the tool simply
  does not exist as far as the runner is concerned.

Totals: **63 tools** on the host allowlist. The sandbox image additionally
carries `python3` and `kube-bench`, which are *not* host-allowlisted — the host
allowlist is the authoritative gate, so they are unreachable.

---

## 1. Passive recon — zero packets to the target

`PASSIVE_TOOL_TEMPLATES`. Runs inside the sandbox with `-passive` flags; these
query third-party sources only. Part of the RECON_PASSIVE state.

| Tool | Template (argv after the tool name) |
|---|---|
| `subfinder` | `-d {target} -passive -silent` |
| `amass` | `enum -passive -d {target}` |
| `assetfinder` | `-silent {target}` |

### Zone A host-side sources

These are not sandbox binaries — they are Python fetchers in
`src/kryonsec/purple/zonea.py` that run on the host. Egress is locked to an
allowlist of hosts, and **every redirect hop is re-checked** against it.

Egress allowlist: `crt.sh`, `web.archive.org`, `otx.alienvault.com`,
`api.shodan.io`, `search.censys.io`, `stat.ripe.net`, `data.iana.org`,
`api.github.com`, `api.hackertarget.com`. Registry RDAP hosts are added
per-call from IANA's official bootstrap file — never from a redirect or from
untrusted data.

| Source | What it returns |
|---|---|
| `crt_sh_subdomains` | subdomains from certificate transparency logs |
| `wayback_subdomains` / `wayback_paths` | subdomains and historical paths |
| `otx_passive_dns` | AlienVault OTX passive DNS |
| `ripestat_whois`, `ripestat_asn` | registration and network ownership |
| `rdap_whois` | registry RDAP records |
| `github_recon` | org/repo/code search (needs `GITHUB_TOKEN`) |
| `hackertarget_hostsearch` | DNS history |
| `shodan_subdomains` | Shodan (needs `SHODAN_API_KEY`) |
| `censys_subdomains` | Censys (needs `CENSYS_API_ID`/`_SECRET`) |
| `cloud_asset_notes` | notes derived from discovered subdomains |

Keyless sources always run. Keyed sources without a key return a *skipped*
result that lands in the audit log as a visible notice — never a silent gap.

---

## 2. Active recon — first contact with the target

`ACTIVE_RECON_TEMPLATES`. Zone B, inside the sandbox. This is the only place
packets are ever sent to the target.

`dnsx` lives here, not in passive: resolving the target's names sends packets to
the target's resolvers.

| Tool | Template | In default plan? |
|---|---|---|
| `nmap` | `-Pn -sT -sV -sC --max-rate {rate} -p {ports} {target}` | yes — stage 1 |
| `naabu` | `-host {target} -p {ports} -rate {rate} -silent` | yes — stage 1 |
| `dnsx` | `-d {target} -silent` | yes — stage 1 |
| `httpx` | `-u {url} -silent -status-code -title -tech-detect` | yes — stage 2 |
| `whatweb` | `-a {1\|2\|3} --no-errors --color=never {url}` | yes — stage 2 |
| `katana` | `-u {url} -d {depth} -silent` | yes — stage 2 |
| `feroxbuster` | `-u {urlfuzz} -w <seclists common.txt> -t 5 --timeout 30` | yes — stage 2 |
| `/opt/kryonsec/openapi_probe.py` | `{url}` | yes — stage 2 |
| `gowitness` | `scan website --url {url} --screenshot-path /evidence --no-console --disable-db` | yes — stage 2 |
| `sslscan` | `--no-failed --sleep {rate} {target}` | yes — TLS ports only |
| `testssl.sh` | `--batch --severity={low\|medium\|high\|critical} --no-color {url}` | yes — TLS ports only |
| `rustscan` | `-a {target} -p {ports} --no-banner -t 2000` | **no** — allowlisted only |
| `hakrawler` | `-url {url} -depth {depth}` | **no** — allowlisted only |
| `massdns` | `-r <resolvers> -t A -o S -w /tmp/massdns.out <seclists DNS>` | **no** — allowlisted only |

Why the three are parked: `nmap` + `naabu` already cover discovery and one
failing is not worth a third scanner's runtime (`rustscan`); `hakrawler`
duplicates `katana`; `dnsx` covers resolution (`massdns`).

**Fixed plan, not free choice.** Stage 1 runs the three discovery tools once.
Stage 2 runs per *discovered web port* (`WEB_PORTS`), with `sslscan`/`testssl.sh`
added when the port is in `TLS_PORTS`. A failed tool never fails the state —
HYPOTHESIZE simply gets less evidence, and the failure is audited.

Ports scanned come from the fixed `RECON_PORTS` list (21, 22, 25, 53, 80, 110,
143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017). A
full-range scan against a third party is exactly what spec §9.1 fears.

**`nmap` uses `-sT` (connect scan) on purpose.** gVisor grants no raw sockets,
so the default SYN scan dies with *"Couldn't open a raw socket"*.

---

## 3. Exploit — only operator-approved hypotheses

`EXPLOIT_TEMPLATES`. The EXPLOIT state runs a tool only for a hypothesis the
operator approved at the human-review gate. Tool choice comes from the
hypothesis; **argv values are fixed constants** — the only variable is the
target URL, composed by `compose_url()`, which refuses any host outside
engagement scope.

| Tool | Template | Runs? |
|---|---|---|
| `nuclei` | `-u {url} -t {template} -rate-limit {rate} -timeout 30` | yes |
| `sqlmap` | `-u {url} --batch --risk={1\|2} --level={1\|2\|3} --technique={B\|E\|U\|T\|Q} --timeout={30\|60\|120} --threads={1\|2\|3\|4}` | yes |
| `nikto` | `-h {url} -timeout 30 -maxtime 120` | yes |
| `curl` | `-sS --max-time 30 {url}` | yes |
| `wget` | `-q -O - --timeout=30 {url}` | yes |
| `ffuf` | `-w <seclists> -u {urlfuzz} -t 5 -maxtime 120` | yes |
| `gobuster` | `dir -w <seclists> -u {urlfuzz} -t 5 --timeout 30s` | yes |
| `wfuzz` | `-w <seclists> --hc 404 {urlfuzz} -t 5` | yes |
| `dalfox` | `url {url} --silence` | yes |
| `commix` | `--url {url} --batch` | yes |
| `ssrfmap` | `-u {url} -m fetch` | yes |
| `arjun` | `-u {url}` | yes |
| `tplmap` | `-u {url}` | yes |
| `graphql-cop` | `-t {url} -o json` | yes |
| `searchsploit` | `--colorless {term}` | yes — local ExploitDB, no egress |
| `/opt/kryonsec/nuclei_meta.py` | `{term}` | yes — local template metadata |
| `jwt_tool` | `{token}` | **no** — needs a captured JWT; nothing produces one yet |
| `kr` | `scan {template} --host {url}` | **no** — needs a `.kx` route wordlist; none baked |

`jwt_tool` and `kr` are allowlisted so they are ready the day an input exists.
Until then each is an **audited skip**, not a silent one.

`{urlfuzz}` carries a `FUZZ` marker in the URL. Directory fuzzing targets the
**path only** — a query string in the hypothesis target is dropped, because
fuzzing a parameter value needs a per-parameter template that does not exist.

`SQL injection` argv is pinned to the safest settings: `--risk=1 --level=1
--technique=B --threads=1`.

---

## 4. Verify — independent confirmation

`VERIFY_TEMPLATES`. A finding is only marked *verified* when a tool
**different from the one that found it** agrees. The boolean probe's verdict is
final; the rest is supporting evidence.

| Tool | Template | Role |
|---|---|---|
| `curl` | `-sS --max-time 30 {url}` | primary boolean probe |
| `curl` (https retry) | `-sS --max-time 30 https://…` | retried over https when the plain-HTTP probe exits 56 |
| `http` (httpie) | `--ignore-stdin --check-status {url}` | secondary reachability |
| `nc` | `-z -w 30 {target} {port}` | raw TCP connect |
| `ncat` | `-z -w 30 {target} {port}` | raw TCP connect (alt) |
| `openssl` | `s_client -connect {hostport} -brief` | TLS handshake — https only |
| `dig` | `{target} +short` | DNS resolution |
| `/opt/kryonsec/probe.py` | `{url}` | baked probe, fixed argv |

The secondary probes prove the **asset is live** — never that the vulnerability
is real. They attach as supporting evidence only.

---

## 5. Post-exploit — evidence collection only

`POST_EXPLOIT_TEMPLATES`. Nothing destructive. **This state is wired but
dormant:** no tool in the current inventory produces an interactive shell, so
`_detect_shell()` returns False and the engagement routes EXPLOIT → VERIFY
directly.

Reachability rule: POST_EXPLOIT runs only when EXPLOIT reported
`shell_obtained and post_exploit_approved` — a separate approval gate from the
hypothesis review.

| Tool | Template | In plan? |
|---|---|---|
| `linpeas.sh` | `-a` | yes (when reachable) |
| `pspy64` | *(no args)* | yes |
| `linux-exploit-suggester.sh` | *(no args)* | yes |
| `/opt/kryonsec/enum_processes.py` | `{target}` | yes |
| `/opt/kryonsec/enum_fs.py` | `{target}` | yes |
| `/opt/kryonsec/enum_network.py` | `{target}` | yes |
| `/opt/kryonsec/find_secrets.py` | `{target}` | yes |
| `/opt/kryonsec/cloud_meta.py` | `{target}` | yes |
| `GetNPUsers.py` | `-dc-ip {target} {term}` | **dormant** |
| `GetUserSPNs.py` | `-dc-ip {target} {term}` | **dormant** |
| `GetADUsers.py` | `-dc-ip {target} {term}` | **dormant** |
| `findDelegation.py` | `-dc-ip {target} {term}` | **dormant** |
| `bloodhound-python` | `--collection All --domain {term} --dc-ip {target}` | **dormant** |

The impacket tools and `bloodhound-python` are read-only AD enumeration only —
no `secretsdump`, `atexec`, `wmiexec`, or anything that writes or extracts. They
need operator-provided domain/credential context, which cannot exist without a
shell. They activate the day a shell-producing tool exists.

The `enum_*.py` / `find_secrets.py` scripts enumerate the sandbox-visible
environment (for example mounted evidence) — not the engagement target's
network. `cloud_meta.py` probes the sandbox's own metadata service from inside;
there is none, so every probe reports unreachable — and that inert result is
itself the evidence.

---

## 6. Blue team — static analysis of a code folder

`BLUE_TEAM_TEMPLATES`. Runs against a **read-only** `/code` mount of a folder
the operator passed with `--code`. The mount point is a fixed literal; the host
path comes from the CLI, never from the LLM.

| Tool | Template | In plan? |
|---|---|---|
| `semgrep` | `--config=auto /code` | yes |
| `bandit` | `-r /code` | yes |
| `gitleaks` | `detect --source /code` | yes |
| `trivy` | `fs --scanners vuln /code` | yes |
| `checkov` | `-d /code` | yes |
| `syft` | `scan /code -o json` | yes |
| `osv-scanner` | `-r /code --format json` | yes |
| `grype` | `dir:/code -o json` | yes |
| `hadolint` | `/code/Dockerfile` | conditional — only when a Dockerfile exists |

`kube-bench` is deliberately absent: it audits a live node's kubelet config, not
a code folder — inside this sandbox it would test the sandbox itself.

`trivy`, `osv-scanner`, and `grype` need egress to their vulnerability
databases. Offline they fail as **audited skips**.

---

## 7. Copilot mode (Mode A) — no sandbox, no offensive tools

Mode A runs on Windows/macOS/Linux and never touches the sandbox. Its tools are
in `src/kryonsec/copilot/`:

| Tool | Behaviour |
|---|---|
| `read_file` | reads inside the workspace freely; outside needs approval |
| `list_directory` | same rule |
| `write_file` | writes inside the workspace freely; outside needs approval |
| CVE lookup | NVD-backed CVE detail (`copilot/cve.py`) |
| Web search | external search, secrets filtered first (`copilot/websearch.py`) |
| MCP tools | optional, operator-configured (`copilot/mcp_tools.py`) |

Path traversal via `../` or symlinks is resolved **before** the approval
decision, so the path shown in the prompt is the real path being acted on. When
the requested name and the resolved path differ (a symlink pointing outside the
workspace), the prompt shows both.

Mode A cannot see live engagement data. It reads only sanitized post-REPORT
summaries from `ltm_engagement_summaries`.

---

## Appendix — template grammar

From the header of `allowlist.py`. `{…}` segments may be a whole argument or sit
inside a larger literal (`--severity={low|medium}`).

| Placeholder | Matches |
|---|---|
| `"literal"` | exactly that text |
| `{a\|b\|c}` | one of the alternatives |
| `{url}` | an `http(s)://` URL |
| `{urlfuzz}` | an `http(s)://` URL containing the `FUZZ` marker |
| `{target}` | scope target (hostname / IP / CIDR-ish token) |
| `{ports}` | port spec, e.g. `80,443` or `1-1000` |
| `{port}` | a single TCP port |
| `{rate}` | a positive integer |
| `{depth}` | crawl depth, 1–3 |
| `{template}` | nuclei template path token, no shell metacharacters |
| `{hostport}` | `host:port` |
| `{token}` | a JWT-shaped token (three base64url segments) |
| `{term}` | search term, no shell metacharacters |

Arguments are compiled to `^…\Z` regexes. `\Z` rather than `$` is deliberate:
Python's `$` also matches just before a trailing newline, so `^…$` would have
accepted an argument ending in `\n`.

### Blocklist (safety Layer 8)

On top of the allowlist, the joined argv is checked against destructive
patterns and rejected if matched: `rm -rf`, `dd if=`, `DROP TABLE`, `mkfs`,
`shred`, and fork bombs. This is re-checked host-side.
