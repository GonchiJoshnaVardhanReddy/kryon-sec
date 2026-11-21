"""Tool allowlist validation (spec v2.1.1 §4.7, §8.1 Layer 2).

Allowlists, not blocklists: argv must match the per-tool template exactly.
masscan is NOT allowlisted (v2.1.1 §9.1 — faster than canaries can react).

Templates are grouped by the state that spawns them (passive tools, active
recon, exploit, verify, post-exploit, enrichment); the ToolAllowlist default
is the union — one tool name, one template, everywhere.

The sandbox entrypoint re-checks tool names as defense-in-depth; the sync
test in tests/test_allowlist.py keeps the two lists from drifting.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


def is_program_name(name: str) -> bool:
    """True when ``name`` is a bare program name, not a path to one.

    The allowlist keys are mostly tools (``sqlmap``, ``nuclei``) and a few
    are scripts inside the sandbox image (``/opt/kryonsec/nuclei_meta.py``).
    Both are spawnable, but only the first is a *tool*: the second is a
    location, and rendering it where a tool name is expected invites a
    caller to treat it as one.
    """
    return bool(name) and "/" not in name and "\\" not in name


def exploit_tool_names() -> list[str]:
    """The entries of :data:`EXPLOIT_TEMPLATES` that name a tool.

    One entry is the HYPOTHESIZE enrichment helper — a script in the image,
    allowlisted so enrichment can spawn it, never run against a target.
    Everything else is a tool the execution engine can actually run, which
    is what a caller advertising the allowlist means to advertise.
    """
    return [name for name in EXPLOIT_TEMPLATES if is_program_name(name)]


class AllowlistViolation(Exception):
    pass


# Template grammar per argument:
#   "literal"       must match exactly
#   "{a|b|c}"       alternation: must be one of a, b, c
#   "{url}"         http(s) URL
#   "{urlfuzz}"     http(s) URL containing the FUZZ marker
#   "{target}"      scope target (hostname / IP / CIDR-ish token)
#   "{ports}"       port spec like "80,443" or "1-1000"
#   "{port}"        single TCP port
#   "{rate}"        positive integer (rate limit / sleep ms)
#   "{depth}"       crawl depth (1-3)
#   "{template}"    nuclei template path token (no shell metacharacters)
#   "{hostport}"    host:port (openssl s_client -connect)
#   "{token}"       JWT-shaped token (three base64url segments)
#   "{term}"        searchsploit search term (no shell metacharacters)
#   "{file}"        file under the fixed read-only /code mount — typed:
#                   every segment must be a real name (never "." or ".."),
#                   the value always starts "/code/", so it can never look
#                   like an option, and no shell metacharacter is allowed.
# {…} segments may sit inside a larger literal: "--severity={low|medium}"
# or "/opt/kryonsec/{probe}.py".

_ARG_PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$"),
    "urlfuzz": re.compile(
        r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*FUZZ"
        r"[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*$"),
    "target": re.compile(r"^[A-Za-z0-9._:/-]+$"),
    "ports": re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$"),
    "port": re.compile(r"^\d{1,5}$"),
    "rate": re.compile(r"^\d+$"),
    "depth": re.compile(r"^[1-3]$"),
    "template": re.compile(r"^[A-Za-z0-9_./-]+$"),
    "hostport": re.compile(r"^[A-Za-z0-9._-]+:\d{1,5}$"),
    "token": re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"),
    "term": re.compile(r"^[A-Za-z0-9 .:+,-]+$"),
    # comma-separated resolver addresses (IPv4/IPv6) — dnsx -r. No '-' in
    # the charset, so an option can never hide in a resolver slot.
    "resolver": re.compile(r"^[0-9A-Fa-f:.]+(,[0-9A-Fa-f:.]+)*$"),
    # file under the fixed read-only /code mount (BLUE_TEAM file-granular
    # tools). The negative lookahead bans "." and ".." as WHOLE segments at
    # every depth — a dotfile like ".env" is still selectable. The value
    # always begins "/code/", so it can never be parsed as an option by the
    # tool, and the charset has no shell metacharacter (argv is a list
    # anyway; this is the second, independent fence).
    "file": re.compile(
        r"^/code/(?:(?!\.{1,2}(?:/|$))[A-Za-z0-9._+@% -]+/)*"
        r"(?!\.{1,2}(?:/|$))[A-Za-z0-9._+@% -]+$"),
}


def is_safe_code_file(path: str) -> bool:
    """True when ``path`` is a value the typed ``{file}`` slot accepts.

    Public so plan builders can refuse to emit a path the allowlist would
    reject — the two rules can never drift.
    """
    # fullmatch, not match: the raw pattern ends with "$" (it gets embedded
    # into compiled templates, where \Z supplies the true anchor), and "$"
    # alone would accept a trailing newline here.
    return bool(_ARG_PATTERNS["file"].fullmatch(path))


# {…} segments inside an argument (may be the whole argument)
_SEGMENT_RE = re.compile(r"\{([^{}]+)\}")


def _alternation_or_pattern(inner: str) -> str:
    """Compile the inside of a {…} into a regex body string."""
    if "|" in inner:  # alternation {a|b|c}
        alts = [re.escape(a) for a in inner.split("|")]
        return "(?:" + "|".join(alts) + ")"
    if inner in _ARG_PATTERNS:
        return _ARG_PATTERNS[inner].pattern.removeprefix("^").removesuffix("$")
    raise ValueError(f"unknown template placeholder: {{{inner}}}")


def _compile_template_arg(arg: str) -> re.Pattern[str]:
    """Compile one template argument: literal parts escaped, every {…}
    segment expanded (alternation or named pattern). Subsumes the old
    prefix-value ("--risk={1|2}") and full-brace ("{url}") special cases."""
    body: list[str] = []
    i = 0
    for m in _SEGMENT_RE.finditer(arg):
        body.append(re.escape(arg[i:m.start()]))
        body.append(_alternation_or_pattern(m.group(1)))
        i = m.end()
    body.append(re.escape(arg[i:]))
    # \Z, not $: Python's $ also matches just BEFORE a trailing newline, so
    # "^…$" accepted an argument ending in "\n" (e.g. "http://t/\n" passed the
    # {url} template). \Z anchors to the true end of the string.
    return re.compile("^" + "".join(body) + r"\Z")


def compile_tool_templates(templates: dict[str, list[str]]) -> dict[str, list[re.Pattern[str]]]:
    """Precompile a {tool: [template args]} mapping."""
    return {
        tool: [_compile_template_arg(a) for a in args]
        for tool, args in templates.items()
    }


# Wordlists baked into the sandbox image (seclists is installed there)
SECLISTS_WEB = "/usr/share/seclists/Discovery/Web-Content/common.txt"
SECLISTS_DNS = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
DNS_RESOLVERS = "/usr/share/seclists/Miscellaneous/dns-resolvers.txt"
# Enumeration/probe scripts baked into the image (executable, shebang)
SANDBOX_SCRIPT_DIR = "/opt/kryonsec"

# Passive subdomain tools — run ONLY inside the sandbox with -passive flags
# (they query third-party sources; zero packets to the target by design).
PASSIVE_TOOL_TEMPLATES: dict[str, list[str]] = {
    "subfinder": ["-d", "{target}", "-passive", "-silent"],
    "amass": ["enum", "-passive", "-d", "{target}"],
    "assetfinder": ["-silent", "{target}"],
}

# First contact with the target (Zone B). dnsx lives HERE, not in passive —
# resolving the target's DNS names sends packets to the target's resolvers.
ACTIVE_RECON_TEMPLATES: dict[str, list[str]] = {
    # -sT (connect scan): gVisor grants no raw sockets — SYN scan is impossible
    "nmap": ["-Pn", "-sT", "-sV", "-sC", "--max-rate", "{rate}", "-p", "{ports}", "{target}"],
    # naabu 2.x (the image's version) has the same DNS behavior as dnsx
    # 1.3.1: without `-r` it ignores resolv.conf and queries its own
    # HARDCODED public-resolver list — queries the gate correctly drops
    # in every pinned-resolver policy, and the run dies with "Could not
    # run enumeration: no valid ipv4 or ipv6 targets were found" for a
    # domain target (found live, Phase-4 lab 2026-11-17: zero dnsmasq
    # queries, IP target unaffected). So `-r` carries the policy's
    # pinned resolver — filled by product code from the egress policy,
    # never caller-invented ({resolver} accepts only IP-ish charset).
    # `-duc` stops the pdtm.sh update phone-home (same choice as the
    # dnsx/httpx/nuclei templates).
    "naabu": ["-host", "{target}", "-r", "{resolver}", "-p", "{ports}",
              "-rate", "{rate}", "-silent", "-duc"],
    "httpx": ["-u", "{url}", "-silent", "-status-code", "-title", "-tech-detect"],
    "rustscan": ["-a", "{target}", "-p", "{ports}", "--no-banner", "-t", "2000"],
    "whatweb": ["-a", "{1|2|3}", "--no-errors", "--color=never", "{url}"],
    # -duc stops the pdtm.sh update phone-home (found live 2026-11-17:
    # katana without it queries api.pdtm.sh once per run — the gate
    # drops the connect, but the query is unnecessary external
    # metadata; same choice as the dnsx/naabu/httpx/nuclei templates).
    "katana": ["-u", "{url}", "-d", "{depth}", "-silent", "-duc"],
    "hakrawler": ["-url", "{url}", "-depth", "{depth}"],
    "feroxbuster": ["-u", "{urlfuzz}", "-w", SECLISTS_WEB, "-t", "5", "--timeout", "30"],
    # ProjectDiscovery httpx under its REAL Kali binary name. Kali's
    # packaging copies the upstream `httpx` binary to `httpx-toolkit`
    # ONLY (debian/rules — the plain `httpx` command does not exist in
    # this image). JSONL output (-json) is the stable machine-readable
    # contract used by the httpx-probe ADAPTER (Phase 2B.3); -duc keeps
    # the run offline-deterministic (no update check).
    # The legacy template name above (`httpx`) stays for the not-yet-
    # rebuilt images; in THIS image it exit-127s (binary absent) and the
    # failure is audited — the adapter path replaces it where registered.
    "httpx-toolkit": [
        "-u", "{url}", "-silent", "-json", "-status-code", "-title",
        "-tech-detect", "-no-color", "-duc",
    ],
    "sslscan": ["--no-failed", "--sleep", "{rate}", "{target}"],
    "testssl.sh": ["--batch", "--severity={low|medium|high|critical}", "--no-color", "{url}"],
    # dnsx resolves the target's names. dnsx 1.3.1 (the version in the
    # pinned image) made `-d` a BRUTE-FORCE input that requires -w; plain
    # resolution of a host list is `-l` (file or comma separated or
    # stdin). The legacy `-d` shape now dies at startup with
    # "missing wordlist(w) flag required with domain(d) input" — found
    # live in the Phase-4 lab experiments (2026-11-16). Without `-r`,
    # dnsx ignores resolv.conf and queries a HARDCODED list of public
    # resolvers (libs/dnsx DefaultResolvers: 1.1.1.1, 8.8.8.8, Quad9,
    # OpenDNS …) that the egress gate correctly drops in every
    # pinned-resolver policy — so `-r` carries the policy's pinned
    # resolver (filled by product code from the egress policy, never
    # caller-invented; {resolver} accepts only IP-ish charset, so no
    # option can hide in the slot). `-resp-only` makes the silent output
    # bare-IP lines — the exact shape the dnsx parsers read (1.3.1's
    # plain -silent prints the bare DOMAIN; -resp prints "host [A]
    # [ip]" with the ip bracketed; both unparseable). `-duc` stops the
    # pdtm.sh update phone-home and `-nc` the ANSI colors (same choice
    # as the httpx/nuclei templates; verified live against the real
    # binary through the gate: 1 query to the pinned resolver, bare-IP
    # output, zero pdtm queries).
    "dnsx": ["-l", "{target}", "-r", "{resolver}", "-resp-only",
             "-silent", "-duc", "-nc"],
    # gowitness (Phase 8): headless-Chrome screenshots into the rw /evidence
    # mount. gowitness 3.2.2 (the version in the pinned image) REMOVED
    # the v2-era `scan website` subcommand and the `--no-console` /
    # `--disable-db` flags — the old shape died at startup with a Usage
    # banner (found live, Phase-4 lab 2026-11-17). The v3 shape is
    # `scan single -u <url>`; v3 writes NO result database unless a
    # --write-* flag is passed (the read-only rootfs needs nothing
    # special), `-q` silences console chatter, and `--chrome-path`
    # pins the image's OWN chromium binary — without it gowitness 3.x
    # downloads a browser at runtime, which the egress gate correctly
    # drops. NOT in the default web plan's first stage; it runs per
    # discovered web port.
    "gowitness": [
        "scan", "single", "-u", "{url}", "--screenshot-path", "/evidence",
        "--chrome-path", "/usr/bin/chromium", "-q",
    ],
    # massdns (Phase 8): brute-force DNS resolution with the image's FIXED
    # wordlist + resolvers. Allowlisted but NOT in the default plan — dnsx
    # already covers resolution; this is here for future plan use.
    "massdns": [
        "-r", DNS_RESOLVERS, "-t", "A", "-o", "S", "-w", "/tmp/massdns.out",
        SECLISTS_DNS,
    ],
    # OpenAPI/API discovery (Phase 8): baked probe script, fixed argv
    f"{SANDBOX_SCRIPT_DIR}/openapi_probe.py": ["{url}"],
    # ---- Phase 4 expansion (2026-11-17) — HexStrike-review feasible set ----
    # WAF fingerprinting: -a checks EVERY signature (no early-stop
    # guess), --no-color for parseable output. Read-only HTTP probes
    # against the approved base URL, bounded by the entrypoint cap.
    "wafw00f": ["-a", "--no-color", "{url}"],
    # Content discovery: the SAME baked SecLists common.txt wordlist the
    # feroxbuster entry uses, 10 threads, per-request timeout, no ANSI.
    # NOT recursive (-r absent): recursion is feroxbuster's lane.
    "dirsearch": ["-u", "{url}", "-w", SECLISTS_WEB, "-t", "10",
                  "--timeout=30", "--no-color"],
    # DNS enumeration: --dnsserver carries the policy's PINNED resolver
    # (the same never-caller-invented rule as dnsx/naabu — a run against
    # hardcoded public resolvers is a known-doomed spawn, so plan code
    # OMITS the entry when no resolver is pinned). --enum is the bounded
    # standard record sweep (NS/SOA/MX/A + BIND version); no wordlist
    # brute-force here (dnsrecon territory, and unbounded time).
    "dnsenum": ["--dnsserver", "{resolver}", "--enum", "{target}"],
    # fierce DNS recon: --dns-servers pins the resolver (same rule);
    # --domain takes the scope target ({term} charset covers hostnames).
    # fierce's own recursion is bounded by its zero-max default OFF —
    # the shipped template pins no --wide/--depth extensions.
    "fierce": ["--domain", "{term}", "--dns-servers", "{resolver}"],
    # NetBIOS/SMB enumeration (Phase 4): PORT-GATED — plan code only
    # builds these entries when discovery OBSERVED 139/445 open. -t 2000
    # bounds nbtscan's per-address response wait (Kali's nbtscan 1.7.2
    # takes MILLISECONDS here — verified from its real usage output,
    # default 1000; the earlier -w flag does not exist in this build and
    # exited 2 with usage text in the Phase 4b lab run). The {target}
    # slot for nbtscan carries the target's RESOLVED IP — nbtscan 1.7.2
    # rejects hostnames ("Error: ... is not an IP address or address
    # range.", verified live) and the plan omits the row when discovery
    # resolved nothing. smbmap's --no-banner/--no-color/--no-update are
    # REAL flags (verified from the tool's own help): banner, color
    # codes and the "Working on it" spinner are stripped at the source,
    # keeping stdout parseable. enum4linux-ng -A is its
    # simple-enumeration sweep (users/shares/policies, no credential
    # brute) — it has NO no-color flag, so its excerpt is cleaned
    # host-side (clean_excerpt).
    "nbtscan": ["-t", "2000", "{target}"],
    "smbmap": ["-H", "{target}", "--no-banner", "--no-color", "--no-update"],
    "enum4linux-ng": ["-A", "{target}"],
}

# ---- exploit templates --------------------------------------------------------

# The reviewed, hash-pinned nuclei template manifest (Phase 2B.8 — the same
# file the sandbox image bakes to /opt/kryonsec/nuclei_manifest.json and the
# entrypoint gate re-verifies at execution time). The EXPLOIT lane's nuclei
# template is BUILT from it: the manifest is the single source of truth, and
# a manifest change IS an allowlist change (test_nuclei_policy.py asserts the
# two agree with the adapter's frozen template).
_NUCLEI_MANIFEST_PATH = Path(__file__).with_name("nuclei_manifest.json")


def nuclei_manifest_template_args() -> tuple[str, ...]:
    """Every reviewed template as flat ``(-t, path)`` argv pairs.

    Reads the reviewed, hash-pinned manifest — the ONLY template inventory
    any product nuclei run may carry. The full baked tree is NEVER
    selectable: Phase 2B.7 audited it and found unsafe subtrees, and the
    Phase-1 lab engagement (lab-p5-full-20261117T110737Z) proved the full
    tree cannot even complete inside the sandbox's 300s cap — 11,143
    templates loaded, 262 with runtime errors, killed at the cap.
    """
    data = json.loads(_NUCLEI_MANIFEST_PATH.read_text(encoding="utf-8"))
    paths = sorted(data.get("templates") or {})
    if not paths:
        raise RuntimeError(
            "nuclei_manifest.json carries no reviewed templates — "
            "nuclei execution stays disabled (fail closed)")
    return tuple(arg for path in paths for arg in ("-t", path))


#: rendered once at import — the manifest is pinned, the pairs are frozen
_NUCLEI_TEMPLATE_ARGS: tuple[str, ...] = nuclei_manifest_template_args()


def render_exploit_template(tool: str, **slots: str) -> "list[str] | None":
    """Render ``EXPLOIT_TEMPLATES[tool]``, filling ``{slot}`` placeholders.

    The renderer build_argv uses for the tools whose templates are built
    here (nuclei: manifest-pinned; wget: bounded retries) — the rendered
    argv and the Layer-2 template are then the SAME list, so the two
    cannot drift. Unknown slots are left untouched (there are none by
    construction).
    """
    template = EXPLOIT_TEMPLATES.get(tool)
    if template is None:
        return None
    rendered: list[str] = []
    for arg in template:
        for name, value in slots.items():
            arg = arg.replace("{" + name + "}", value)
        rendered.append(arg)
    return rendered


# Exploit/testing tools (spec §4.7; masscan intentionally absent)
EXPLOIT_TEMPLATES: dict[str, list[str]] = {
    # nuclei (Phase 1, 2026-11-17): the reviewed manifest ONLY — never the
    # full baked tree. The legacy full-tree selection died twice over in the
    # lab engagement: (1) 11,143 UNREVIEWED templates with 262 runtime
    # errors behind a Gate-2 approval that could not have reviewed them,
    # (2) killed at the sandbox's 300s cap (exit 137 — gVisor reports the
    # entrypoint timeout's SIGKILL as 137, not coreutils' 124; proven with
    # a zero-memory `sleep 400` run) before finishing, while nuclei's own
    # external IP-check phoned home and marked the target unresponsive.
    # The flags are the RECON_ACTIVE probe's proven safety set (frozen
    # literals, adapter_nuclei.py): -etags intrusive (never a self-declared
    # intrusive template), -silent/-nc (match lines only, no ANSI), -ni
    # (NO interactsh/OAST), -duc (no update check), -or (no raw
    # request/response dumps), -rl 20 -c 10 (bounded rate/concurrency),
    # -retries 1, and -mt 2m — nuclei's own graceful max-time so the run
    # COMPLETES inside the 300s cap instead of being killed.
    "nuclei": [
        "-u", "{url}", *_NUCLEI_TEMPLATE_ARGS,
        "-etags", "intrusive", "-silent", "-nc", "-ni", "-duc", "-or",
        "-rl", "20", "-c", "10", "-timeout", "30", "-retries", "1",
        "-mt", "2m",
    ],
    "sqlmap": [
        "-u", "{url}", "--batch", "--risk={1|2}", "--level={1|2|3}",
        "--technique={B|E|U|T|Q}", "--timeout={30|60|120}", "--threads={1|2|3|4}",
    ],
    "nikto": ["-h", "{url}", "-timeout", "30", "-maxtime", "120"],
    "curl": ["-sS", "--max-time", "30", "{url}"],
    # wget (Phase 1, 2026-11-17): bounded retries. wget's DEFAULT -t 20
    # burned 266s inside the sandbox on the lab /ftp response (the server
    # closes the body 12 bytes short of Content-Length; every retry hit
    # the same quirk). -t 3 with --waitretry=2 caps the worst case near
    # 30s of transfer attempts — a truncated response is still captured
    # content, and the failure is honestly classified downstream.
    "wget": ["-q", "-O", "-", "--timeout=30", "-t", "3", "--waitretry=2",
             "{url}"],
    # ffuf/gobuster/wfuzz: directory fuzzing with the sandbox's common wordlist.
    # {urlfuzz}: the URL carries the FUZZ position marker.
    "ffuf": ["-w", SECLISTS_WEB, "-u", "{urlfuzz}", "-t", "5", "-maxtime", "120"],
    "gobuster": ["dir", "-w", SECLISTS_WEB, "-u", "{urlfuzz}", "-t", "5", "--timeout", "30s"],
    "wfuzz": ["-w", SECLISTS_WEB, "--hc", "404", "{urlfuzz}", "-t", "5"],
    # injection specialists
    "dalfox": ["url", "{url}", "--silence"],
    "commix": ["--url", "{url}", "--batch"],
    "ssrfmap": ["-u", "{url}", "-m", "fetch"],
    "arjun": ["-u", "{url}"],
    "tplmap": ["-u", "{url}"],
    # jwt_tool takes a captured token (three-segment JWT), not a URL
    "jwt_tool": ["{token}"],
    # kiterunner scans API routes from a .kx wordlist file ({template} token)
    "kr": ["scan", "{template}", "--host", "{url}"],
    # graphql-cop takes the target with -t (its README: `graphql-cop.py -t
    # <url>`); -u is not one of its flags, so the old template produced an
    # argv the tool rejects outright.
    "graphql-cop": ["-t", "{url}", "-o", "json"],
    # ExploitDB search (local database inside the image — no egress)
    "searchsploit": ["--colorless", "{term}"],
    # Nuclei template metadata search (Phase 8): local template files in
    # the image — used by HYPOTHESIZE enrichment, same shape as searchsploit
    f"{SANDBOX_SCRIPT_DIR}/nuclei_meta.py": ["{term}"],
}

# Independent confirmation tools (a finding is only "verified" when a tool
# DIFFERENT from the one that found it agrees).
VERIFY_TEMPLATES: dict[str, list[str]] = {
    "curl": ["-sS", "--max-time", "30", "{url}"],
    "http": ["--ignore-stdin", "--check-status", "{url}"],
    "openssl": ["s_client", "-connect", "{hostport}", "-brief"],
    "dig": ["{target}", "+short"],
    "nc": ["-z", "-w", "30", "{target}", "{port}"],
    "ncat": ["-z", "-w", "30", "{target}", "{port}"],
    # the baked probe script (python) — fixed argv, never free-form code
    f"{SANDBOX_SCRIPT_DIR}/probe.py": ["{url}"],
}

# Post-exploit enumeration (Phase 4): evidence collection only, nothing
# destructive. linpeas/pspy/LES run with no or fixed flags; the enum_*.py /
# find_secrets.py scripts are baked into the image and take the target as
# context (they enumerate the sandbox-visible environment, e.g. mounted
# evidence, not the engagement target's network).
# Phase 8 DORMANT additions: impacket AD recon + bloodhound-python +
# cloud_meta.py are allowlisted and in the image but NOT in the fixed
# POST_EXPLOIT_PLAN — no current tool yields a shell, and AD tools need
# operator-provided domain/credential context that cannot exist without
# one. They activate the day a shell-producing tool exists (same rule as
# the rest of POST_EXPLOIT: the plan, never the LLM, decides).
POST_EXPLOIT_TEMPLATES: dict[str, list[str]] = {
    # `-s` (stealth/faster) disables the `su` brute force and the slow
    # broad finds; `-N` clears linpeas' colour variables and `-q` drops
    # the banner (the ASCII logo is hardcoded truecolor — measured: 1718
    # escapes survive -N, which would make the bounded excerpt pure art).
    # NOT `-a`: it sets ONLINE_VULN_CHECKS=1 (a HackTricks phone-home)
    # and EXTRA_CHECKS, and the `su` brute force never finishes inside
    # the sandbox's 300s cap — measured 2026-11-18, the container dies at
    # ~255s mid-"Bruteforcing user root", so the run produced no payload
    # at all. `-s -N -q` is bounded, offline AND readable.
    "linpeas.sh": ["-s", "-N", "-q"],
    "pspy64": [],
    "linux-exploit-suggester.sh": [],
    f"{SANDBOX_SCRIPT_DIR}/enum_processes.py": ["{target}"],
    f"{SANDBOX_SCRIPT_DIR}/enum_fs.py": ["{target}"],
    f"{SANDBOX_SCRIPT_DIR}/enum_network.py": ["{target}"],
    f"{SANDBOX_SCRIPT_DIR}/find_secrets.py": ["{target}"],
    # cloud metadata enumeration (Phase 8): probes the sandbox's OWN
    # metadata service from inside — inert by design (there is none), it
    # exists so the check exists the day a shell lands somewhere real.
    f"{SANDBOX_SCRIPT_DIR}/cloud_meta.py": ["{target}"],
    # impacket AD recon (Phase 8, dormant — read-only enumeration only;
    # no secretsdump/atexec/wmiexec or anything that writes/extracts)
    "GetNPUsers.py": ["-dc-ip", "{target}", "{term}"],
    "GetUserSPNs.py": ["-dc-ip", "{target}", "{term}"],
    "GetADUsers.py": ["-dc-ip", "{target}", "{term}"],
    "findDelegation.py": ["-dc-ip", "{target}", "{term}"],
    # bloodhound-python (Phase 8, dormant): full collection needs domain
    # creds; the template pins the collection method to All
    "bloodhound-python": [
        "--collection", "All", "--domain", "{term}", "--dc-ip", "{target}"],
}

# Blue-team static analyzers (Phase 5): run against the read-only /code
# mount of a user-provided code folder. The mount point is the FIXED
# literal /code — the host path comes from the CLI (--code), never the
# LLM, and the sandbox mounts it read-only.
BLUE_TEAM_TEMPLATES: dict[str, list[str]] = {
    "semgrep": ["--config=auto", "/code"],
    "bandit": ["-r", "/code"],
    "gitleaks": ["detect", "--source", "/code"],
    "trivy": ["fs", "--scanners", "vuln", "/code"],
    "checkov": ["-d", "/code"],
    "hadolint": ["/code/Dockerfile"],
    # Phase 8: SBOM + dependency-vulnerability scanners (JSON output)
    "syft": ["scan", "/code", "-o", "json"],
    "osv-scanner": ["scan", "source", "-r", "--format", "json", "/code"],
    "grype": ["dir:/code", "-o", "json"],
    # Phase 4 (2026-11-17): dir-mode binary/forensics scanners over
    # the read-only /code mount.
    # terrascan deferred: no Kali package (Dockerfile note).
    # checksec's dir mode audits every ELF's hardening in one run.
    "checksec": ["--dir=/code"],
    # exiftool -r walks /code printing file metadata (any file type);
    # -q keeps per-file warnings out of the evidence excerpt.
    "exiftool": ["-r", "-q", "/code"],
    # ---- Phase 3 (2026-11-19): file-granular binary tools --------------
    # The typed {file} slot exists now: every argv carries ONLY a
    # traversal-free path under the fixed read-only /code mount. The plan
    # (blue_team.build_file_scan_plan) selects regular files host-side,
    # never follows symlinks, and caps file count/size. Flags verified
    # live against the pinned image on /usr/bin/ls (2026-11-19).
    # strings: printable strings, minimum length 8.
    "strings": ["-n", "8", "{file}"],
    # xxd: first 4096 bytes as a hex dump — bounded by the flag itself.
    "xxd": ["-l", "4096", "{file}"],
    # binwalk -B: signature scan ONLY (-e extraction is never used).
    "binwalk": ["-B", "{file}"],
    # objdump: disassembly without raw instruction bytes (smaller, readable).
    "objdump": ["-d", "--no-show-raw-insn", "{file}"],
    # ROPgadget: pop/ret gadgets only — the full gadget inventory is
    # output-heavy and says nothing a bounded excerpt can carry.
    "ROPgadget": ["--binary", "{file}", "--depth", "6",
                  "--only", "pop|ret"],
    # radare2: file info only (-c "iI;q"); -N skips the user rc file so a
    # planted .radare2rc in the code folder can never run.
    "r2": ["-N", "-q", "-c", "iI;q", "{file}"],
    # gdb: defined functions only; -nx disables init files for the same
    # reason (nothing in the code folder can execute).
    "gdb": ["-nx", "-batch", "-ex", "info functions", "{file}"],
}

# Historical name kept (tests / callers import it): the union of everything
# above — one ToolAllowlist validates every state's spawns.
EXPLOIT_ALLOWLIST_TEMPLATES: dict[str, list[str]] = {
    **PASSIVE_TOOL_TEMPLATES,
    **ACTIVE_RECON_TEMPLATES,
    **EXPLOIT_TEMPLATES,
    **VERIFY_TEMPLATES,
    **POST_EXPLOIT_TEMPLATES,
    **BLUE_TEAM_TEMPLATES,
}


# Hardline blocklist (safety Layer 8) — regex patterns over the joined argv
BLOCKLIST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\brm\s+-rf\b"),
    re.compile(r"\bdd\s+if="),
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bshred\b"),
    re.compile(r"\b:\(\)\s*\{.*\};\s*:"),  # fork bomb
]


class ToolAllowlist:
    """Layer 2: per-subagent tool + argv template validation."""

    def __init__(self, templates: dict[str, list[str]] | None = None):
        # None = the shipped defaults; {} = deliberately NO tools (fail
        # closed — an empty mapping must never expand to the full set)
        self._compiled = compile_tool_templates(
            templates if templates is not None else EXPLOIT_ALLOWLIST_TEMPLATES
        )

    def validate(self, tool_name: str, argv: list[str]) -> None:
        """Raise AllowlistViolation unless argv matches the tool's template."""
        if tool_name not in self._compiled:
            raise AllowlistViolation(f"tool not in allowlist: {tool_name}")

        patterns = self._compiled[tool_name]
        # argv[0] is the tool name itself; the rest must match the template
        args = argv[1:] if argv and argv[0] == tool_name else argv

        if len(args) != len(patterns):
            raise AllowlistViolation(
                f"{tool_name}: expected {len(patterns)} args, got {len(args)}"
            )
        for pattern, arg in zip(patterns, args):
            if not pattern.match(arg):
                raise AllowlistViolation(
                    f"{tool_name}: argument {arg!r} rejected by template"
                )

    def check_blocklist(self, argv: list[str]) -> None:
        """Layer 8: reject destructive patterns (also re-checked host-side)."""
        joined = " ".join(argv)
        for pat in BLOCKLIST_PATTERNS:
            if pat.search(joined):
                raise AllowlistViolation(f"blocklist pattern matched: {pat.pattern}")
