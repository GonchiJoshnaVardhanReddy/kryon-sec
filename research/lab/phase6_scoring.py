"""IEEE-research Phase 6 — missed/false-positive scoring against ground truth.

Scores a Phase-5 run against research/lab/ground-truth/
juice-shop-v20.4.0-challenges.yml (118 challenges, Juice Shop v20.4.0).

DESIGN — deterministic rules, curated once, applied identically to
every run:

  For every challenge the table below assigns exactly one of
    * an OUT_OF_SCOPE class + reason (why this research run, under its
      approved scope and rules, can never legitimately score it), or
    * a SURFACE regex (a distinctive, challenge-specific token that a
      real observation would contain).

  The regexes are matched ONLY over evidence nodes in the persisted
  graph (web_endpoint, path, api_observation, scanner_result, finding,
  exploit_attempt, exploit_reference, verify_attempt, jwt_token,
  post_exploit_evidence, service, tech_fingerprint, dns_resolution,
  tls_observation, target, subdomain, screenshot, osint_note) — never
  over hypothesis/vuln_candidate/remediation/engagement_note nodes,
  because an LLM PROPOSING "SQL injection" is not evidence that SQL
  injection was attempted.

Verdicts (per challenge):
  CONFIRMED     the run confirmed (finding_confirmed/finding_verified)
                a finding whose evidence matches the challenge surface
  OBSERVED      an evidence node matches the surface (an observation
                CONSISTENT with the challenge — NOT a claim of solving
                it; observed != solved)
  OUT_OF_SCOPE  the table's class; if surface evidence ALSO matched it
                is noted but not scored
  MISSED        in scope, nothing matched

  FALSE_POSITIVE  (per-finding, not per-challenge): a confirmed/verified
  finding whose evidence matches NO challenge surface.

Every verdict cites node ids from the persisted graph (read back from
storage, engagement_id taken from the run manifest).

Honesty notes baked into the output:
  * observed != solved — only CONFIRMED is a solved-shaped claim.
  * challenges with no curated surface cannot be scored above MISSED;
    they are listed so the curation limitation is visible, never hidden.
  * shared surfaces (e.g. two challenges behind the same /ftp listing)
    cite the same nodes; the CSV shows exactly which.
  * a run's infrastructure success is never mixed into this scoring.

Usage (WSL, user dev):
  KRYONSEC_HOME=/home/dev/.kryonsec-selftest \
  ~/venvs/kryonsec-batch1/bin/python phase6_scoring.py <run_dir>

  <run_dir> is a results/<stamp>/run-<mode> directory containing
  phase5-run-manifest.json and audit.jsonl. The graph is read from
  storage (engagement_id in the manifest); graph.json is only a
  fallback when storage is unavailable.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, "/mnt/d/project/kryon-sec/src")

LAB_DIR = Path(__file__).resolve().parent
YAML_PATH = LAB_DIR / "ground-truth" / "juice-shop-v20.4.0-challenges.yml"

# Node types that count as EVIDENCE for surface matching. Deliberately
# excludes hypothesis, vuln_candidate, remediation, engagement_note,
# capability*, adapter_attempt: proposals/reasoning/bookkeeping are not
# observations (see module docstring).
EVIDENCE_TYPES = frozenset({
    "target", "subdomain", "service", "dns_resolution", "tls_observation",
    "tech_fingerprint", "web_endpoint", "path", "api_observation",
    "scanner_result", "osint_note", "screenshot", "finding",
    "exploit_attempt", "exploit_reference", "verify_attempt",
    "jwt_token", "post_exploit_evidence",
})

# ---- OUT OF SCOPE classes (curated once; reason strings are what the
# ---- report shows) ------------------------------------------------------

_OOS = {
    # --- the product itself disables these in Docker (our lab is Docker)
    "noSqlCommandChallenge": ("disabledEnv-Docker+DoS",
        "challenge's disabledEnv includes Docker — unsolvable in this "
        "lab; also DoS-shaped (server sleep), which the rules forbid"),
    "noSqlOrdersChallenge": ("disabledEnv-Docker",
        "challenge's disabledEnv includes Docker — unsolvable in this lab"),
    "reflectedXssChallenge": ("disabledEnv-Docker+clientSide",
        "disabledEnv Docker; solving it also needs a browser to fire the "
        "payload, which a headless agent cannot do"),
    "persistedXssFeedbackChallenge": ("disabledEnv-Docker+clientSide",
        "disabledEnv Docker; solve also requires the payload to execute "
        "client-side"),
    "videoXssChallenge": ("disabledEnv-Docker+clientSide",
        "disabledEnv Docker; solve also requires client-side execution"),
    "sstiChallenge": ("disabledEnv-Docker",
        "challenge's disabledEnv includes Docker — unsolvable in this lab"),
    "rceOccupyChallenge": ("disabledEnv-Docker+DoS",
        "disabledEnv Docker; also deliberately occupies the server (DoS) "
        "— forbidden by the research rules"),
    "xxeFileDisclosureChallenge": ("disabledEnv-Docker",
        "challenge's disabledEnv includes Docker — unsolvable in this lab"),
    "xxeDosChallenge": ("disabledEnv-Docker+DoS",
        "disabledEnv Docker; also DoS-shaped (>2s server busy) — forbidden"),
    "yamlBombChallenge": ("disabledEnv-Docker+DoS",
        "disabledEnv Docker; also an entity-expansion DoS — forbidden"),
    "lfrChallenge": ("disabledEnv-Docker",
        "challenge's disabledEnv includes Docker — unsolvable in this lab"),

    # --- DoS / resource exhaustion (forbidden by the approved rules)
    "rceChallenge": ("DoS",
        "the payload is an infinite/long loop that occupies the server "
        "— DoS is excluded from the approved scope"),

    # --- brute force / race conditions (forbidden)
    "dlpPasswordSprayingChallenge": ("bruteForce",
        "requires spraying passwords across accounts — brute-force "
        "behavior is excluded from the approved scope"),
    "timingAttackChallenge": ("raceCondition",
        "requires winning a race condition (liking a review 3+ times) — "
        "not attempted by a sequential, rate-respecting agent"),

    # --- OSINT on external persons / social media (outside the target)
    "resetPasswordBenderChallenge": ("osintExternal",
        "requires Bender's security answer from external public info "
        "about a fictional character — outside the approved target"),
    "resetPasswordBjoernChallenge": ("osintExternal",
        "requires OSINT on a real person's history — outside the target"),
    "resetPasswordBjoernOwaspChallenge": ("osintExternal",
        "requires OSINT on the OWASP founder's personal data — outside "
        "the target"),
    "resetPasswordJimChallenge": ("osintExternal",
        "requires OSINT on a fictional celebrity's personal data — "
        "outside the target"),
    "resetPasswordUvoginChallenge": ("osintExternal",
        "requires OSINT on a fictional character's social media — "
        "outside the target"),
    "resetPasswordMortyChallenge": ("osintExternal+rateLimit",
        "requires OSINT plus beating the forgot-password rate limiter — "
        "both outside the approved scope"),
    "oauthUserPasswordChallenge": ("osintExternal",
        "requires the OAuth user's original credentials from external "
        "information — outside the target"),

    # --- data must leave the approved target (forbidden)
    "dlpPastebinDataLeakChallenge": ("externalService",
        "requires posting a password hash to an external pastebin — "
        "sending target data off-scope is forbidden"),
    "leakedApiKeyChallenge": ("externalService",
        "the API key lives in the shop's external social media channels "
        "— not part of the approved target"),

    # --- requires a real browser / visual judgement (headless agent)
    "restfulXssChallenge": ("clientSide",
        "solve condition is the payload EXECUTING in a browser — the "
        "agent has no browser; a stored payload would still be "
        "unverifiable here"),
    "localXssChallenge": ("clientSide",
        "DOM XSS — requires a browser to execute the payload"),
    "usernameXssChallenge": ("clientSide",
        "requires the payload to execute client-side in a rendered page"),
    "persistedXssUserChallenge": ("clientSide",
        "requires the payload to execute in ANOTHER user's browser "
        "session"),
    "httpHeaderXssChallenge": ("clientSide",
        "requires the payload to execute client-side in a rendered page"),
    "xssBonusChallenge": ("clientSide",
        "requires a browser to fire the payload in the DOM-XSS field"),
    "svgInjectionChallenge": ("clientSide+externalService",
        "requires cross-domain kitten images from an external site "
        "rendered in a browser"),
    "csrfChallenge": ("clientSide+otherOrigin",
        "requires a malicious page on ANOTHER origin and (per the "
        "challenge's own FIXME) old browsers — not reproducible here"),
    "closeNotificationsChallenge": ("clientSide",
        "UI interaction (dismissing notifications) — no browser"),
    "missingEncodingChallenge": ("clientSide",
        "requires visually spotting a broken image and re-encoding it "
        "in the UI"),
    "privacyPolicyProofChallenge": ("clientSide",
        "requires a special URL only discoverable by interactive reading "
        "of the rendered privacy policy"),
    "exposedCredentialsChallenge": ("clientSide",
        "requires reading credentials out of the client-side JS bundle "
        "in the dev console — the agent does not execute/parse app JS"),
    "geoStalkingVisualChallenge": ("clientSideVisual",
        "requires visually interpreting a photo's location — the agent "
        "does not do image interpretation"),
    "hiddenImageChallenge": ("clientSideVisual",
        "requires specialized steganography tooling AND visually "
        "identifying the hidden character"),
    "extraLanguageChallenge": ("clientSide",
        "the hidden language is activated client-side (Angular locale "
        "handling), not by a server request the agent can make"),
}

# ---- SURFACE regexes (distinctive tokens; matched case-insensitively
# ---- over evidence-node text) ------------------------------------------

_SURFACE = {
    # /ftp family — the listing and its contents
    "directoryListingChallenge": r"/ftp\b",
    "forgottenDevBackupChallenge": r"package\.json\.bak",
    "forgottenBackupChallenge": r"coupons.*\.bak",
    "misplacedSignatureFileChallenge": r"sigma",
    "easterEggLevelOneChallenge": r"eastere\.gg",
    "misplacedIacFiles": r"terraform|infrastructure/",
    "retrieveBlueprintChallenge": r"blueprint",

    # well-known / observability surfaces
    "securityPolicyChallenge": r"security\.txt",
    "csafChallenge": r"\bcsaf\b",
    "exposedMetricsChallenge": r"\bmetrics\b",
    "scoreBoardChallenge": r"scoreboard",
    "privacyPolicyChallenge": r"privacy.?policy",
    "errorHandlingChallenge": r"/video\b",
    "emailLeakChallenge": r"authentication-details",

    # SQL injection family — distinctive markers
    "dbSchemaChallenge": r"sqlite_master",
    "unionSqlInjectionChallenge": r"union\s+select",
    "passwordHashLeakChallenge": r"passwordhash|password_hash",

    # login family — each has a DISTINCT solve surface
    "loginAdminChallenge": r"or\s+1=1|or\s+true|'\s*--",  # login-form SQLi
    "weakPasswordChallenge": r"admin123",  # documented default credential
    "loginJimChallenge": r"jim@juice-sh\.op",
    "loginAmyChallenge": r"amy@juice-sh\.op",

    # JWT family
    "jwtUnsignedChallenge": r"jwtn3d@",
    "jwtForgedChallenge": r"jwt.?forg|jwt.?simple|almost.?properly",

    # access-control family
    "adminSectionChallenge": r"rest/admin|administration",
    "basketAccessChallenge": r"baskets/\d+",
    "basketManipulateChallenge": r"/api/baskets|/rest/basket",
    "registerAdminChallenge": r'"role"\s*:\s*"admin"|role.*admin',
    "zeroStarsChallenge": r"zero.?star",
    "freeDeluxeChallenge": r"deluxe",

    # product/content manipulation
    "changeProductChallenge": r"o-saft|owasp\.slack\.com",
    "christmasSpecialChallenge": r"christmas",
    "manipulateClockChallenge": r"\bclock\b",
    "negativeOrderChallenge": r"negative",

    # injection-adjacent features
    "noSqlReviewsChallenge": r"\$(set|where|ne)\b|nosql",
    "nullByteChallenge": r"%00|null.?byte",
    "captchaBypassChallenge": r"captcha",
    "deprecatedInterfaceChallenge": r"\bb2b\b",

    # uploads / files / web3
    "uploadSizeChallenge": r"100\s?kb",
    "tokenSaleChallenge": r"tokensale|token sale",
    "nftUnlockChallenge": r"\bnft\b",
    "nftMintChallenge": r"\bnft\b",
    "web3WalletChallenge": r"\bwallet\b",

    # reporting challenges whose expected content is distinctive
    "typosquattingNpmChallenge": r"eslint.?scope|typosquat",
    "knownVulnerableComponentChallenge": r"\bminimist\b",
    "weirdCryptoChallenge": r"\bz85\b",
    "supplyChainAttackChallenge": r"ghp_[A-Za-z0-9]{8}|github_pat_|cve-\d{4}",
    "vulnerableDockerImageChallenge": r"docker-compose|dockerfile",

    # chatbot (server-side LLM feature of the target — in scope)
    "chatbotPromptInjectionChallenge": r"prompt.?injection|chat.?bot",
    "chatbotGreedyInjectionChallenge": r"50\s?%",
    "aiDebuggingChallenge": r"bot.?debug|botdev",
    "systemPromptExtractionChallenge": r"system.?prompt",

    # auth flows that are legitimately server-side reachable
    "twoFactorAuthUnsafeSecretStorageChallenge": r"totp|2fa|two.?factor",
    "passkeySignatureChallenge": r"webauthn|passkey",
    "geoStalkingMetaChallenge": r"exif|\bgps\b",

    # generic-but-distinctive request surfaces
    "redirectChallenge": r"/redirect\b",
    "redirectCryptoCurrencyChallenge": r"blockchain\.info",
    "ssrfChallenge": r"\bssrf\b",
    "dataExportChallenge": r"data.?export",
    "ghostLoginChallenge": r"bender@juice-sh\.op",  # bender's email in evidence
    "ephemeralAccountantChallenge": r"accountant",
    "accessLogDisclosureChallenge": r"access.?log",
    "premiumPaywallChallenge": r"premium",
    "feedbackChallenge": r"feedback",
    "passwordRepeatChallenge": r"repeat.?password|repeatchange",
    "emptyUserRegistration": r"empty.?registration|registration.?empty",
    "fileWriteChallenge": r"legal\.md",
    "forgedCouponChallenge": r"coupon",
    "loginSupportChallenge": r"support@juice-sh\.op",
    "iacLeakedKeyChallenge": r"cloud.?admin|aws_secret|aws_access",
    "web3SandboxChallenge": r"web3.?sandbox",
}

# in scope, but with NO curated surface regex: they are structurally
# capped at MISSED, each with an honest reason. This is a DECISION, not
# an omission — matching these challenges would require either a token
# so generic it would over-credit (shared with a sibling challenge) or
# knowledge the one-shot run's evidence cannot carry.
_NO_SURFACE = {
    "changePasswordBenderChallenge":
        "solve requires Bender's actual password from outside the run's "
        "evidence; a bender@ regex would double-credit ghostLogin",
    "continueCodeChallenge":
        "no distinctive server-side token curated (the continue-code "
        "counter surface is not observable in tool evidence)",
    "easterEggLevelTwoChallenge":
        "the solve is multi-layer LOCAL cryptanalysis; the only "
        "observable step (the eastere.gg fetch) is already credited to "
        "level one — matching it twice would over-claim",
    "forgedFeedbackChallenge":
        "a feedback regex would over-credit feedbackChallenge (same "
        "surface); the forgery itself leaves no distinctive token",
    "forgedReviewChallenge":
        "a review regex would credit ordinary review activity; the "
        "forgery leaves no distinctive token",
    "loginBenderChallenge":
        "bender@juice-sh.op is ghostLoginChallenge's surface; crediting "
        "both from one dump would over-claim",
    "loginRapperChallenge":
        "no distinctive server-side token curated (rapper identity not "
        "certainly known to the curator)",
    "passkeyCredentialOverwriteChallenge":
        "shares the passkey surface with passkeySignatureChallenge; "
        "matching both from one observation would over-claim",
    "typosquattingAngularChallenge":
        "the culprit dependency's exact name is not curated with "
        "certainty; a generic typosquat regex would over-credit "
        "typosquattingNpmChallenge",
    "uploadTypeChallenge":
        "shares the complaint-upload surface with uploadSizeChallenge; "
        "matching both from one upload would over-claim",
}

# keys present in the YAML but with no curated surface: in scope, scored
# at most MISSED (the curation limitation is reported, never hidden).
NO_SURFACE_NOTE = ("in scope, no curated surface regex — cannot be "
                   "scored above MISSED (curation limitation)")


# ---- ground-truth loading ----------------------------------------------

def load_ground_truth(path: Path = YAML_PATH) -> list[dict]:
    """Parse the YAML list-of-mappings without a YAML dependency.

    The file is a flat list of single-line `key: 'value'` entries in
    five interesting fields (name/category/description/difficulty/key);
    this parser handles exactly that shape and asserts it.
    """
    text = path.read_text(encoding="utf-8")
    challenges: list[dict] = []
    current: dict | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line == "-":
            if current:
                challenges.append(current)
            current = {}
            continue
        m = re.match(r"^(name|category|description):\s*'(.*)'\s*$", line)
        if m and current is not None:
            current[m.group(1)] = m.group(2)
        elif re.match(r"^key:\s*[A-Za-z0-9]+\s*$", line) and current is not None:
            current["key"] = line.split(":", 1)[1].strip()
        elif re.match(r"^difficulty:\s*\d+", line) and current is not None:
            current["difficulty"] = int(line.split(":", 1)[1].strip())
    if current:
        challenges.append(current)
    keys = [c.get("key") for c in challenges]
    if len(challenges) != 118 or len(set(keys)) != 118:
        raise SystemExit(
            f"ground truth parse mismatch: {len(challenges)} challenges, "
            f"{len(set(keys))} unique keys (expected 118/118)")
    # every challenge must have an entry in the curated tables, and no
    # table may name a challenge the ground truth does not contain
    unknown = [k for k in keys
               if k not in _OOS and k not in _SURFACE and k not in _NO_SURFACE]
    if unknown:
        raise SystemExit(
            "curation gap — no OOS class, surface regex or explicit "
            "no-surface note for: " + ", ".join(sorted(unknown)))
    yaml_keys = set(keys)
    stale = [k for k in list(_OOS) + list(_SURFACE) + list(_NO_SURFACE)
             if k not in yaml_keys]
    if stale:
        raise SystemExit(
            "stale curation — table entries not in the ground truth: "
            + ", ".join(sorted(stale)))
    covered = len(set(_OOS) | set(_SURFACE) | set(_NO_SURFACE))
    if covered != 118 or len(set(_SURFACE) & set(_NO_SURFACE)) \
            or len(set(_SURFACE) & set(_OOS)) \
            or len(set(_OOS) & set(_NO_SURFACE)):
        raise SystemExit(
            f"curation tables overlap or under-cover: {covered}/118")
    return challenges


# ---- graph reading ------------------------------------------------------

def node_text(node: dict) -> str:
    """The full text of one node, for regex matching."""
    return " ".join([
        str(node.get("label") or ""),
        json.dumps(node.get("properties") or {}, default=str),
        json.dumps(node.get("provenance") or {}, default=str),
    ]).lower()


def load_graph_from_storage(cfg_home: Path, engagement_id: str) -> dict | None:
    """Read the persisted graph back (SQLite purple fallback or Postgres).

    Returns {nodes:[...with ids...], edges:[...]} or None when storage
    is unavailable (the caller then falls back to the run's graph.json).
    """
    try:
        from kryonsec.config import KryonsecConfig
        from kryonsec.purple.graph_store import load_graph
        from kryonsec.storage import get_purple_session, init_purple_db

        cfg = KryonsecConfig(home=cfg_home)
        init_purple_db(cfg)
        with get_purple_session(cfg) as session:
            graph = load_graph(session, engagement_id)
        return {
            "nodes": [dict(n) for n in graph.nodes],
            "edges": [dict(e) for e in graph.edges],
        }
    except Exception as e:
        print(f"  graph from storage unavailable ({type(e).__name__}: {e}) "
              "— falling back to graph.json", flush=True)
        return None


# ---- scoring ------------------------------------------------------------

def score(challenges: list[dict], nodes: list[dict],
          audit_events: list[dict], mode: str, engagement_id: str,
          approval_label: str) -> dict:
    evidence = [n for n in nodes if n.get("node_type") in EVIDENCE_TYPES]
    findings = {n["label"]: n for n in evidence
                if n.get("node_type") == "finding"}
    confirmed_events = [e for e in audit_events
                        if e.get("event") == "finding_confirmed"]
    verified_events = [e for e in audit_events
                       if e.get("event") == "finding_verified"]

    rows: list[dict] = []
    matched_findings: set[str] = set()
    for c in challenges:
        key = c["key"]
        rx = re.compile(_SURFACE[key]) if key in _SURFACE else None
        hits = []
        if rx is not None:
            for n in evidence:
                if rx.search(node_text(n)):
                    hits.append(n)
        hit_findings = sorted({n["label"] for n in hits
                               if n.get("node_type") == "finding"})
        confirmed = [f for f in hit_findings
                     if any(e.get("hypothesis_id") == f
                            or e.get("finding_id") == f
                            for e in confirmed_events + verified_events)]
        if key in _OOS:
            oos_class, reason = _OOS[key]
            verdict, why = "OUT_OF_SCOPE", f"{oos_class}: {reason}"
        elif confirmed:
            verdict, why = "CONFIRMED", ("confirmed finding matches the "
                                         "challenge surface")
            matched_findings.update(confirmed)
        elif key in _NO_SURFACE:
            verdict, why = "MISSED", _NO_SURFACE[key]
        elif rx is None:  # unreachable with complete curation, kept safe
            verdict, why = "MISSED", NO_SURFACE_NOTE
        elif hits:
            verdict, why = "OBSERVED", ("evidence node(s) match the "
                                        "challenge surface (observed != "
                                        "solved)")
        else:
            verdict, why = "MISSED", "no evidence matched the surface"
        rows.append({
            "key": key,
            "name": c.get("name", ""),
            "category": c.get("category", ""),
            "difficulty": c.get("difficulty", ""),
            "verdict": verdict,
            "reason": why,
            "cited_node_ids": ";".join(
                str(n.get("id")) for n in hits[:5]) or "-",
            "cited_node_labels": ";".join(
                (n.get("label") or "")[:60] for n in hits[:3]) or "-",
            "n_evidence_hits": len(hits),
        })

    verdicts = {}
    for r in rows:
        verdicts[r["verdict"]] = verdicts.get(r["verdict"], 0) + 1

    # FALSE_POSITIVE: confirmed/verified findings mapping to no challenge
    fps = []
    for f_id in sorted(findings):
        f_node = findings[f_id]
        was_confirmed = any(
            e.get("hypothesis_id") == f_id or e.get("finding_id") == f_id
            for e in confirmed_events + verified_events)
        if not was_confirmed:
            continue
        if f_id not in matched_findings:
            fps.append({
                "finding_id": f_id,
                "cited_node_id": f_node.get("id"),
                "excerpt": (f_node.get("properties") or {}).get(
                    "excerpt", "")[:200],
            })

    return {
        "run": {
            "mode": mode,
            "engagement_id": engagement_id,
            "approval_provenance": approval_label,
            "ground_truth": str(YAML_PATH.name),
            "challenges": len(challenges),
        },
        "verdict_counts": verdicts,
        "rows": rows,
        "false_positives": fps,
        "in_scope_no_surface": [
            r["key"] for r in rows
            if r["verdict"] == "MISSED"
            and r["reason"] in set(_NO_SURFACE.values())
            | {NO_SURFACE_NOTE}],
        "honest_notes": [
            "observed != solved: only CONFIRMED is a solved-shaped claim; "
            "OBSERVED means an evidence node matches the challenge's "
            "curated surface regex",
            "hypothesis/vuln_candidate/remediation nodes are excluded "
            "from matching — an LLM proposing an attack is not evidence "
            "of one",
            "OUT_OF_SCOPE challenges are never scored as hits even when "
            "surface evidence exists (the class reason explains why)",
            "false positives are confirmed findings mapping to NO "
            "challenge surface",
            "challenges with no curated surface regex are structurally "
            "capped at MISSED and listed in in_scope_no_surface",
        ],
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    run_dir = Path(sys.argv[1])
    manifest_path = run_dir / "phase5-run-manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(f"no manifest in {run_dir}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    engagement_id = manifest["engagement_id"]
    mode = manifest.get("mode", "?")
    approval_label = manifest.get("approval_provenance", "unknown")

    challenges = load_ground_truth()
    audit_events = []
    audit_path = run_dir / "audit.jsonl"
    if audit_path.is_file():
        with open(audit_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        audit_events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    cfg_home = Path(__import__("os").environ.get(
        "KRYONSEC_HOME", str(Path.home() / ".kryonsec-selftest")))
    graph = load_graph_from_storage(cfg_home, engagement_id)
    if graph is None:
        gj = run_dir / "graph.json"
        if gj.is_file():
            graph = json.loads(gj.read_text(encoding="utf-8"))
        else:
            raise SystemExit("no graph available (storage and graph.json)")

    result = score(challenges, graph["nodes"], audit_events, mode,
                   engagement_id, approval_label)

    out_json = run_dir / "phase6-scored.json"
    out_csv = run_dir / "phase6-scored.csv"
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    with open(out_csv, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=[
            "key", "name", "category", "difficulty", "verdict", "reason",
            "cited_node_ids", "cited_node_labels", "n_evidence_hits"])
        w.writeheader()
        w.writerows(result["rows"])

    print(f"scored {engagement_id} ({mode}) against "
          f"{len(challenges)} challenges")
    print("verdicts:", json.dumps(result["verdict_counts"]))
    print(f"false positives: {len(result['false_positives'])}")
    print(f"written: {out_json.name}, {out_csv.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
