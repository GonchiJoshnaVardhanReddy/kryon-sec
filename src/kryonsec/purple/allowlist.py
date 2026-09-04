"""Tool allowlist validation (spec v2.1.1 §4.7, §8.1 Layer 2).

Allowlists, not blocklists: argv must match the per-tool template exactly.
masscan is NOT allowlisted (v2.1.1 §9.1 — faster than canaries can react).
"""

from __future__ import annotations

import re


class AllowlistViolation(Exception):
    pass


# Template grammar per argument:
#   "literal"       must match exactly
#   "{a|b|c}"       alternation: must be one of a, b, c
#   "{url}"         http(s) URL
#   "{target}"      scope target (hostname / IP / CIDR-ish token)
#   "{ports}"       port spec like "80,443" or "1-1000"
#   "{rate}"        positive integer (rate limit)
#   "{template}"    nuclei template path token (no shell metacharacters)

_ARG_PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$"),
    "target": re.compile(r"^[A-Za-z0-9._:/-]+$"),
    "ports": re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$"),
    "rate": re.compile(r"^\d+$"),
    "template": re.compile(r"^[A-Za-z0-9_./-]+$"),
}


def _compile_template_arg(arg: str) -> re.Pattern[str]:
    # Prefix-value form: "--risk={1|2}" or "--timeout={30|60|120}"
    m = re.match(r"^(-+)([A-Za-z0-9_-]+)=\{(.+)\}$", arg)
    if m:
        prefix, name, inner = m.group(1) + m.group(2) + "=", m.group(2), m.group(3)
        value_re = _alternation_or_pattern(inner)
        return re.compile("^" + re.escape(prefix) + value_re + "$")

    if arg.startswith("{") and arg.endswith("}"):
        return re.compile("^" + _alternation_or_pattern(arg[1:-1]) + "$")
    return re.compile("^" + re.escape(arg) + "$")


def _alternation_or_pattern(inner: str) -> str:
    """Compile the inside of a {…} into a regex body string."""
    if "|" in inner:  # alternation {a|b|c}
        alts = [re.escape(a) for a in inner.split("|")]
        return "(?:" + "|".join(alts) + ")"
    if inner in _ARG_PATTERNS:
        return _ARG_PATTERNS[inner].pattern.removeprefix("^").removesuffix("$")
    raise ValueError(f"unknown template placeholder: {{{inner}}}")


def compile_tool_templates(templates: dict[str, list[str]]) -> dict[str, list[re.Pattern[str]]]:
    """Precompile a {tool: [template args]} mapping."""
    return {
        tool: [_compile_template_arg(a) for a in args]
        for tool, args in templates.items()
    }


# Default EXPLOIT allowlist (spec §4.7; masscan intentionally absent)
EXPLOIT_ALLOWLIST_TEMPLATES: dict[str, list[str]] = {
    "nmap": ["-sV", "-sC", "--max-rate", "{rate}", "-p", "{ports}", "{target}"],
    "sqlmap": [
        "-u", "{url}", "--batch", "--risk={1|2}", "--level={1|2|3}",
        "--technique={B|E|U|T|Q}", "--timeout={30|60|120}", "--threads={1|2|3|4}",
    ],
    "nuclei": ["-u", "{url}", "-t", "{template}", "-rate-limit", "{rate}", "-timeout", "30"],
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
        self._compiled = compile_tool_templates(templates or EXPLOIT_ALLOWLIST_TEMPLATES)

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
