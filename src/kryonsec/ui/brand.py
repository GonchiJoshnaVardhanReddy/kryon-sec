"""Responsive KRYONSEC wordmark.

Branding is presentation only.  One renderer feeds every terminal surface
(the Textual workspace, the legacy Rich shell, and the CLI banner), so the
wordmark cannot drift between modes or grow back into the one-line top bar.

Design rules enforced here (not in the callers):

* Mode A renders white/monochrome, Mode B renders the brand purple.  The
  colour is supplied by the caller's :class:`ThemeTokens`; this module never
  invents a colour.
* ``by rahasec`` always sits under the wordmark and is always visually
  smaller: it is a single dim line, never part of the block art.
* Wide terminals get the block wordmark; narrower terminals step down to a
  medium then a one-line mark.  Nothing is ever clipped horizontally.
* Terminals that cannot encode box-drawing characters get an ASCII font.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.text import Text

from .theme import ThemeTokens

CREDIT = "by rahasec"
TAGLINE = "security workspaces for your terminal"

#: The widest block font.  Eight letters, 71 columns.
LARGE_UNICODE: tuple[str, ...] = (
    "██╗  ██╗ ██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗ ███████╗ ███████╗ ██████╗",
    "██║ ██╔╝ ██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║ ██╔════╝ ██╔════╝██╔════╝",
    "█████╔╝  ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║ ███████╗ █████╗  ██║     ",
    "██╔═██╗  ██╔══██╗  ╚██╔╝  ██║   ██║██║╚██╗██║ ╚════██║ ██╔══╝  ██║     ",
    "██║  ██╗ ██║  ██║   ██║   ╚██████╔╝██║ ╚████║ ███████║ ███████╗╚██████╗",
    "╚═╝  ╚═╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝ ╚══════╝ ╚══════╝ ╚═════╝",
)

#: Medium font: the same block-letter language as the large mark, five rows
#: high and 47 columns wide.  It deliberately avoids the slashes and pipes of
#: the old fallback, which were hard to read at a glance.
MEDIUM_UNICODE: tuple[str, ...] = (
    "█   █ ████  █   █ █████ █   █ █████ █████ █████",
    "█  █  █   █  █ █  █   █ ██  █ █     █     █    ",
    "███   ████    █   █   █ █ █ █ ████  ████  █    ",
    "█  █  █  █    █   █   █ █  ██     █ █     █    ",
    "█   █ █   █   █   █████ █   █ █████ █████ █████",
)

#: ASCII terminals get the identical letterforms in ``#`` blocks.
MEDIUM_ASCII: tuple[str, ...] = tuple(
    line.replace("█", "#") for line in MEDIUM_UNICODE
)

#: Spelled-out mark for very narrow terminals.
SPACED = "K R Y O N S E C"
PLAIN = "KRYONSEC"

_LARGE_WIDTH = max(len(line) for line in LARGE_UNICODE)
_MEDIUM_WIDTH = max(len(line) for line in MEDIUM_UNICODE)


@dataclass(frozen=True)
class BrandVariant:
    """One selected presentation for a terminal width."""

    lines: tuple[str, ...]
    compact: bool = False


def brand_variant(width: int, *, unicode_ok: bool = True) -> BrandVariant:
    """Pick the widest mark that fits ``width`` columns.

    Widths include no padding; callers may centre the result.  The thresholds
    are the art's own widths plus two columns of breathing room.
    """
    width = max(1, int(width))
    if not unicode_ok:
        if width >= _MEDIUM_WIDTH + 2:
            return BrandVariant(MEDIUM_ASCII)
        if width >= len(SPACED) + 2:
            return BrandVariant((SPACED,))
        if width >= len(PLAIN):
            return BrandVariant((PLAIN,))
        return BrandVariant(("",))
    if width >= _LARGE_WIDTH + 2:
        return BrandVariant(LARGE_UNICODE)
    if width >= _MEDIUM_WIDTH + 2:
        return BrandVariant(MEDIUM_UNICODE)
    if width >= len(SPACED) + 2:
        return BrandVariant((SPACED,))
    if width >= len(PLAIN):
        return BrandVariant((PLAIN,))
    return BrandVariant(("",))


def compact_brand(width: int) -> str:
    """One-line brand that never exceeds ``width`` columns."""
    width = max(1, int(width))
    with_credit = f"{PLAIN}  ·  {CREDIT}"
    if width >= len(with_credit):
        return with_credit
    if width >= len(PLAIN):
        return PLAIN
    return ""


def brand_text(
    tokens: ThemeTokens,
    *,
    width: int,
    unicode_ok: bool = True,
    compact: bool = False,
    show_tagline: bool = True,
) -> Text:
    """Render the wordmark and its credit as one Rich ``Text``.

    ``compact`` keeps the brand visible during conversation activity without
    spending vertical space: one line, with the credit still attached but
    dimmer.  The wordmark colour is always ``tokens.brand`` — white in Mode A,
    purple in Mode B — so switching modes restyles the same component.
    """
    text = Text(justify="center")
    if compact:
        mark = compact_brand(width)
        if not mark:
            return text
        word, _, credit = mark.partition("  ·  ")
        text.append(word, style=f"bold {tokens.brand}")
        if credit:
            text.append(f"  ·  {credit}", style=f"dim {tokens.muted}")
        return text

    variant = brand_variant(width, unicode_ok=unicode_ok)
    for line in variant.lines:
        text.append(line.rstrip() + "\n", style=f"bold {tokens.brand}")
    if not variant.lines[0]:
        return text
    text.append("\n")
    # The credit is a single dim line: visibly smaller than the block art.
    if width >= len(CREDIT):
        text.append(f"{CREDIT}\n", style=f"dim {tokens.muted}")
    if show_tagline and width >= len(TAGLINE):
        text.append(f"{TAGLINE}\n", style=f"dim {tokens.faint}")
    return text
