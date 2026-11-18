"""Branding contracts: one responsive wordmark, two modes, no clipping.

The wordmark is presentation only; these tests do not touch security logic.
They lock the properties the UI depends on: the same art at every surface,
white in Mode A, purple in Mode B, ``by rahasec`` underneath, and a smaller
variant when the terminal cannot hold the full block font.
"""

from __future__ import annotations

from kryonsec.cli import BANNER, BANNER_ASCII, banner_styled
from kryonsec.ui.brand import (
    CREDIT,
    LARGE_UNICODE,
    MEDIUM_ASCII,
    PLAIN,
    SPACED,
    brand_text,
    brand_variant,
    compact_brand,
)
from kryonsec.ui.theme import workspace_tokens


def _ascii_only(value: str) -> bool:
    return all(ord(char) < 128 for char in value)


# ---- variant selection ---------------------------------------------------


def test_large_art_is_rectangular():
    assert {len(line) for line in LARGE_UNICODE} == {71}
    assert all(line.strip() for line in LARGE_UNICODE)


def test_medium_art_fits_its_own_width():
    widest = max(len(line) for line in MEDIUM_ASCII)
    assert widest <= 54
    assert all(line.strip() for line in MEDIUM_ASCII)


def test_wide_terminal_gets_block_art():
    assert brand_variant(120).lines == LARGE_UNICODE
    assert brand_variant(73).lines == LARGE_UNICODE


def test_medium_terminal_steps_down_to_ascii_font():
    assert brand_variant(70).lines == MEDIUM_ASCII
    assert brand_variant(54).lines == MEDIUM_ASCII


def test_narrow_terminal_gets_spaced_mark():
    assert brand_variant(40).lines == (SPACED,)
    assert brand_variant(17).lines == (SPACED,)


def test_very_narrow_terminal_gets_plain_mark():
    assert brand_variant(16).lines == (PLAIN,)
    assert brand_variant(8).lines == (PLAIN,)


def test_too_narrow_terminal_renders_nothing_rather_than_clipping():
    assert brand_variant(7).lines == ("",)
    assert brand_variant(1).lines == ("",)


def test_every_variant_fits_the_requested_width():
    for width in range(1, 140):
        variant = brand_variant(width)
        assert all(len(line) <= width for line in variant.lines)


def test_non_unicode_terminal_never_receives_box_drawing():
    for width in range(1, 140):
        variant = brand_variant(width, unicode_ok=False)
        assert all(_ascii_only(line) for line in variant.lines)
    assert brand_variant(120, unicode_ok=False).lines == MEDIUM_ASCII


# ---- compact one-line mark ----------------------------------------------


def test_compact_mark_includes_credit_when_there_is_room():
    assert compact_brand(40) == f"{PLAIN}  ·  {CREDIT}"


def test_compact_mark_drops_credit_before_the_wordmark():
    assert compact_brand(12) == PLAIN
    assert compact_brand(7) == ""


# ---- Rich rendering ------------------------------------------------------


def test_mode_a_wordmark_is_white_and_has_credit_underneath():
    tokens = workspace_tokens("copilot", truecolor=True)
    text = brand_text(tokens, width=120)
    styles = {str(span.style) for span in text.spans}
    assert f"bold {tokens.brand}" in styles
    assert tokens.brand == "#ffffff"
    plain = text.plain
    assert plain.splitlines()[-2] == CREDIT
    assert plain.index(CREDIT) > plain.index(LARGE_UNICODE[0])


def test_mode_b_wordmark_is_purple_and_same_art():
    tokens = workspace_tokens("purple", truecolor=True)
    text = brand_text(tokens, width=120)
    styles = {str(span.style) for span in text.spans}
    assert f"bold {tokens.brand}" in styles
    assert tokens.brand == "#a855f7"
    assert LARGE_UNICODE[0] in text.plain


def test_compact_rendering_keeps_brand_and_credit():
    tokens = workspace_tokens("purple", truecolor=True)
    text = brand_text(tokens, width=80, compact=True)
    assert text.plain == f"{PLAIN}  ·  {CREDIT}"
    assert str(text.spans[0].style) == f"bold {tokens.brand}"
    assert any("dim" in str(span.style) for span in text.spans[1:])


def test_full_rendering_has_no_line_wider_than_the_terminal():
    tokens = workspace_tokens("copilot", truecolor=True)
    for width in (73, 60, 40, 20, 8):
        for line in brand_text(tokens, width=width).plain.splitlines():
            assert len(line) <= width


# ---- CLI banner ----------------------------------------------------------


def test_cli_banner_uses_the_shared_block_art():
    assert BANNER == "\n".join(LARGE_UNICODE)
    assert "██╗" in BANNER
    assert "███████╗" in BANNER
    assert all(_ascii_only(line) for line in BANNER_ASCII.splitlines())


def test_cli_banner_keeps_mode_colors_and_credit():
    white = banner_styled("copilot", width=120)
    purple = banner_styled("purple", width=120)
    assert "[bold white]" in white
    assert "[bold magenta]" in purple
    assert CREDIT in white
    assert CREDIT in purple


def test_cli_banner_shrinks_on_narrow_consoles():
    narrow = banner_styled("copilot", width=50)
    assert "K R Y O N S E C" in narrow
    tiny = banner_styled("copilot", width=10)
    assert "KRYONSEC" in tiny
    assert "██╗" not in tiny
