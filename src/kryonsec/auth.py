"""`kryonsec login` — sign this machine in to a beta account.

The credential a beta account gets is a *session token*, not a membership key.
It is obtained by a browser step and it can be taken away again, which a key
posted in an email cannot. That is the whole reason this exists next to the
key model rather than replacing it: `kryonsec connect` registers a machine
that already holds a key, and `kryonsec login` is for accounts that never had
one.

The browser step is the device-authorization grant (RFC 8628), the same shape
`connect` uses:

  1. the CLI asks kryonsec.in for a code, prints the link, and waits
  2. the person opens the link, signs in with Google or GitHub, and approves
  3. the CLI picks up a token on its own — it is never typed, pasted, or seen

That *is* the manual fallback for a headless or restricted machine. There is
no second protocol for them: step 1 prints the URL and the code, so a person on
a box with no browser opens it on their phone and types eight characters. The
brief's rules against improvising a password prompt are honoured by not having
one — nothing here ever asks for a Google or GitHub password, a provider
token, a website cookie, or a membership key.

What is stored, and what is not:

    ~/.kryonsec/auth.json   0600, one line of JSON, the token and an email

No password, no client secret, no provider subject, no session cookie. The
token is never printed to the terminal and never accepted as an argument, so
it cannot land in shell history or in a process list.

Nothing here reads or writes `config.toml`. Signing in must not disturb the
LLM settings, the engagement history, or the sandbox configuration — a login
that reformatted somebody's config would be a worse bug than no login at all.
The one thing it does write elsewhere is the member email in the license state
file, which is what `kryonsec doctor` and the Purple Team gate already read.
"""

from __future__ import annotations

import json
import os
import platform
import re
import stat
import time
from pathlib import Path
from typing import Any

from rich.console import Console

from . import __version__
from . import license as lic

console = Console()

AUTH_FILENAME = "auth.json"

# Overridable so a preview deployment can be tested without editing source,
# matching how license.py handles its URLs.
LOGIN_START_URL = os.environ.get(
    "KRYONSEC_LOGIN_START_URL", "https://kryonsec.in/api/beta/device/start")
LOGIN_POLL_URL = os.environ.get(
    "KRYONSEC_LOGIN_POLL_URL", "https://kryonsec.in/api/beta/device/poll")
LOGOUT_URL = os.environ.get(
    "KRYONSEC_LOGOUT_URL", "https://kryonsec.in/api/beta/cli/logout")

POLL_INTERVAL_S = 2
POLL_TIMEOUT_S = 180

# `s_` + 64 hex, minted by createCliSession. Anything else is not a token, and
# saying so is better than sending it and reading the server's refusal.
TOKEN_PATTERN = re.compile(r"^s_[0-9a-f]{64}$")


def auth_path(cfg: Any) -> Path:
    return Path(cfg.home) / AUTH_FILENAME


# ---- the credential ---------------------------------------------------------

def load(cfg: Any) -> dict:
    """The stored credential, or {}. Missing, corrupt, or malformed -> {}.

    Shape-checked rather than merely parsed: a half-written file, or one from
    a future version, must read as "not signed in" so the person runs `login`
    again. The alternative is a token that looks present and fails at the
    server with a message about nothing in particular.

    It also never raises, and that matters more than it looks: `license.verify`
    asks this question on every launch, and verify's whole contract is that it
    does not raise. A home directory that is missing, unreadable, or not
    configured at all has to read as "no token" rather than take the check
    down — hence TypeError alongside the obvious two, which is what
    `Path(None)` throws.
    """
    try:
        path = auth_path(cfg)
        if not path.is_file():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError, TypeError):
        return {}
    if not isinstance(data, dict) or not TOKEN_PATTERN.match(str(data.get("token") or "")):
        return {}
    return data


def save(cfg: Any, data: dict) -> bool:
    """Write the credential file 0600. False if it could not be written.

    A failure here is reported rather than swallowed: the caller has a live
    token in hand and no way to keep it, which is a thing to say out loud
    instead of leaving the person believing they are signed in.
    """
    path = auth_path(cfg)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Create the file with the mode rather than chmod-ing afterwards: a
        # window where a credential sits world-readable is a window, however
        # short. O_EXCL is not used so a re-login simply overwrites.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
    except OSError:
        return False
    _tighten(path)
    return True


def _tighten(path: Path) -> None:
    """Best effort. On Windows the mode bits do not map, and the file is
    already protected by the profile directory's ACLs — so a failure here is
    not worth refusing a successful login over."""
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def token(cfg: Any) -> str:
    """The stored session token, or "" if this machine is not signed in."""
    return str(load(cfg).get("token") or "")


def email(cfg: Any) -> str:
    return str(load(cfg).get("email") or "")


def forget(cfg: Any) -> None:
    """Delete the local credential. Idempotent."""
    try:
        auth_path(cfg).unlink()
    except OSError:
        pass


# ---- the flow ---------------------------------------------------------------

def _machine_payload(cfg: Any) -> dict:
    """What the CLI tells the server about this machine, and nothing more.

    The same short list `connect` sends: an id this install invented, the OS,
    the architecture, the version. No hostname, no username, no paths, nothing
    about an engagement.
    """
    return {
        "device_id": lic.device_id(cfg),
        "os": platform.system(),
        "arch": platform.machine(),
        "version": __version__,
    }


def login(cfg: Any, *, open_browser: bool = True) -> int:
    """Run the browser step and store the token. Returns a process exit code."""
    # A machine holding a membership key is already authorised by it, and the
    # key is what the verify endpoint checks first — so a token obtained here
    # would be stored and then never consulted. Refusing is the honest answer;
    # silently accepting would look like it worked and change nothing.
    if (getattr(cfg, "license_key", None) or "").strip():
        console.print(
            "[yellow]This machine is already signed in with a membership "
            "key[/yellow], which takes precedence over a beta account. "
            "To use a beta account here instead, remove the key first "
            "(run [bold]kryonsec setup[/bold])."
        )
        return 1

    started = lic.http_post_json(LOGIN_START_URL, _machine_payload(cfg))
    if started is None:
        console.print(
            "[red]Could not reach kryonsec.in.[/red] Signing in needs the "
            "network once. Check your connection and try again."
        )
        return 1

    error = str(started.get("error") or "")
    if error:
        console.print(f"[red]{error}[/red]")
        return 1

    url = str(started.get("url") or "")
    code = str(started.get("code") or "")
    device_code = str(started.get("device_code") or "")
    if not (url and code and device_code):
        console.print("[red]kryonsec.in gave an unexpected answer.[/red]")
        return 1

    console.print("\nOpen this link to sign this machine in:\n")
    console.print(f"  [bold cyan]{url}[/bold cyan]\n")
    console.print(f"It should show code [bold]{code}[/bold].\n")
    console.print(
        "[dim]No browser here? Open the link on any other device you are "
        "signed in on — a phone will do. The code in the link is what ties "
        "that page to this terminal.[/dim]\n"
    )

    if open_browser:
        import webbrowser

        # Quietly returns False on a headless box. The link is printed either
        # way, so there is always a way through.
        if webbrowser.open(url):
            console.print("[dim]opened in your browser[/dim]")
        else:
            console.print("[dim]no browser available — open the link above[/dim]")

    console.print("[dim]waiting for you to approve it in the browser…[/dim]")

    deadline = time.monotonic() + POLL_TIMEOUT_S
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL_S)
        answer = lic.http_post_json(LOGIN_POLL_URL, {"device_code": device_code})
        if answer is None:
            continue  # a dropped poll is not a verdict; the deadline is

        status = str(answer.get("status") or "")
        if status == "pending":
            continue
        if status == "approved":
            return _keep(cfg, answer)
        if status == "denied":
            # "denied" means two different things on the wire. Usually the
            # person clicked no. Sometimes the entitlement behind the approval
            # went away in the minutes since, and the route sends a reason for
            # that case — telling someone they declined when their access was
            # withdrawn sends them to look in the wrong place.
            why = str(answer.get("reason") or "").strip()
            console.print(
                f"\n[yellow]That sign-in was denied — {why}[/yellow] "
                "Nothing was stored on this machine."
                if why
                else "\n[yellow]That sign-in was denied in the browser.[/yellow] "
                "Nothing was stored on this machine."
            )
            return 1
        if status in ("expired", "unknown"):
            console.print(
                f"\n[yellow]That sign-in code was {status}.[/yellow] "
                "Nothing was changed — run `kryonsec login` again."
            )
            return 1
        # Any other status is not something to guess at: keep waiting.

    console.print(
        "\n[yellow]Timed out waiting for the browser.[/yellow] "
        "Nothing was changed — run `kryonsec login` again."
    )
    return 1


def _keep(cfg: Any, answer: dict) -> int:
    """Store a collected token, and say so without ever printing it."""
    raw = str(answer.get("token") or "")
    if not TOKEN_PATTERN.match(raw):
        console.print("[red]kryonsec.in gave an unexpected answer.[/red]")
        return 1

    email = str(answer.get("email") or "")
    prefix = str(answer.get("prefix") or raw[:10] + "…")
    if not save(cfg, {"token": raw, "email": email}):
        console.print(
            f"[red]Could not write {auth_path(cfg)}.[/red] This machine is "
            "signed in on the server but cannot remember it, so nothing was "
            "kept. Check that the directory is writable and run "
            "`kryonsec login` again."
        )
        return 1

    # The email is what `kryonsec doctor` shows under Membership and what the
    # Purple Team gate reads to know this machine is registered. Written into
    # the license state file, which connect already owns, rather than a
    # parallel notion of "registered" that could disagree with it.
    state = lic.load_state(cfg)
    state["member_email"] = email
    lic.save_state(cfg, state)

    console.print(f"\n[green]Signed in.[/green] This machine is {email or 'registered'}.")
    console.print(
        f"[dim]Token {prefix} — 90 days, revocable from your dashboard. "
        "`kryonsec auth status` shows it; `kryonsec logout` ends it.[/dim]"
    )
    return 0


def logout(cfg: Any) -> int:
    """Revoke this machine's token, then delete it locally.

    The order matters: revoking on the server is what makes a stolen copy of
    the file worthless, so a local-only delete would be a sign-out in name
    only. If the server cannot be reached the local file still goes — leaving
    it would mean "logout" silently did nothing — and the person is told
    plainly which half happened.
    """
    raw = token(cfg)
    if not raw:
        console.print("[dim]This machine is not signed in.[/dim]")
        return 0

    answer = lic.http_post_json(LOGOUT_URL, {}, token=raw)
    forget(cfg)

    # Clear the registered email too, but only the one field: `load_state`
    # round-trips the rest, so the daily cache and the device id survive.
    state = lic.load_state(cfg)
    if state.pop("member_email", None) is not None:
        lic.save_state(cfg, state)

    if answer is None:
        console.print(
            "[yellow]Signed out on this machine, but kryonsec.in could not be "
            "reached to revoke the token.[/yellow] It will keep working until "
            "it expires unless you revoke it from your dashboard."
        )
        return 0

    console.print("[green]Signed out.[/green] The token has been revoked.")
    return 0


def status(cfg: Any) -> int:
    """`kryonsec auth status` — what this machine holds and whether it works."""
    stored = load(cfg)
    key = (getattr(cfg, "license_key", None) or "").strip()

    if not stored and not key:
        console.print(
            "[yellow]Not signed in.[/yellow] Copilot mode works without an "
            "account; run [bold]kryonsec login[/bold] for beta access and "
            "Purple Team."
        )
        return 1

    if key:
        console.print(f"Membership key: …{key[-4:]} (from config.toml)")
    if stored:
        raw = str(stored.get("token") or "")
        console.print(f"Account: {stored.get('email') or '—'}")
        console.print(f"Token:   {raw[:10]}…")
    if not stored:
        console.print("[dim]No beta account on this machine.[/dim]")

    # The same check the Purple Team gate makes, so this command cannot say
    # "signed in" about a token the gate would refuse.
    result = lic.verify(cfg)
    tone = "green" if result.purple_allowed else "yellow"
    line = {
        lic.VALID: "Active.",
        lic.GRACE: f"Offline — {result.message}.",
    }.get(result.status, result.message or result.status)
    console.print(f"[{tone}]Access: {line}[/{tone}]")
    if result.expires:
        console.print(f"[dim]Expires: {result.expires}[/dim]")
    return 0 if result.purple_allowed else 1
