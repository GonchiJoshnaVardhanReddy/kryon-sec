"""`kryonsec connect` — register this machine to a membership.

The one-time browser step. The CLI asks kryonsec.in for a short code, prints
the link, and waits; the member opens it, types their email, and the CLI
picks up the answer on its own. No password is ever typed into a terminal,
and the membership key never leaves the machine as part of this flow — it is
what the CLI already holds, and it is what authorises asking for a code.

Why a code at all, rather than just asking who you are: the code is what ties
*this* terminal to *that* browser tab, so the answer cannot be collected by
somebody who only saw the URL. The code is displayed; the secret the CLI
polls with (`device_code`) is not. Both expire in fifteen minutes.

The result is written to the license state file, so the admin view can say
which member is on which machine. It is not a credential: nothing here
authorises anything, and losing it costs a re-connect and nothing else.
"""

from __future__ import annotations

import platform
import time
from typing import Any

from rich.console import Console

from . import __version__
from . import license as lic

console = Console()

POLL_INTERVAL_S = 2
POLL_TIMEOUT_S = 180


def _start_payload(cfg: Any) -> dict:
    """What we tell the server about this machine — and nothing more.

    An id this install invented, the OS, the architecture, the app version.
    No hostname, no username, no paths, no target, and nothing about an
    engagement: this is a "which machine is this" question, not telemetry.
    """
    return {
        "key": (getattr(cfg, "license_key", None) or "").strip(),
        "device_id": lic.device_id(cfg),
        "os": platform.system(),
        "arch": platform.machine(),
        "version": __version__,
    }


def connect(cfg: Any, *, open_browser: bool = True) -> int:
    """Run the connect flow. Returns a process exit code."""
    payload = _start_payload(cfg)
    if not payload["key"]:
        console.print(
            "[red]No membership key configured.[/red] Set one first — "
            "run [bold]kryonsec setup[/bold], or set KRYONSEC_LICENSE_KEY."
        )
        return 1

    lic.clear_http_error()
    started = lic.http_post_json(lic.CONNECT_START_URL, payload)
    if started is None:
        failure = lic.last_http_error()
        if failure:
            console.print(
                f"[red]Could not complete connection: {failure.message}.[/red] "
                "Connecting needs the network once. Check your connection "
                "and try again."
            )
        else:
            console.print(
                "[red]Could not reach kryonsec.in.[/red] Connecting needs the "
                "network once. Check your connection and try again."
            )
        return 1

    error = str(started.get("error") or "")
    if error:
        # The key is a credential: name its tail, never the whole thing.
        console.print(f"[red]{error}[/red] (key …{payload['key'][-4:]})")
        if error == "key not recognised":
            console.print(
                "[yellow]That key is not on the membership list.[/yellow] "
                "Check it against your membership email."
            )
        return 1

    url = str(started.get("url") or "")
    code = str(started.get("code") or "")
    device_code = str(started.get("device_code") or "")
    if not (url and device_code):
        console.print("[red]kryonsec.in gave an unexpected answer.[/red]")
        return 1

    console.print("\nOpen this link to connect this machine:\n")
    console.print(f"  [bold cyan]{url}[/bold cyan]\n")
    console.print(f"It should show code [bold]{code}[/bold].\n")

    if open_browser:
        import webbrowser

        # On a headless box this quietly returns False; the link above is
        # already printed, so there is always a way through.
        if webbrowser.open(url):
            console.print("[dim]opened in your browser[/dim]")
        else:
            console.print("[dim]no browser available — open the link above[/dim]")

    console.print("[dim]waiting for you to finish in the browser…[/dim]")

    deadline = time.monotonic() + POLL_TIMEOUT_S
    last_failure = None
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL_S)
        lic.clear_http_error()
        answer = lic.http_post_json(lic.CONNECT_POLL_URL, {"device_code": device_code})
        if answer is None:
            last_failure = lic.last_http_error() or last_failure
            continue  # a dropped poll is not a verdict; the deadline is

        status = str(answer.get("status") or "")
        if status == "pending":
            continue
        if status == "connected":
            email = str(answer.get("email") or "")
            state = lic.load_state(cfg)
            state["member_email"] = email
            lic.save_state(cfg, state)
            console.print(
                f"\n[green]Connected.[/green] This machine is registered to "
                f"{email}."
            )
            console.print(
                "[dim]Purple Team will start now. "
                "`kryonsec doctor` shows this under Membership.[/dim]"
            )
            return 0
        if status in ("expired", "unknown"):
            console.print(
                f"\n[yellow]That connect code was {status}.[/yellow] "
                "Nothing was changed — run `kryonsec connect` again."
            )
            return 1
        # Any other status is not something to guess at: keep waiting.

    detail = (
        f" Last request failed: {last_failure.message}."
        if last_failure else ""
    )
    console.print(
        "\n[yellow]Timed out waiting for the browser.[/yellow]"
        f"{detail} Nothing was changed — run `kryonsec connect` again."
    )
    return 1
