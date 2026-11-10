# Kryonsec terminal UI architecture

## Boundary

Kryonsec keeps the security engine and the terminal renderer separate:

- **Business logic:** `copilot/`, `purple/runner.py`, `purple/orchestrator.py`,
  approvals, allowlists, audit, evidence, storage, and the existing wizard
  operations.
- **Observable events:** agent callbacks, orchestrator state callbacks, audit
  observers, and concise log notices. UI adapters only observe these streams.
- **Interaction:** `cli.py`, the controller in `ui/workspace.py`, and the two
  explicit approval gates. An approval is still denied unless the operator
  explicitly approves it.
- **Rendering:** the Textual app in `ui/app.py` and shared components in
  `ui/components.py`. A rendering error cannot change a result or an audit
  transition.
- **UI preferences:** `~/.kryonsec/ui.json`. It stores only theme name and
  light/dark/system mode; it never changes `config.toml` or security settings.
  The full-screen workspace palette is derived from the active mode instead:
  these preferences cannot reintroduce accent colours there.

## Framework choice

The interactive surface is a single **Textual** application. It owns the
terminal while it runs, so conversation updates are painted inside one screen
instead of being appended to the scrollback. Textual also provides the layout
system, focus handling, mouse support, resize breakpoints, and headless test
driver used by the UI tests.

Rich renders the text inside the app, and prompt_toolkit remains the dialog
layer for the first-run setup wizard and the non-TUI input fallback. This keeps
the existing wizard, history, pipe fallback, and synchronous backend contracts
intact. The choice is presentation-only: the orchestrator, state machine,
allowlists, sandbox, audit chain, and approval policy are unchanged.

## Screen layout

- **Top bar:** the Kryonsec mark, real stored session or engagement tabs, the
  selected-tab highlight, `+ New session` / `+ New engagement`, and the active
  mode.
- **Centre:** the large Kryonsec brand when a session is empty; a scrolling
  conversation with Markdown and inline tool activity once it has messages. In
  Mode B the centre is a live operations view: the target/stage/agent header
  with the sandbox status from the engagement's own `sandbox_check` audit
  event, the 10-state workflow timeline with per-stage durations, a
  timestamped **Live Activity** stream (one row per realistic observation:
  stage started/completed, tool launched/finished, approvals, notices), a
  **Current Operation** block showing the active agent, its task, the current
  tool and its real argv (redacted, never constructed by the UI), and the
  findings/evidence counts from the graph store.
- **Right sidebar:** always visible on wide terminals. Mode A shows the real
  session identity, context usage, provider/model, MCP connection status,
  Docker status, workspace, and tool activity. Mode B is organised into
  runtime-fed sections: **Engagement** (target, id, state, elapsed, stage,
  active agent), **Runtime** (Docker and sandbox from real checks — the same
  `docker_server_ok()`/`sandbox_available()` probes the gates use, collected
  on a background thread and shown as `unknown` until they have actually
  run — memory viewer, MCP subsystem, workspace), **Agents** (the eight
  executable security agents with `idle`/`running`/`completed`/`failed`, the
  running agent's operation, the finished agent's last tool outcome),
  **Tool · Command** (active tool, status, duration, and its argv), and
  **Connections** (each configured MCP server with its real connection
  state), plus the budget and findings blocks, and a focusable
  **Kryonsec Memory** entry that opens the existing read-only loopback
  memory browser after explicit activation (Enter or click) — never on
  startup or on a mode switch. The sidebar collapses below 100 columns.
- **Bottom:** a multiline composer, a live mode/agent/stage/cwd/elapsed/status
  line (no static tagline), and discoverable shortcuts. Approvals and the
  command palette are modal screens.

## Keyboard contract

- `Enter`: send. `Shift+Enter`: insert a newline.
- `Shift+Tab`: switch Copilot/Purple only when the existing sandbox and
  licensing checks allow it.
- `Ctrl+P`: open the command palette.
- `Ctrl+N`: create a real new session or engagement.
- `Ctrl+R`: rename the active Copilot session — a prepopulated modal dialog;
  empty names are refused, `Esc` cancels. Mode B engagement tabs keep their
  immutable identifiers and cannot be renamed.
- `Ctrl+W`: close the active tab. Closing never deletes stored session
  history and never acts as an approval or a cancellation: while an
  operation or a pending approval is active, closing is refused. When the
  last tab closes, the workspace returns to a clean new-session state.
- `Ctrl+Left` / `Ctrl+Right`: move between stored tabs.
- `Ctrl+Q`: leave. `Ctrl+C`: stop the active operation at a safe boundary, or
  leave when nothing is running.
- `Esc` / `Enter` in an approval dialog: deny. Approval requires an explicit
  `A` or the Approve button.

## Failure behaviour

`ui/runtime.py` checks TTY, UTF-8, `TERM`, and Textual availability before the
app starts. If any check fails, `cli.py` keeps the readable Rich fallback. A
controller or paint error is shown as status, never as a workflow decision.
Closing the app denies any approval still waiting and saves every non-empty
session.

## Colors

The workspace palette is mode-driven and monochrome-first. Mode A (Copilot)
uses only black/white/gray — states are carried by text marks (✓ ○ ! …), never
by colour alone. Mode B is the same monochrome design with purple (`#a855f7`)
reserved exclusively for the KRYONSEC wordmark; tabs, buttons, selections,
progress, and agent statuses stay monochrome. Every semantic "accent" token
maps to a gray in this design, and a companion Textual `Theme` keeps default
widget chrome (scrollbars, input selection, buttons) monochrome too. `/theme`
remains available, but the saved preference now applies only to other Kryonsec
surfaces.

## Screenshots

`docs/screenshots/` contains headless captures of the real app (Mode A empty,
conversation, command palette, approval gate, Mode B engagement, compact
terminal) plus a short tour GIF, and the refinement-pass captures
`mode-a-monochrome.png`, `mode-b-purple-branding.png`, `session-rename.png`,
`session-management.png`, and `mode-b-memory-sidebar.png`. They are generated
from synthetic state and do not show a live target.
