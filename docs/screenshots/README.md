# Kryonsec workspace screenshots

These images were captured from the real Textual app with its headless test
driver and synthetic state. No live target, LLM, MCP server, Docker container,
or Purple Team tool was used.

The first five images show the current mode-driven palette (Mode A fully
monochrome; Mode B monochrome with the purple KRYONSEC wordmark only); the
numbered scenes below predate that refinement pass and are kept for layout
reference.

| Screenshot | What it shows |
|---|---|
| [Mode A — monochrome](mode-a-monochrome.png) | Current Mode A design: pure black/white/gray, white wordmark, monochrome sidebar and composer |
| [Mode B — purple branding](mode-b-purple-branding.png) | Current Mode B design: monochrome everywhere except the purple KRYONSEC wordmark |
| [Session rename](session-rename.png) | Prepopulated rename dialog over the workspace |
| [Session management](session-management.png) | Command palette with Rename session / Close session entries |
| [Mode B — memory sidebar](mode-b-memory-sidebar.png) | Mode B sidebar with the focusable Kryonsec Memory entry |
| [Mode A — empty](01-mode-a-empty.png) | Centred brand, real session tabs, always-visible context sidebar, bottom composer *(captured before the monochrome palette refinement)* |
| [Mode A — conversation](02-mode-a-conversation.png) | Markdown answer, code block, inline tool activity, session tabs, runtime sidebar |
| [Command palette](03-command-palette.png) | `Ctrl+P` command palette over the workspace |
| [Approval gate](04-approval-gate.png) | Fail-closed post-exploitation approval; deny remains the default |
| [Mode B — engagement](05-mode-b-engagement.png) | Target, 10-state timeline, live tools, findings, and the eight-agent sidebar *(captured before the monochrome palette refinement)* |
| [Compact terminal](06-compact-terminal.png) | Sidebar collapsed below the 100-column breakpoint; bottom status stays inside the screen |
| [Tour GIF](kryonsec-workspace-tour.gif) | Short sequence through the screens above *(captured before the monochrome palette refinement)* |

SVG versions sit next to each PNG. They are exported directly by Textual and
are useful for diffing layout changes. The PNG/SVG images substitute an
installed monospace font for Fira Code, which may not exist on a headless CI
host.
