# Session notes — 2026-09-05 (updated after waitlist build)

## n8n waitlist automation — COMPLETE (all 3 workflows published)

- **WF1 "Kryon Waitlist - Intake"** (OoiXSZled6h4Rw6n, published):
  POST https://n8n.kryonsec.in/webhook/kryon/waitlist
  Webhook → Normalize → Find Existing Email (Data Table query, alwaysOutputData)
  → Process Application (validate/dedupe/build record+links) → Should Insert?
  → Insert Application → Discord #waitlist + JSON response.
- **WF2 "Kryon Waitlist - Approval & Welcome"** (NAWSLcQzklMcwZxu, published):
  GET .../webhook/kryon/waitlist-decision?app=<id>&token=<token>&decision=approve|reject
  → Get Application → Apply Decision (token check + state machine) → email branch
  (onError continueErrorOutput) → Finalize Store → Update Application → respond + Discord.
- **WF3 "Kryon Waitlist - Error Handler"** (xhsYAmE9gUZLd58O, published) — set as
  errorWorkflow on WF1+WF2. Sanitizes paths/stacks, alerts Discord #waitlist.
- **Storage: Data Table "kryon-waitlist"** (id R5YXMAyYTTSCVaci, personal project
  z3GDoqO6bYxAJJWB). The instance blocks ALL workflow file access
  (N8N_RESTRICT_FILE_ACCESS_TO), so the original JSON-file design was replaced.
  Columns: application_id, name, email, phone, role, why_use_product, status,
  email_sent, submitted_at, decided_at, email_sent_at, email_error, approve_token.
- All 8 test cases passed via test_workflow (executions 4–21). Test rows deleted;
  temp cleanup workflow 4afrIvsGF9ICutWG archived.
- Credentials reused only: "SMTP account" (MFIeXwSHyGG2Zu7b),
  "Discord Bot account" (YnRVjNjdRLtUfzJY). No new credentials, no secrets in chat.
- Existing workflows "Wait List" (2gDoQwDYXfsOgLi7) and
  "Feedback (Kryonsec)" (6IIYbMHLAI0w5LJO) untouched.

## RESOLVED — the "403 Basic Auth on /webhook" was never Basic auth

- **Diagnosis (corrected):** there is NO Basic-auth proxy layer. The 403
  "Authorization data is wrong!" only hits bot-like user agents (curl's default
  UA). Real browsers — any origin, including http://localhost:8765 — reach n8n
  and the workflow executes. Verified by A/B test on the decision webhook:
  curl UA → 403, browser UA → 200 + execution.
- The 403 is n8n's **Ignore Bots** option on the webhook nodes (intentional —
  it stops Discord's link-preview bot from auto-clicking approve/reject links).
  Nothing was changed on the Ubuntu server. The n8n editor login is untouched.
- **Real production bug found and fixed:** every live intake execution died at
  "Notify Review Channel" with "The parameter Color is not properly formatted".
  The embed color `5763719` was read as HEX by the Discord node (= ~91 million,
  over Discord's max 16777215). Fixed to `57F3A7` (the green intended).
  Published as activeVersionId 091c2577-c445-4b08-8178-82374c59ac36.
  This bug was invisible in testing because the Discord node was PINNED
  (simulated) during test_workflow runs — pinned credential nodes hide real
  API failures. Lesson: unpin and run one live check before launch.

## Launch end-to-end test — PASSED (2026-09-05 ~17:43 UTC)

1. Browser-style form POST → https://n8n.kryonsec.in/webhook/kryon/waitlist
   → JSON success response, application_id app-mtoo8r3g-b3d8c4, execution 30 = success.
2. Data Table row created: status "pending", email_sent "no".
3. Discord #waitlist notification sent (embed, green color) — first real one ever.
4. GET decision link with approve + correct token → "Approved - the welcome
   email was sent to joshnavardhan97@gmail.com." (execution 31 = success).
5. Row updated: status "approved", email_sent "yes", decided_at + email_sent_at set.
6. Welcome email delivered to joshnavardhan97@gmail.com ("You are in - Kryonsec
   early access") — check the Gmail inbox.
7. All 4 test rows deleted (table now empty). Temp cleanup workflow
   9ixqQWqSi57fLvIz created, run once, archived.

Also: the "Feedback (Kryonsec)" workflow is **inactive** — its production URL
(.../webhook/59875b67-...) won't respond until it is activated.

## Feedback automation — COMPLETE (2026-09-05 ~18:16 UTC)

- Reused the existing **Feedback (Kryonsec)** workflow `6IIYbMHLAI0w5LJO`
  (was an empty 1-node stub). Now 12 nodes, PUBLISHED
  (activeVersionId 7a95f32a-b191-4320-aa77-d3f60d53ab85).
- Flow: POST **/webhook/kryon/feedback** (ignoreBots, responseNode) →
  Normalize (website fields full_name/phone_number/email/comments/feature_request
  + JSON fallbacks) → Validate Feedback (Code: required name/email/feedback,
  email regex, trim, lowercase, server-side feedback_id + submitted_at,
  ignores client IDs/timestamps) → Insert into Data Table **kryon-feedback**
  (`URwvRW0j1kDVErnC`) → Send Thank-You Email (SMTP credential MFIeXwSHyGG2Zu7b,
  subject "Thank you for your feedback — Kryon", body editable in node) →
  Update Email Status (email_sent yes / no + email_error) → Respond Success.
  Invalid → 400 JSON, nothing saved. Insert failure → 500, no email sent.
  Email failure → row kept, email_sent=no + email_error, still 200.
- Bug found & fixed during live test: the first "Is Valid?" IF used string
  equality against a boolean $json.valid — strict type validation threw before
  any respond node (empty 200s). Fixed to boolean `true` operator.
- All 5 live tests passed (valid → row + email + 200; bad email → 400 no row;
  missing feedback → 400 no row; row fields verified; email actually sent —
  `email_sent:"yes"` only set after real SMTP success, check Gmail).
- feedback.html form action updated to https://n8n.kryonsec.in/webhook/kryon/feedback.
- Test row deleted; temp cleanup workflow CawrMSzhB9aatPIL archived.
- Waitlist workflows untouched. No CORS changes needed (form-encoded POST to
  an iframe target = no cross-origin JS fetch).

## Landing page (C:\Users\gonch\Desktop\kryonsec-landing)

- feedback.html redesign SAVED (mockup sections, same style.css/fonts,
  "N8N WORKFLOW" label removed → "READ BY A HUMAN").
- Both form actions updated from dead trycloudflare tunnels to:
  - index.html waitlist → https://n8n.kryonsec.in/webhook/kryon/waitlist
  - feedback.html → https://n8n.kryonsec.in/webhook/59875b67-3790-41c8-b76b-73c6753d4019
- Form field names are compatible with the intake webhook fallbacks.
- NOTE: 2 bounce emails (for test.three@…invalid and test@nonexistent) may land
  in the joshnavardhan97@gmail.com inbox from testing — safe to delete.
- Version label still says v1.0.1; CLI is v1.1.0.
