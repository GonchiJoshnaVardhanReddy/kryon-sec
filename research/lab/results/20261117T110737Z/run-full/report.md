# Security Test Report

**Engagement:** lab-p5-full-20261117T110737Z
**Target website:** juice-shop.lab
**Date:** 2026-11-17 11:23 UTC

## What we did



We collected public information about juice-shop.lab from third-party
sources (certificate records and web archives). We did **not** send any
traffic to the website during this step.

Based on that information, the assistant suggested
4 possible security issues.
You approved 4 of them
.


Tools were run against the target to test the approved items.
Here is what each test did:


- **H1:curl** (curl): ran and did **not** confirm
  the issue. A test that finds nothing is not proof that nothing is there.



- **H1:nuclei** (nuclei): ran and did **not** confirm
  the issue. A test that finds nothing is not proof that nothing is there.



- **H2:curl** (curl): ran and did **not** confirm
  the issue. A test that finds nothing is not proof that nothing is there.



- **H2:wget** (wget): ran and did **not** confirm
  the issue. A test that finds nothing is not proof that nothing is there.



- **H3:curl** (curl): ran and did **not** confirm
  the issue. A test that finds nothing is not proof that nothing is there.



- **H3:wget** (wget): ran and did **not** confirm
  the issue. A test that finds nothing is not proof that nothing is there.



- **H4:curl** (curl): ran and did **not** confirm
  the issue. A test that finds nothing is not proof that nothing is there.





## Timeline


| When (UTC) | What happened |
|---|---|
| 2026-11-17T11:08:25+00:00 | engagement_created — juice-shop.lab |
| 2026-11-17T11:08:26+00:00 | state_enter — RECON_PASSIVE |
| 2026-11-17T11:09:28+00:00 | state_enter — RECON_ACTIVE |
| 2026-11-17T11:12:59+00:00 | state_enter — HYPOTHESIZE |
| 2026-11-17T11:13:31+00:00 | state_enter — HUMAN_REVIEW |
| 2026-11-17T11:13:31+00:00 | state_enter — EXPLOIT |
| 2026-11-17T11:23:09+00:00 | state_enter — VERIFY |
| 2026-11-17T11:23:09+00:00 | state_enter — BLUE_TEAM |
| 2026-11-17T11:23:36+00:00 | state_enter — REPORT |



## How the testing was done (steps you can repeat)


A tester can check any item below by hand. Every test runs inside a
locked-down sandbox container, one test at a time, against the target
website only.


### Steps for H1:curl


1. The tool curl was run with these settings:
   `curl -sS --max-time 30 http://juice-shop.lab/metrics`
2. The tool sent test requests to the target website and watched how
   it answered.
3. Result: the tool ran and did not find the issue — it looked and got no
   proof.


To repeat it yourself: run the same command (shown in step 1) in a safe
test environment and compare what the tool answers. Only test websites
you are allowed to test.

### Steps for H1:nuclei


1. The tool nuclei was run with these settings:
   `nuclei -u http://juice-shop.lab/metrics -t /opt/nuclei-templates -rate-limit 50 -timeout 30`
2. The tool sent test requests to the target website and watched how
   it answered.
3. Result: the tool ran and did not find the issue — it looked and got no
   proof.


To repeat it yourself: run the same command (shown in step 1) in a safe
test environment and compare what the tool answers. Only test websites
you are allowed to test.

### Steps for H2:curl


1. The tool curl was run with these settings:
   `curl -sS --max-time 30 http://juice-shop.lab/ftp`
2. The tool sent test requests to the target website and watched how
   it answered.
3. Result: the tool ran and did not find the issue — it looked and got no
   proof.


To repeat it yourself: run the same command (shown in step 1) in a safe
test environment and compare what the tool answers. Only test websites
you are allowed to test.

### Steps for H2:wget


1. The tool wget was run with these settings:
   `wget -q -O - --timeout=30 http://juice-shop.lab/ftp`
2. The tool sent test requests to the target website and watched how
   it answered.
3. Result: the tool ran and did not find the issue — it looked and got no
   proof.


To repeat it yourself: run the same command (shown in step 1) in a safe
test environment and compare what the tool answers. Only test websites
you are allowed to test.

### Steps for H3:curl


1. The tool curl was run with these settings:
   `curl -sS --max-time 30 http://juice-shop.lab/main.js`
2. The tool sent test requests to the target website and watched how
   it answered.
3. Result: the tool ran and did not find the issue — it looked and got no
   proof.


To repeat it yourself: run the same command (shown in step 1) in a safe
test environment and compare what the tool answers. Only test websites
you are allowed to test.

### Steps for H3:wget


1. The tool wget was run with these settings:
   `wget -q -O - --timeout=30 http://juice-shop.lab/main.js`
2. The tool sent test requests to the target website and watched how
   it answered.
3. Result: the tool ran and did not find the issue — it looked and got no
   proof.


To repeat it yourself: run the same command (shown in step 1) in a safe
test environment and compare what the tool answers. Only test websites
you are allowed to test.

### Steps for H4:curl


1. The tool curl was run with these settings:
   `curl -sS --max-time 30 http://juice-shop.lab/`
2. The tool sent test requests to the target website and watched how
   it answered.
3. Result: the tool ran and did not find the issue — it looked and got no
   proof.


To repeat it yourself: run the same command (shown in step 1) in a safe
test environment and compare what the tool answers. Only test websites
you are allowed to test.



## What we found about the target

**Subdomains found:** 0

- none found


**Old pages found in the web archive:** 11
(a sample is listed; these are old URLs, not live pages)

- /ftp

- :80/

- :80/chunk-3CyVWL1v.js

- :80/chunk-CE5v8pBj.js

- :80/chunk-CajNVifV.js

- :80/main.js

- :80/polyfills.js

- :80/rolldown-runtime-kqx1xuJ_.js

- :80/scripts.js

- :80/styles.css

- Auto-filtering


## Possible security issues

These are **suggestions only** — the assistant looked at public
information and guessed what might be wrong. Nothing below is confirmed
.


### H1 — Potential unauthenticated disclosure through Prometheus metrics
- Where: /metrics (this engagement never recorded this asset)

- How sure the assistant is: 72%
- Your decision: approved
- Tested: yes


- Severity guess (CVSS vector): CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
  (calculated base score: 5.3 — medium)


- Why it thinks this: A detection-only candidate identifies prometheus-metrics at this path. The endpoint might expose operational information without authorization. No response content, access-control behavior, or sensitive metric labels are recorded, so neither accessibility nor meaningful information disclosure is established.
- How to check it: curl, nuclei


### H2 — Potential public directory listing or unintended file disclosure
- Where: /ftp

- How sure the assistant is: 55%
- Your decision: approved
- Tested: yes


- Severity guess (CVSS vector): CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
  (calculated base score: 5.3 — medium)


- Why it thinks this: The recorded /ftp path returned HTTP 200. Its name suggests a file-distribution surface that might expose a directory listing or files intended to remain private. No listing, file contents, or authorization requirements are recorded; the response could also be an application fallback. The impact estimate assumes limited unintended disclosure.
- How to check it: curl, wget


### H3 — Potential sensitive information embedded in a client-side bundle
- Where: /main.js (this engagement never recorded this asset)

- How sure the assistant is: 28%
- Your decision: approved
- Tested: yes


- Severity guess (CVSS vector): CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
  (calculated base score: 5.3 — medium)


- Why it thinks this: The crawl recorded /main.js alongside several JavaScript chunks, making client-delivered code an evidenced inspection surface. This bundle might contain nonpublic configuration or other information unintentionally shipped to clients. No bundle contents or exposed secrets are recorded, and ordinary public route names would not by themselves establish a vulnerability.
- How to check it: curl, wget


### H4 — Potential overly permissive cross-origin access
- Where: / (this engagement never recorded this asset)

- How sure the assistant is: 25%
- Your decision: approved
- Tested: yes


- Severity guess (CVSS vector): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N
  (calculated base score: 4.3 — medium)


- Why it thinks this: The fingerprint records an Access-Control-Allow-Origin header but omits its value and any credential-related headers. The root response might permit an untrusted origin to read information that should be restricted. Header presence alone is not a vulnerability: this hypothesis requires both permissive browser-enforced cross-origin behavior and sensitive response content, neither of which is recorded. The impact estimate is conditional on limited sensitive disclosure.
- How to check it: curl



## Code scanning results (blue team)


No code scanners ran (no --code folder was provided, or the sandbox was unavailable).


## How to fix them (blue team advice)


### Fix for H1 — Risk to verify: public Prometheus metrics exposure
- How serious: medium
- What to do: No disclosure was confirmed; the supplied testing summaries conflict. If /metrics is publicly reachable, remove its public application route or deny /metrics and /metrics/ at the public reverse proxy. Expose metrics only on an internal listener restricted to the Prometheus collector, with authentication enforced before serving metrics.
- How to spot attacks: At the public ingress, alert on requests whose normalized path is /metrics or begins /metrics/ from sources outside the approved monitoring network. Include method, path, status, source address, and authenticated identity. Treat a 200 response to an unauthenticated external request as a priority validation signal, not proof of sensitive disclosure.
- Weakness types (suggested, not verified): CWE-200; A05:2021-Security Misconfiguration——


### Fix for H2 — Risk to verify: directory listing or unintended files under /ftp
- How serious: medium
- What to do: No listing or file disclosure was confirmed. If /ftp is not a required public feature, remove its static-directory mount and deny /ftp and /ftp/ descendants at the public ingress. If downloads are required, replace directory serving with an explicit allowlist of public files; keep all other files outside the served directory and disable directory indexing. Disabling indexing alone does not prevent direct downloads.
- How to spot attacks: Alert on requests to /ftp or its descendants when this route is disabled. If public downloads remain enabled, alert on requests for paths outside the published allowlist, especially backup, configuration, dotfile, or archive names. Escalate successful responses for non-allowlisted paths and bursts of distinct filename probes.
- Weakness types (suggested, not verified): CWE-552; A05:2021-Security Misconfiguration——


### Fix for H3 — Risk to verify: sensitive content in the client bundle
- How serious: medium
- What to do: No sensitive bundle content was confirmed, and no source scan was supplied. Inspect the deployed /main.js and associated source maps. If credentials, private keys, or confidential configuration are present, remove them from frontend source and build-time substitutions, store them in backend-only configuration, and perform privileged operations through authenticated, authorized backend endpoints. Rebuild and redeploy the bundle, purge cached copies, and revoke or rotate any exposed credentials. Add a secret-scanning gate for generated frontend artifacts before deployment.
- How to spot attacks: Fail the frontend artifact gate on verified secret patterns in generated JavaScript or source maps, recording artifact names and redacted locations rather than secret values. Normal /main.js downloads cannot reliably distinguish exploitation from ordinary browsing; correlate suspected exposure with anomalous use of affected credentials in backend or provider audit logs.
- Weakness types (suggested, not verified): CWE-540———


### Fix for H4 — Risk to verify: overly permissive CORS
- How serious: medium
- What to do: No exploitable cross-origin access was confirmed. If the application requires only same-origin browser access, disable CORS middleware and remove Access-Control-Allow-* response headers. Otherwise, configure an exact allowlist of required origins including scheme, hostname, and port; do not reflect arbitrary Origin values or accept null. Emit Access-Control-Allow-Credentials: true only where credentialed cross-origin access is necessary, limit allowed methods and headers, and add Vary: Origin when responses vary by origin. Apply this policy to sensitive API routes as well as /.
- How to spot attacks: Log the request Origin and response Access-Control-Allow-Origin and Access-Control-Allow-Credentials headers on relevant routes. Alert when an origin outside the approved list is echoed as allowed, especially with credentials enabled. Also flag wildcard origin responses on endpoints designated as sensitive. An unapproved Origin request alone is a probe, not evidence that a browser could read the response.
- Weakness types (suggested, not verified): CWE-942; A05:2021-Security Misconfiguration——



## Post-exploitation status


No post-exploitation was performed: no shell/session capability was ever claimed (no tool in the inventory provides independently verifiable capability evidence). No post-exploitation happened in this engagement.


## Coverage of what was tested

This summary is built from the audit log and the evidence graph — not
from the assistant's statements. An item absent from a list here is
**unassessed**, never "checked and clean".


- Areas actually tested: / | /ftp | /main.js | /metrics

- Issue items the model proposed: 4 — tool runs really
  started for 7 of them.
- Confirmed by a test tool: 0
- Tested but not confirmed: 4 (H1, H2, H3, H4)
- Unresolved results (ran with no conclusion either way): 0
- Test steps that could not run: 0


## Limitations

Nothing below is a claim of completeness — these are the recorded gaps.

- Network egress from the execution sandbox was restricted by a host-layer allow-only firewall (DOCKER-USER chain) at the time of execution; DNS queries to the pinned resolvers could still carry exfiltration in query names — the boundary does not inspect DNS payloads.
- The capability parser registry is empty: no shell/session capability can be claimed, and post-exploitation stays dormant.


## Proof this report is genuine

Every step of this engagement was recorded in a tamper-proof log.
The log's final fingerprint is:

`3f722d3e801c5057acabe8a660d44f9d6c67c1dfa0aa4adce20cc63f9dbc090a`

Anyone can check the log file (`engagements/lab-p5-full-20261117T110737Z/audit.jsonl`)
against this fingerprint to prove nothing was changed after the fact.
