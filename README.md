# Cybersecurity Incident Response Playbook Runner

**Group 3** · Gaurav Tiwari (12315283) · Kritagya Pandey (12321043) · Khushi Dogra (12320152)

This multi-agent system takes a raw security alert and returns:

- a triage decision (**severity**)
- the **affected assets**
- an **ordered containment plan**, with the **intel source behind each step**

The agents are built on **Microsoft Semantic Kernel** and coordinated with a **planner-executor** architecture. They use **RAG over a threat-report set** and a **shared incident timeline**. A **safety guard** keeps destructive steps from running until a human approves them (the group-of-3 add-on).

## Quick start

```bash
pip install -r requirements.txt

python evaluate.py                                # the 10-alert evaluation -> output/eval_report.md
python main.py --alert A01                        # one alert; you approve destructive steps at the console
python main.py --all --approval deny              # every alert, simulated analyst rejects destructive steps
python main.py --alert A07 --inject-plan-fault    # watch the Commander reject an unsafe plan
python main.py --alert-file my_alert.json         # your own raw alert (JSON or a syslog line)
python -m unittest discover -s tests -t .         # 37 unit, integration and HTTP security tests
```

### Web console

```bash
python webapp.py          # prints and opens http://localhost:8000/#token=<per-launch token>
```

The browser console runs the real pipeline. It needs no extra packages, since the server uses only the Python standard library. Always open the exact link the server prints. Without the token the console stays locked; see *Security model* below.

- **Run an alert.** Pick one of the 10 synthetic alerts, or paste your own raw alert as JSON or a syslog line.
- **See the result.** The page shows the severity (checked against ground truth), the agent pipeline, affected and at-risk assets, and the ordered containment plan. Click any intel citation to open the source threat report with that step highlighted.
- **Approve or reject gated steps.** Set your analyst name (top right) first; every decision is recorded on the timeline under that name. Recovery steps on the same target wait too.
- **Recent incidents.** Incidents are kept on disk, so after a server restart you can reopen one and still approve its pending steps.
- **Read the timeline.** The full shared incident timeline is shown, and you can filter it by agent.
- **Check the evaluation.** The **Evaluation** tab shows the metrics and safety checks, and can re-run the evaluation.

Deep links: `/?alert=A05`, `/?incident=<id>` and `/?tab=eval`.

No API key is needed. The pipeline is deterministic, so the evaluation gives the same result on every run. If `OPENAI_API_KEY`, Azure OpenAI or `ANTHROPIC_API_KEY` variables are set (see [irp/llm.py](irp/llm.py)), the Incident Commander also uses a Semantic Kernel `ChatCompletionAgent` to write an executive summary.

## Architecture

```
                    raw alert
                        │
        ┌───────────────▼────────────────┐   re-plans after every task:
        │        WorkflowPlanner         │   • low-confidence intel -> broaden retrieval
        │  (what to do, in what order)   │   • plan rejected -> revise + re-review
        └───────────────┬────────────────┘   • rejected 3x -> escalate, don't execute
                        │ task list
        ┌───────────────▼────────────────┐
        │          PlanExecutor          │   dispatches each task to its agent
        └──┬──────┬──────┬──────┬──────┬─┘
           │      │      │      │      │
   ┌───────▼┐ ┌───▼───┐ ┌▼─────┐ ┌▼────────┐ ┌▼──────────────────┐
   │ Alert  │ │Threat │ │Impact│ │Contain- │ │ Incident Commander│
   │ Parser │ │ Intel │ │Asses-│ │ ment    │ │ review -> approve │
   │        │ │ (RAG) │ │ sor  │ │ Planner │ │ -> execute        │
   └───┬────┘ └───┬───┘ └──┬───┘ └───┬─────┘ └───┬──────────┬────┘
       │          │        │         │           │          │ destructive?
  ═════▼══════════▼════════▼═════════▼═══════════▼═══╗ ┌────▼──────────┐
  ║      SHARED INCIDENT TIMELINE (read + write)     ║ │ Human Approval│
  ╚══════════════════════════════════════════════════╝ │ Gate (token)  │
                                                        └────┬──────────┘
  Semantic Kernel plugins (tools):                           │
   threat_intel.search_reports / get_containment     ┌───────▼──────────┐
   assets.lookup_host / lookup_ip / lookup_user /    │ Mock Response    │
          lookup_cloud                               │ Tool + Safety    │
   response.execute_action ─────────────────────────►│ Guard (verifies) │
                                                     └──────────────────┘
```

| Agent | Module | Reads from timeline | Writes to timeline | Tools |
|---|---|---|---|---|
| Alert Parser | [irp/agents/alert_parser.py](irp/agents/alert_parser.py) | `alert_received` | `incident_record_created` | none |
| Threat Intel Retrieval | [irp/agents/threat_intel.py](irp/agents/threat_intel.py) | incident record | `intel_retrieved` | `threat_intel.search_reports` |
| Impact Assessor | [irp/agents/impact_assessor.py](irp/agents/impact_assessor.py) | incident, intel | `impact_assessed` (assets + severity) | `assets.*` |
| Containment Planner | [irp/agents/containment_planner.py](irp/agents/containment_planner.py) | incident, intel, impact | `containment_plan_drafted` | `threat_intel.get_containment` |
| Incident Commander | [irp/agents/incident_commander.py](irp/agents/incident_commander.py) | everything | `plan_reviewed`, `step_*`, `incident_report` | `response.execute_action` |

Agents never hand results to each other directly. Each one writes its output to the [shared timeline](irp/timeline.py), and the next agent reads its input from there. The timeline is saved to `output/<alert>/timeline.jsonl`, which gives a full audit trail, including every approval decision.

### How each part works

- **Parsing.** The parser handles JSON from 7 different products, each with its own field names, plus raw syslog lines. Field aliases normalise the known fields. Regexes pull out IPs, SHA-256 hashes, domains, AWS keys and account IDs. The parser also tags the alert as *confirmed* (the attack succeeded), *blocked*, or *unknown*.
- **RAG.** The 12 threat reports in [data/threat_reports/](data/threat_reports/) are split into sections and indexed with TF-IDF. An IOC that matches exactly gives a report a score boost. Two reports (TR-011 DDoS, TR-012 SQLi) are distractors with no matching alert.
- **Severity.** The score is: base severity of the matched report, +1 if a directly affected asset is high or critical (−1 if all are low), +1 if the attack is confirmed (−1 if blocked). The score maps to Low (≤1), Medium (2), High (3) or Critical (≥4).
- **Containment.** Every step is built from the matched report's *Recommended Containment* section. The planner fills in real targets from the incident, filters steps by minimum severity (for example, reimaging is only proposed at High or above), and orders them preserve → contain → eradicate → recover. Each step cites its report and step number, for example `TR-005 RC #4`.
- **Commander review.** The Commander checks that every step cites a retrieved report, that destructive steps are flagged, that step order is correct, that host targets are known assets, and that there are no duplicates. If any check fails, the plan goes back to the planner with feedback.

### Safety guard (group-of-3 add-on)

Defined in [irp/safety.py](irp/safety.py). The destructive actions are `wipe_and_reimage`, `terminate_instances`, `shutdown_service` and `purge_emails`. Two independent layers protect them:

1. **The Commander asks the HumanApprovalGate** before any destructive step. The analyst can approve at the console, or a simulated analyst can approve or deny. Only an approved step receives a token. The token is an HMAC over (incident, step, action, target) signed with a secret only the gate holds, and it works once.
2. **The response tool's SafetyGuard verifies the token itself.** An agent that skips the gate, forges a token, or reuses a token on a different host or action is refused at the tool.

A recovery step on a target whose destructive step is still waiting (for example, *restore from backup* after an unapproved *wipe*) is deferred as well.

### Approval policy

| Step | Needs a human decision? |
|---|---|
| Destructive (`wipe_and_reimage`, `terminate_instances`, `shutdown_service`, `purge_emails`) | **Always.** The Commander asks the gate, and the response tool verifies the token itself. |
| Any non-preservation step when threat-intel confidence is **low** (even after broadened retrieval) | **Yes.** The plan may rest on the wrong report. |
| Recovery step on a target whose destructive step is still held | It is deferred, then runs once that step is approved, or is skipped if it is rejected. |
| Everything else | No; runs automatically. |

Approval tokens are `issued_at.HMAC(incident, step, action, target, issued_at)`, single-use, and expire after 15 minutes (`IRP_APPROVAL_TTL_SECONDS`).

### Memory architecture

- **Working memory: the shared incident timeline** ([irp/timeline.py](irp/timeline.py)). It is strictly append-only: events are deep-copied on write and on read, so no agent can rewrite history. It is thread-safe, persisted as JSONL, and can be reloaded from disk to resume an incident after a restart.
- **Long-term knowledge.** The threat-report RAG index and the asset inventory are read-only and shared across incidents. Agents reach them only through Semantic Kernel tools.
- **Agents keep no state of their own.** Each run reads its inputs from the timeline and writes its output back as a new event.
- **No memory across incidents.** Agents do not learn from past cases (a possible next step).

### Failure handling

- **Agent crash or exhausted task budget (`IRP_MAX_TASKS`):** the incident is escalated to a human and nothing is executed.
- **Plan rejected more than `IRP_MAX_PLAN_REVISIONS` times:** escalated.
- **No matching threat report:** the planner refuses to invent steps, and the incident is escalated.
- **A response-tool call fails:** that step is marked `failed`, and the rest of the plan continues.

### Security model (web console)

| Threat | Control |
|---|---|
| Another website POSTing approvals (CSRF) | Every API call needs the per-launch console token (`X-Console-Token`). POSTs must be `application/json`, which forces a CORS preflight that the server refuses. |
| DNS rebinding | The `Host` header must be `localhost` or `127.0.0.1`; anything else gets 421. |
| Clickjacking the Approve button | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` |
| XSS from attacker-controlled alert text | All values are HTML-escaped. A strict CSP (`script-src 'self'`) means no inline script runs. |
| Path traversal through incident ids | Ids are validated against `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`. |
| Resource exhaustion | Request size is capped at 256 KB and alert size at 64 KB; session memory is an LRU cache. |
| Leaking internals | 500 responses carry only an error id; the details go to the server log. |
| Token exposure | The token travels in the URL fragment, which is never sent to the server or logged, and is removed from the address bar on load. |
| Anonymous approvals | Approvals need a validated analyst name, which is recorded on the timeline. |

The console binds to 127.0.0.1 by default. It is a single-analyst local tool. Multi-user deployment would need real authentication (for example SSO/OIDC), four-eyes approval for destructive steps, and TLS.

### Configuration

All settings live in [irp/config.py](irp/config.py) and can be overridden with environment variables: `IRP_PORT`, `IRP_HOST`, `IRP_CONSOLE_TOKEN`, `IRP_APPROVAL_TTL_SECONDS`, `IRP_MAX_PLAN_REVISIONS`, `IRP_MAX_TASKS`, `IRP_LOW_CONFIDENCE_SCORE`, `IRP_MAX_ALERT_BYTES`, `IRP_MAX_REQUEST_BYTES`, `IRP_MAX_SESSIONS`, `IRP_OUTPUT_DIR`, `IRP_LOG_LEVEL`.

## Evaluation results (`python evaluate.py`)

| Metric | Result |
|---|---|
| Severity accuracy | **10/10 (100%)**. Baseline using the vendor's own severity field: 0/10 |
| Containment steps citing the correct intel source | **42/42 (100%)** |
| Affected-asset recall | 14/14 (100%) |
| No destructive step without human approval | **PASS** |

The safety claim is tested four ways:

- **Rejecting analyst:** 6 destructive steps proposed, 0 executed.
- **Approving analyst:** all 6 executions were preceded by a matching approval event on the timeline.
- **Direct attacks on the tool:** missing, malformed, forged, expired, replayed and reused tokens were all blocked.
- **Fault injection:** the planner was made to mislabel destructive steps. The Commander rejected each faulty plan, and nothing destructive ran without approval.

Full per-alert tables are in `output/eval_report.md`.

**Limitations (please read).** The 10 alerts, the threat reports and the severity rubric were all written together, so 100% means the rubric works on this set, not that it generalises. A useful robustness check: with the IOC boost turned off, the correct report still ranks first for all 10 alerts, by a margin of about 0.4–0.6 cosine similarity. A larger, independently labelled alert set would be the next step.

## Layout

```
main.py                 CLI demo
webapp.py               web console server (stdlib) + JSON API + security controls
web/index.html          web console page (markup + styles)
web/app.js              web console logic (served separately for a strict CSP)
irp/config.py           settings (env-overridable)
tests/                  unit, pipeline-integration and HTTP security tests
evaluate.py             10-alert evaluation + safety tests
irp/orchestrator.py     WorkflowPlanner, PlanExecutor, PlaybookRunner (kernel + plugin setup)
irp/agents/             the five agents (one module each)
irp/tools/              SK plugins: threat intel (RAG), asset inventory, mock response tool
irp/rag.py              TF-IDF retriever over threat reports
irp/timeline.py         shared incident timeline
irp/safety.py           destructive-action guard + human approval gate
data/                   threat reports, asset inventory, 10 synthetic alerts with ground truth
output/                 generated timelines, reports and the evaluation report
```
