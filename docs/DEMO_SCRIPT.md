# 5-minute demo video script

Setup: `python -m blastradius ui`, browser at 1500×950 or larger, sidebar shows **Tool transport: mcp** and **Inject canary fault: on**. Press **Reset lab** before recording.

| Time | Screen / click | Narration (suggested) |
|---|---|---|
| 0:00-0:30 | Title slide, then the Control Tower | "41% of major network outages and 51% of major IT outages start with a change (Uptime 2026), and an hour of downtime costs a large enterprise over $300K (ITIC 2024). Tonight an AI agent wants to upgrade 40 servers and two top-of-rack switches. Should you let it?" |
| 0:30-1:00 | Intent is pre-filled. Click **Analyse change**. Point at the agent timeline. | "BlastRadius parses the intent, then its Topology agent builds a live dependency graph from five MCP servers: 563 nodes across compute, network, virtualization and storage, in about a second." |
| 1:00-1:30 | Tab ① with the **Hidden dependencies** overlay | "First catch: LLDP shows blr-esx-07, the host running payments-db, has had its second uplink err-disabled for three weeks. No single-domain tool connects that to tonight's switch upgrade. Risk propagation makes tor-r1-a the riskiest asset in the change." |
| 1:30-2:00 | Overlay **Attempt 1 · wave 1 impact** (red graph) | "The planner's first idea is the obvious one: do both ToR switches first. The simulation shows 504 VMs losing service, because the storage array hangs only off this switch pair, so the *other* cluster loses its datastores too. The constraint checker rejects the plan with 12 violations." |
| 2:00-2:45 | Tab ② Plan & Verifier: attempt 1, then attempt 2 | "Second catch: hallucinations. The planner says 'ROM v2.32 remediates SYN-CVE-2026-1105' and rates itself 91% confident. The independent Verifier pulls the release notes and the advisory over MCP: contradicted, the fix is in iLO 1.66. Five contradicted claims, Trust Score 0. The planner re-plans with that feedback: switches staggered, the single-homed host evacuated with its switch, five hosts per cluster per wave. Trust Score 97. The one unverifiable claim, about Saturday traffic, is labelled honestly." |
| 2:45-3:15 | Tab ③ Go / No-Go, then **Approve and sign** | "Nothing runs without a human. The card shows the waves, Blast-Radius Scores, evidence and rollback plan. The approval is HMAC-signed into the ledger, and the MCP write tools only accept tokens scoped to these assets." |
| 3:15-4:15 | Tab ④ Execution (chart animates) | "The canary runs: hosts evacuated, iLO then ROM flashed, signals compared. On blr-esx-03, NIC latency jumps 4.1x. Auto-halt, write access revoked, rollback, signals recover. The other four waves never run. Estimated outage avoided: four hours at $300K an hour, $1.2M." |
| 4:15-4:45 | Lesson banner, then **New run** → **Analyse change** → Risk heat (grey hosts) | "BlastRadius learns. The healthy control host also got iLO 1.64, so iLO is exonerated; ROM v2.32 with NIC firmware 229.x is blamed. On the next run the 20 affected hosts are deferred automatically and the rest proceed safely." |
| 4:45-5:00 | Tab ⑤ Audit: **Verify chain**, **Simulate tampering**; then the architecture slide | "Every prompt hash, tool call, claim, approval and action is in a hash-chained ledger; edit one entry and the chain breaks. BlastRadius is MCP-native, built to register in GreenLake Intelligence: preventive runtime control for the agentic enterprise." |

Say plainly once in the video: *"Execution here runs against a simulated digital twin with an injected fault; the data is synthetic."*

Backup if the UI misbehaves: `python -m blastradius demo --auto-approve --reset` shows the same story in the terminal.
