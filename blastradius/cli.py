"""Command-line entry point: ``python -m blastradius <command>``."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from .config import ROOT

DEFAULT_INTENT = ("Upgrade iLO 6 and System ROM on clusters PROD-BLR-07 and PROD-BLR-08 and the ToR switch pair "
                  "to the latest baseline this Saturday 10pm")

COLORS = {"info": "", "warn": "\033[33m", "error": "\033[31m", "success": "\033[32m"}


def _print_timeline(events: list[dict], start: int = 0) -> int:
    tty = sys.stdout.isatty()
    for e in events[start:]:
        c = COLORS.get(e["level"], "") if tty else ""
        reset = "\033[0m" if c else ""
        print(f"  {c}[{e['agent']:>10}] {e['detail']}{reset}")
    return len(events)


def _card(card: dict) -> None:
    print(f"\n  ┌─ GO / NO-GO ({card['scope']}) ── plan {card['plan_hash'][:12]} ({card['plan_provenance']})")
    draft = card.get("draft_trust_score")
    print(f"  │ Trust Score {card['trust_score']:.0f}/100 (planner self-confidence {card['self_confidence']})"
          + (f" · planner's draft rationale {draft:.0f}/100" if draft is not None else "")
          + f"  · max Blast-Radius Score {card['max_brs']:.0f} · {card['total_duration_min']} min")
    for w in card["waves"]:
        ev = f" (+evacuate {', '.join(w['evacuate'])})" if w["evacuate"] else ""
        print(f"  │  {w['name']:<32} {len(w['assets']):>2} assets  BRS {w['brs']:>5.1f}  {w['duration_min']} min{ev}")
    cov, rr = card.get("canary_coverage"), card.get("risk_ranked_coverage")
    if cov and card["scope"] == "canary":
        canary = card["waves"][0]["assets"] if card["waves"] else []
        print(f"  │ Canary {', '.join(canary)} covers {cov['covered']}/{cov['total']} configuration cohorts "
              f"({cov['hosts_represented']}/{cov['hosts_total']} hosts represented)")
        if rr:
            print(f"  │   a risk-ranked canary ({', '.join(rr['canary'])}) would cover {rr['covered']}/{rr['total']} "
                  f"({rr['hosts_represented']}/{rr['hosts_total']})")
    if card.get("canary_result"):
        cr = card["canary_result"]
        print(f"  │ Canary {', '.join(cr['assets'])}: {cr['result']} ({cr['checked']} signal sets checked)")
    for w in card.get("warnings") or []:
        print(f"  │ Warning: {w}")
    if card.get("optimizer_stopped_by") == "time_budget":
        print("  │ Optimiser stopped by its time cap, not its iteration count: this plan depends on machine speed")
    if card["deferred"]:
        print(f"  │ Deferred: {len(card['deferred'])} asset(s) - {card['deferred'][0]['reason'][:110]}")
    pm = card.get("premortem")
    if pm and card["scope"] == "canary":
        cmp_rows = card.get("premortem_compare") or []
        first = next((r for r in cmp_rows if r["plan"] == "attempt 1"), None)
        print(f"  │ Pre-mortem (assumption-driven): P(tier-0 outage) {pm['p_tier0_loss']:.2%} over the change"
              + (f" vs {first['p_tier0_loss']:.0%} for attempt 1" if first else "")
              + f"; expected VMs lost {pm['expected_vms_lost']:.2f}")
    print(f"  │ Rollback: {card['rollback_plan'][:150]}...")
    print(f"  └─ requires {card['required_approvers']} approver(s)")


def cmd_demo(args) -> int:
    from .services import Services
    from .workflow import Engine

    os.environ["BR_FAULTS"] = args.faults
    sv = Services.create(tool_transport=args.transport, fault_scenario=args.faults)
    if args.reset:
        sv.reset_lab(forget_lessons=True)
    eng = Engine(sv)
    print(f"BlastRadius demo · tools over {sv.bus.transport.upper()} · planner={sv.llm.model} · verifier={sv.verifier_llm.model}")
    print(f"Intent: {args.intent}\n")
    r = eng.start(args.intent)
    shown = _print_timeline(r["state"]["timeline"])
    while r["interrupt"]:
        card = r["interrupt"]
        if card["scope"] == "escalation":
            print("\n  Escalated: no plan passed. Feedback:", json.dumps(card["feedback"], indent=2)[:800])
            r = eng.resume(r["run_id"], {"decision": "abort", "approver": "cli"})
            break
        _card(card)
        need = card["required_approvers"]
        if args.auto_approve:
            names = ["auto.approver-1", "auto.approver-2"][:need]
            verdict = "approve"
        else:
            ans = input("  Approve? [y/N] ").strip().lower()
            verdict = "approve" if ans in ("y", "yes") else "reject"
            names = [input(f"  Approver {i + 1} name: ").strip() for i in range(need)] if verdict == "approve" else [input("  Your name: ").strip()]
        payload = {"decision": verdict, "approver": names[0], "approvers": names}
        r = eng.resume(r["run_id"], payload)
        shown = _print_timeline(r["state"]["timeline"], shown)
        if r["interrupt"] and r["state"].get("approval_error"):
            print(f"\n  Not signed: {r['state']['approval_error']}")
    st = r["state"]
    print(f"\nOutcome: {st.get('status')}")
    if st.get("business_impact"):
        from .business import summary_lines

        for line in summary_lines(st["business_impact"]):
            print(line)
        opt = st["business_impact"].get("with_optimised_order")
        if opt and (opt.get("detected_wave") or 0) > 1:  # only when the risk-ranked canary would have missed it
            print(f"With the optimiser's risk-aware ordering alone, a missed canary would have cost ~${opt['counterfactual_usd']:,.0f} "
                  f"({'no' if not opt['tier0_vms'] else len(opt['tier0_vms'])} tier-0 VMs exposed).")
    mem = sv.memory.stats()
    print(f"Planning memory: {mem['rules']} rules; first-attempt pass rate {mem['first_attempt_pass_rate']} over {mem['runs']} run(s)")
    if st.get("report"):
        print(f"Signed report: {st['report']['path']}")
    v = sv.ledger.verify()
    print(f"Ledger: {v['entries']} entries, hash chain {'OK' if v['ok'] else 'BROKEN at ' + str(v['broken_at'])}")
    return 0


def cmd_ledger(args) -> int:
    from .config import Settings
    from .ledger import Ledger

    settings = Settings()
    led = Ledger(settings.runtime_dir / "ledger.sqlite", settings.signing_key)
    if args.action == "verify":
        print(json.dumps(led.verify(), indent=2))
    else:
        for e in led.entries(args.run):
            print(f"{e['seq']:>5} {e['run_id']} {e['actor']:<22} {e['event']:<20} {e['hash'][:16]}")
    return 0


def cmd_tools(args) -> int:
    from .services import Services

    sv = Services.create(tool_transport="mcp", ledger_path=":memory:")
    for domain in sv.bus.describe()["servers"]:
        print(f"{domain}: {', '.join(sv.bus.list_mcp_tools(domain))}")
    return 0


def cmd_reset(args) -> int:
    from .services import Services

    sv = Services.create(tool_transport="inproc", ledger_path=":memory:")
    sv.reset_lab(forget_lessons=True)
    print("lab twin reset; learned incidents cleared")
    return 0


def cmd_ui(args) -> int:
    app = ROOT / "ui" / "app.py"
    return subprocess.call([sys.executable, "-m", "streamlit", "run", str(app), "--server.port", str(args.port)])


def cmd_mcp_serve(args) -> int:
    from .mcp_layer import serve_stdio

    serve_stdio(args.domain)
    return 0


def cmd_redteam(args) -> int:
    from .redteam import main as redteam_main

    return redteam_main(["--seed", str(args.seed), "--extractor", args.extractor] + (["--no-paraphrases"] if args.no_paraphrases else [])
                        + (["--json", args.json] if args.json else []))


def cmd_memory(args) -> int:
    from .services import Services

    sv = Services.create(tool_transport="inproc", ledger_path=":memory:")
    if args.action == "clear":
        sv.memory.clear()
        print("planning memory cleared")
        return 0
    print(json.dumps({k: v for k, v in sv.memory.stats().items() if k != "top_rules"}, indent=2))
    for r in sorted(sv.memory.rules(), key=lambda r: -r["hits"]):
        print(f"- [{r['hits']}x] {r['key']}: {r['guidance']}")
    return 0


def cmd_greenlake(args) -> int:
    from .config import Settings
    from .greenlake import doctor, list_devices

    s = Settings()
    if args.action == "doctor":
        rep = doctor(s)
        print(json.dumps(rep, indent=2))
        return 0 if rep.get("ready") else 1
    r = list_devices(s)  # the one real network call
    if not r.get("enabled"):
        print(r.get("note") or "gl-mcp not configured")
        return 1
    for d in r.get("devices", [])[:50]:
        print(f"{d.get('serial', ''):<16} {d.get('model', ''):<34} {d.get('device_type', ''):<10} subs={len(d.get('subscriptions') or [])}")
    print(f"pages={r.get('pages')} total_reported={r.get('total_reported')} truncated={r.get('truncated')} ok={r.get('ok')}"
          + (f" error={r.get('error')}" if r.get("error") else ""))
    return 0 if r.get("ok") else 1


def cmd_a2a(args) -> int:
    from .a2a_server import agent_card

    print(json.dumps(agent_card(), indent=2))
    return 0


def cmd_a2a_serve(args) -> int:
    from .a2a_server import A2AService, make_server
    from .services import Services
    from .workflow import Engine

    sv = Services.create(tool_transport=args.transport)
    svc = A2AService(Engine(sv))
    srv = make_server(svc, host=args.host, port=args.port)
    print(f"A2A endpoint (read-only assess-change skill): {svc.base_url}/a2a")
    print(f"Agent card: {svc.base_url}/.well-known/agent-card.json")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def main(argv: list[str] | None = None) -> int:
    # BR_FAULTS and BR_TOOL_TRANSPORT (.env.example) set the defaults; an explicit flag wins.
    faults, transport = os.environ.get("BR_FAULTS", "on").strip().lower(), os.environ.get("BR_TOOL_TRANSPORT", "mcp").strip().lower()
    p = argparse.ArgumentParser(prog="blastradius", description="Agentic change-safety mesh (HPE Agentic AI Hackathon 2026 PoC)")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="run the end-to-end story in the terminal")
    d.add_argument("--intent", default=DEFAULT_INTENT)
    d.add_argument("--faults", choices=["on", "off", "subtle", "backup", "on+backup", "subtle+backup"], default=faults,
                   help="on: canary regression (4x); subtle: 1.3x regression only the statistical judge catches; "
                        "backup: slowdown on every host that a tight fixed threshold would mistake for a regression")
    d.add_argument("--transport", choices=["mcp", "inproc"], default=transport)
    d.add_argument("--auto-approve", action="store_true")
    d.add_argument("--reset", action="store_true", help="reset the twin and forget learned incidents first")
    d.set_defaults(fn=cmd_demo)
    lg = sub.add_parser("ledger", help="inspect or verify the audit ledger")
    lg.add_argument("action", choices=["verify", "show"])
    lg.add_argument("--run")
    lg.set_defaults(fn=cmd_ledger)
    sub.add_parser("tools", help="list MCP servers and tools").set_defaults(fn=cmd_tools)
    sub.add_parser("reset", help="reset the lab twin and forget learned incidents").set_defaults(fn=cmd_reset)
    u = sub.add_parser("ui", help="start the Streamlit Control Tower")
    u.add_argument("--port", type=int, default=8501)
    u.set_defaults(fn=cmd_ui)
    m = sub.add_parser("mcp-serve", help="run one domain MCP server over stdio")
    m.add_argument("domain", choices=["compute", "network", "virt", "telemetry", "knowledge"])
    m.set_defaults(fn=cmd_mcp_serve)
    rt = sub.add_parser("redteam", help="measure the Verifier against labelled false claims and mutated plans")
    rt.add_argument("--seed", type=int, default=7)
    rt.add_argument("--no-paraphrases", action="store_true")
    rt.add_argument("--extractor", choices=["offline", "configured"], default="offline",
                    help="'configured' extracts claims with the configured verifier model")
    rt.add_argument("--json")
    rt.set_defaults(fn=cmd_redteam)
    me = sub.add_parser("memory", help="show or clear the planner's learned rules")
    me.add_argument("action", choices=["show", "clear"])
    me.set_defaults(fn=cmd_memory)
    gl = sub.add_parser("greenlake", help="HPE GreenLake MCP (gl-mcp): readiness check, or a read-only device listing")
    gl.add_argument("action", choices=["doctor", "devices"])
    gl.set_defaults(fn=cmd_greenlake)
    sub.add_parser("a2a-card", help="print the A2A agent card that a2a-serve serves (default host and port)").set_defaults(fn=cmd_a2a)
    a2 = sub.add_parser("a2a-serve", help="serve the read-only assess-change skill over A2A (JSON-RPC)")
    a2.add_argument("--host", default="127.0.0.1")
    a2.add_argument("--port", type=int, default=8765)
    a2.add_argument("--transport", choices=["mcp", "inproc"], default=transport)
    a2.set_defaults(fn=cmd_a2a_serve)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
