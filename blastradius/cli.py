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
    print(f"  │ Trust Score {card['trust_score']:.0f}/100 (planner self-confidence {card['self_confidence']})"
          f"  · max Blast-Radius Score {card['max_brs']:.0f} · {card['total_duration_min']} min")
    for w in card["waves"]:
        ev = f" (+evacuate {', '.join(w['evacuate'])})" if w["evacuate"] else ""
        print(f"  │  {w['name']:<32} {len(w['assets']):>2} assets  BRS {w['brs']:>5.1f}  {w['duration_min']} min{ev}")
    if card.get("canary_result"):
        cr = card["canary_result"]
        print(f"  │ Canary {', '.join(cr['assets'])}: {cr['result']} ({cr['checked']} signal sets checked)")
    if card["deferred"]:
        print(f"  │ Deferred: {len(card['deferred'])} asset(s) - {card['deferred'][0]['reason'][:110]}")
    print(f"  │ Rollback: {card['rollback_plan'][:150]}...")
    print(f"  └─ requires {card['required_approvers']} approver(s)")


def cmd_demo(args) -> int:
    from .services import Services
    from .workflow import Engine

    os.environ["BR_FAULTS"] = args.faults
    sv = Services.create(tool_transport=args.transport, faults_enabled=args.faults == "on")
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
    st = r["state"]
    print(f"\nOutcome: {st.get('status')}")
    if st.get("avoided_cost_usd"):
        print(f"Estimated outage avoided (illustrative, ITIC $300K/h floor x 4 h): ${st['avoided_cost_usd']:,.0f}")
    if st.get("report"):
        print(f"Signed report: {st['report']['path']}")
    v = sv.ledger.verify()
    print(f"Ledger: {v['entries']} entries, hash chain {'OK' if v['ok'] else 'BROKEN at ' + str(v['broken_at'])}")
    return 0


def cmd_ledger(args) -> int:
    from .config import Settings
    from .ledger import Ledger

    led = Ledger(Settings().runtime_dir / "ledger.sqlite")
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


def cmd_a2a(args) -> int:
    print((ROOT / "a2a" / "agent-card.json").read_text())
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="blastradius", description="Agentic change-safety mesh (HPE Agentic AI Hackathon 2026 PoC)")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="run the end-to-end story in the terminal")
    d.add_argument("--intent", default=DEFAULT_INTENT)
    d.add_argument("--faults", choices=["on", "off"], default="on", help="inject the canary firmware regression")
    d.add_argument("--transport", choices=["mcp", "inproc"], default="mcp")
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
    sub.add_parser("a2a-card", help="print the A2A agent card").set_defaults(fn=cmd_a2a)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
