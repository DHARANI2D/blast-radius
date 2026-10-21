"""Telemetry tools, shaped after OpsRamp-style golden signals."""

from __future__ import annotations

from . import ToolContext, ToolSpec


def tools(ctx: ToolContext) -> list[ToolSpec]:
    twin = ctx.twin

    def get_golden_signals(assets: list[str]) -> list[dict]:
        """Current golden signals (health, NIC latency, drops, CRC, reachability, VM heartbeats) for each asset."""
        return [twin.signals(a) for a in assets]

    def get_metric_series(asset: str, metric: str, minutes: int = 10) -> list[dict]:
        """Samples of one metric over the last N minutes."""
        return twin.series(asset, metric, minutes)

    def get_clock() -> dict:
        """Simulated wall clock of the lab, in minutes since the change window opened."""
        return {"t_min": twin.clock_min}

    def advance_clock(minutes: int) -> dict:
        """Let the lab run for N minutes (soak time)."""
        twin.advance(minutes)
        return {"t_min": twin.clock_min}

    return [
        ToolSpec("telemetry", "get_golden_signals", get_golden_signals, description=get_golden_signals.__doc__),
        ToolSpec("telemetry", "get_metric_series", get_metric_series, description=get_metric_series.__doc__),
        ToolSpec("telemetry", "get_clock", get_clock, description=get_clock.__doc__),
        ToolSpec("telemetry", "advance_clock", advance_clock, description=advance_clock.__doc__),
    ]
