"""Persist concise, non-secret metadata for generation runs."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utc_timestamp() -> str:
    """Return a second-precision UTC timestamp suitable for JSON and filenames."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_id(timestamp: str | None = None) -> str:
    """Return a sortable run identifier."""
    value = timestamp or utc_timestamp()
    return value.replace("-", "").replace(":", "")


def new_generation_log(settings: dict[str, object], scenario_count: int) -> dict[str, Any]:
    """Create the run-level log structure before scenario processing starts."""
    started_at = utc_timestamp()
    return {
        "schema_version": 1,
        "run_id": run_id(started_at),
        "started_at": started_at,
        "command": "generate",
        "scenario_count": scenario_count,
        "settings": settings,
        "scenarios": [],
    }


def write_generation_log(run_log: dict[str, Any], base: Path) -> Path:
    """Write a timestamped generation log under ``runs/generation-log``."""
    directory = base / "generation-log"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{run_log['run_id']}.json"
    path.write_text(json.dumps(run_log, indent=2), encoding="utf-8")
    return path
