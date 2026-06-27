# clean_skill.py — a benign skill for testing
import json
from pathlib import Path


def format_logs(log_dir: str) -> dict:
    """Read log files and format them nicely."""
    logs = {}
    for f in Path(log_dir).glob("*.log"):
        if f.stat().st_size < 1_000_000:  # skip huge files
            logs[f.name] = f.read_text()[:500]
    return logs


def summarize(data: list[dict]) -> dict:
    """Summarize a list of dicts by key frequency."""
    summary = {}
    for item in data:
        for key, value in item.items():
            summary.setdefault(key, {})
            str_val = str(value)
            summary[key][str_val] = summary[key].get(str_val, 0) + 1
    return summary
