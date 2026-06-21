import json
from pathlib import Path
from typing import Optional

_HISTORY_PATH = Path.home() / ".policydrift" / "scan_history.json"


def _repo_id(repo_path: str) -> str:
    import hashlib
    return hashlib.sha256(str(Path(repo_path).resolve()).encode()).hexdigest()[:16]


def _fingerprint(finding: dict) -> tuple:
    # Identity is content-based, not position-based, so a violation that
    # shifts line numbers is still recognized as the same finding.
    return (finding["policy_id"], finding["file_path"], finding["line_content"].strip())


def load_last_scan(repo_path: str) -> Optional[list[dict]]:
    if not _HISTORY_PATH.exists():
        return None
    history = json.loads(_HISTORY_PATH.read_text())
    return history.get(_repo_id(repo_path))


def save_scan(repo_path: str, findings: list[dict]) -> None:
    history: dict = {}
    if _HISTORY_PATH.exists():
        history = json.loads(_HISTORY_PATH.read_text())
    history[_repo_id(repo_path)] = findings
    _HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    _HISTORY_PATH.write_text(json.dumps(history, indent=2))


def compute_drift(previous: Optional[list[dict]], current: list[dict]) -> dict:
    if previous is None:
        return {"new": current, "fixed": [], "persisting": []}

    prev_fps = {_fingerprint(f): f for f in previous}
    curr_fps = {_fingerprint(f): f for f in current}

    return {
        "new":        [curr_fps[fp] for fp in curr_fps if fp not in prev_fps],
        "fixed":      [prev_fps[fp] for fp in prev_fps if fp not in curr_fps],
        "persisting": [curr_fps[fp] for fp in curr_fps if fp in prev_fps],
    }
