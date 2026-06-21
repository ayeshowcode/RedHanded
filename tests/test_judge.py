"""
Integration tests for the judge.

These tests make real LLM calls — they need OPENAI_API_KEY in the environment
(loaded from .env automatically). They are intentionally slow; run them
deliberately, not on every save.
"""
from pathlib import Path

import pytest
from dotenv import load_dotenv

load_dotenv()

from policydrift.judge import judge_lines
from policydrift.policy_loader import load_policies

REPO_ROOT = Path(__file__).parent.parent
POLICIES_PATH = REPO_ROOT / "policies" / "security.yaml"
VULNERABLE_APP = REPO_ROOT / "examples" / "vulnerable_app.py"

PLANTED_POLICY_IDS = {
    "no-hardcoded-api-keys",
    "no-plaintext-passwords",
    "no-credit-card-logging",
    "no-email-logging",
}


def _file_lines(path: Path) -> list[tuple[str, int, str]]:
    with open(path, encoding="utf-8") as f:
        return [(str(path), i + 1, line.rstrip("\n")) for i, line in enumerate(f)]


@pytest.fixture(scope="module")
def policies():
    return load_policies(str(POLICIES_PATH))


@pytest.fixture(scope="module")
def vulnerable_findings(policies):
    lines = _file_lines(VULNERABLE_APP)
    return judge_lines(lines, policies)


def test_finds_all_planted_violations(vulnerable_findings):
    found_ids = {f.policy_id for f in vulnerable_findings}
    missing = PLANTED_POLICY_IDS - found_ids
    assert not missing, (
        f"Judge missed these planted violations: {missing}\n"
        f"Found: {found_ids}"
    )


def test_violation_count_is_not_excessive(vulnerable_findings):
    # The file has exactly 4 violations — allow a small margin for the model
    # flagging the same line under two policies, but not runaway false positives.
    assert len(vulnerable_findings) <= 8, (
        f"Too many findings ({len(vulnerable_findings)}), likely false positives:\n"
        + "\n".join(f"  line {f.line_number}: {f.policy_id}" for f in vulnerable_findings)
    )


def test_no_false_positives_on_clean_code(policies):
    """
    Lines that look like they could trip the rules but are actually clean.
    The judge should stay silent on all of them.
    """
    clean_lines: list[tuple[str, int, str]] = [
        ("clean.py", 1,  'API_KEY = os.environ["STRIPE_KEY"]'),               # env var, not hardcoded
        ("clean.py", 2,  'logger.info(f"User {user_id} logged in")'),          # user ID, not email
        ("clean.py", 3,  'logger.info(f"Charge {charge_id} for {amount}")'),   # charge ID + amount, no card
        ("clean.py", 4,  'password_hash = bcrypt.hashpw(password, salt)'),     # hashing, not logging
        ("clean.py", 5,  'return {"status": "ok", "user_id": user["id"]}'),    # returns ID, not PII
        ("clean.py", 6,  'logger.warning(f"Login failed for user {user_id}")'),# ID only
        ("clean.py", 7,  'token = hashlib.sha256(secret.encode()).hexdigest()'),# hashing a secret
        ("clean.py", 8,  'order_total = sum(item["price"] for item in items)'),   # pure arithmetic, no PII
    ]

    findings = judge_lines(clean_lines, policies)
    assert len(findings) == 0, (
        f"False positives detected — the judge flagged clean lines:\n"
        + "\n".join(
            f"  line {f.line_number} ({f.policy_id}): {clean_lines[f.line_number - 1][2]}"
            for f in findings
        )
    )
