import json
import re

from langchain_openai import ChatOpenAI

from .models import Finding, Policy

CHUNK_SIZE = 40

# ── Tune these two constants to change how the model behaves ──────────────────

SYSTEM_PROMPT = """\
You are a strict code security auditor. Your only job is to identify lines \
that genuinely violate the given policies.

A violation only occurs when a sensitive value is actively written somewhere \
it should not be — logged, printed, returned in a response, written to a file, \
or sent to an external service. Reading, accessing, or passing a value is NOT \
a violation on its own.

NOT violations (do not flag these):
- email = body.get("email")          — reads a value, does not expose it
- card = request.data["card_number"] — accesses a dict key, does not expose it
- user = get_user(db, email)         — passes a value to a function, does not expose it
- if card_number == stored:          — compares a value, does not expose it

ARE violations (flag these):
- logger.info(f"email={user.email}") — writes PII to a log
- print(f"card: {card_number}")      — writes card number to stdout
- API_KEY = "sk_live_abc123"         — hardcodes a secret in source

Additional rules:
- Only flag a line if you are certain it violates a policy. When unsure, return nothing.
- Never invent line numbers. Only use line numbers from the numbered list you are given.
- A violation must be on the flagged line itself — do not flag imports or definitions \
  that do not directly expose the violation.
- Return ONLY a valid JSON array. No prose, no markdown, no explanation outside the JSON.
- If there are no violations, return exactly: []\
"""

VIOLATION_PROMPT = """\
Policies to enforce:
{policy_text}

Code lines (numbered):
{numbered_lines}

Return a JSON array of violations. Each element must have exactly these keys:
  "line_number"   : integer matching one of the line numbers above
  "policy_id"     : string matching one of the policy IDs above exactly
  "explanation"   : one sentence explaining why this line violates the policy
  "suggested_fix" : the corrected line or a concrete alternative
  "confidence"    : float 0.0-1.0, your certainty this is a genuine violation

Return [] if nothing is a genuine violation.\
"""

# ─────────────────────────────────────────────────────────────────────────────


def _extract_json(text: str) -> str:
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if match:
        return match.group(1)
    match = re.search(r"\[[\s\S]*\]", text)
    if match:
        return match.group(0)
    return text.strip()


def _build_prompt(chunk: list[tuple[str, int, str]], policies: list[Policy]) -> tuple[str, set[str]]:
    numbered = "\n".join(f"{i + 1}: {line}" for i, (_, _, line) in enumerate(chunk))
    policy_text = "\n".join(f"- {p.id}: {p.description}" for p in policies)
    valid_ids = {p.id for p in policies}
    prompt = VIOLATION_PROMPT.format(numbered_lines=numbered, policy_text=policy_text)
    return prompt, valid_ids


def _parse_response(content: str, chunk: list[tuple[str, int, str]], valid_ids: set[str]) -> list[Finding]:
    try:
        violations = json.loads(_extract_json(content))
    except (json.JSONDecodeError, ValueError):
        return []

    findings: list[Finding] = []
    for v in violations:
        idx = v.get("line_number")
        confidence = float(v.get("confidence", 0))
        policy_id = v.get("policy_id", "")

        if not isinstance(idx, int) or not (1 <= idx <= len(chunk)):
            continue
        if confidence < 0.6:
            continue
        if policy_id not in valid_ids:
            continue

        file_path, line_number, line_content = chunk[idx - 1]
        findings.append(Finding(
            file_path=file_path,
            line_number=line_number,
            line_content=line_content,
            policy_id=policy_id,
            explanation=v.get("explanation", ""),
            suggested_fix=v.get("suggested_fix", ""),
            confidence=confidence,
        ))

    return findings


def _judge_chunk(chunk: list[tuple[str, int, str]], policies: list[Policy], llm: ChatOpenAI) -> list[Finding]:
    prompt, valid_ids = _build_prompt(chunk, policies)
    response = llm.invoke([{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}])
    return _parse_response(response.content, chunk, valid_ids)


async def judge_chunk_async(chunk: list[tuple[str, int, str]], policies: list[Policy], llm: ChatOpenAI) -> list[Finding]:
    prompt, valid_ids = _build_prompt(chunk, policies)
    response = await llm.ainvoke([{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}])
    return _parse_response(response.content, chunk, valid_ids)


def judge_lines(
    lines: list[tuple[str, int, str]],
    policies: list[Policy],
) -> list[Finding]:
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    findings: list[Finding] = []
    for i in range(0, len(lines), CHUNK_SIZE):
        findings.extend(_judge_chunk(lines[i : i + CHUNK_SIZE], policies, llm))
    return findings
