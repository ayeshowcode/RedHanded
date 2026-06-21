# RedHanded

Somewhere in your codebase right now, a line like
`logger.info(f"Processing payment for {user.email}")` is probably sitting in
production. Your security policy says "never log customer PII." That line breaks
it — and nobody noticed, because the policy lives in a doc and the violation
lives in code, and no one reads both at once.

RedHanded reads your policies in plain English and finds exactly where your code
breaks them.

---

## The problem

Engineering teams write rules like:

- *Never log email addresses*
- *No hardcoded API keys — use environment variables*
- *Passwords must not appear in plaintext logs*

Then they ship code. The rules stay in a Confluence doc or a YAML file no one
opens. The violations accumulate quietly. A regex can't catch them because
the violation isn't a pattern — it's a judgment call. `logger.info(f"Sending
receipt to {user['email']}")` is fine until you know the policy; then it isn't.

RedHanded sends each candidate line plus your plain-English policies to an LLM
and asks: does this line violate this rule? It returns the exact file and line,
the explanation, and a suggested fix.

---

## Quickstart

```bash
git clone https://github.com/ayeshowcode/RedHanded.git
cd RedHanded
uv sync

# Run against the included demo app (has 4 planted violations)
uv run policydrift scan examples/ --policies policies/security.yaml

# Run against your own repo
uv run policydrift scan /path/to/your/repo --policies policies/security.yaml

# Track what changed since your last scan
uv run policydrift scan /path/to/your/repo --policies policies/security.yaml --drift
```

You need an OpenAI API key. Copy `.env.example` to `.env` and add it:

```
OPENAI_API_KEY=sk-...
```

---

## Writing your own policies

Policies are plain YAML. Each rule has an id, a plain-English description,
a category, and a severity:

```yaml
policies:
  - id: no-email-logging
    description: Never log email addresses — they are PII and must not appear in logs
    category: PII
    severity: high

  - id: no-hardcoded-api-keys
    description: API keys must not be hardcoded in source — use environment variables or a secrets manager
    category: secrets
    severity: high
```

Point `--policies` at any YAML file with this structure.

---

## How it works

```
Load policies (YAML)
       |
Collect files (walk repo, read every .py line)
       |
Batch lines into chunks of ~40
       |
Judge each batch (LLM sees: lines + all policies → returns violations as JSON)
       |
Aggregate findings → ScanReport
       |
CLI renders findings grouped by severity
```

The LLM receives a strict system prompt: flag only genuine violations, return
nothing when unsure, never invent line numbers. Results below 0.6 confidence
are dropped. The prompt template is a readable constant in `judge.py` — easy
to inspect and tune.

---

## Screenshot

<!-- add terminal screenshot here -->

---

## Limitations

- **This is an assistant, not an auditor.** It will miss things and occasionally
  flag things that are fine. Use it to surface candidates for human review, not
  as a compliance gate.
- **False positives are possible.** The false-positive test in `tests/test_judge.py`
  covers common look-alike patterns, but novel cases will slip through.
- **v1 covers secrets and PII logging only.** Architectural violations,
  dependency risks, and logic errors are out of scope.
- **Python files only** in v1. Other languages are a config change away but
  untested.
- **Cost.** Each scan makes one LLM call per 40-line batch. A 10,000-line repo
  costs roughly 250 calls to gpt-4o-mini — a few cents.

---

## Roadmap

- GitHub Action: run on pull requests, comment findings inline
- More languages: JS/TS, Go, Java
- Custom severity thresholds and per-rule ignore lists
