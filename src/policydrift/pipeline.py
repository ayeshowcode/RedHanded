import asyncio

from langchain_openai import ChatOpenAI
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from .judge import CHUNK_SIZE, judge_chunk_async
from .models import ScanReport
from .policy_loader import load_policies
from .scanner import collect_files

MAX_CONCURRENT = 5


async def _run_async(repo_path: str, policies_path: str) -> ScanReport:
    policies = load_policies(policies_path)
    lines = collect_files(repo_path)

    chunks = [lines[i : i + CHUNK_SIZE] for i in range(0, len(lines), CHUNK_SIZE)]
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    findings = []

    async def run_chunk(chunk, progress, task):
        async with semaphore:
            result = await judge_chunk_async(chunk, policies, llm)
            progress.advance(task)
            return result

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
    ) as progress:
        task = progress.add_task(f"Scanning {len(chunks)} chunks…", total=len(chunks))
        results = await asyncio.gather(*[run_chunk(c, progress, task) for c in chunks])

    for result in results:
        findings.extend(result)

    # Deduplicate by (file_path, line_number, policy_id), keeping highest confidence.
    seen: dict[tuple[str, int, str], int] = {}
    unique = []
    for f in findings:
        key = (f.file_path, f.line_number, f.policy_id)
        if key not in seen:
            seen[key] = len(unique)
            unique.append(f)
        elif f.confidence > unique[seen[key]].confidence:
            unique[seen[key]] = f

    return ScanReport(
        findings=unique,
        files_scanned=len({fp for fp, _, _ in lines}),
        policies_checked=len(policies),
    )


def run_scan(repo_path: str, policies_path: str) -> ScanReport:
    return asyncio.run(_run_async(repo_path, policies_path))
