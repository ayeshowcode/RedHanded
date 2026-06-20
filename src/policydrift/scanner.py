import os
import sys

import git

SKIP_DIRS = {"node_modules", ".venv", ".git", "__pycache__"}


def _is_binary(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(8192)
    except OSError:
        return True


def collect_files(
    repo_path: str, extensions: list[str] = [".py"]
) -> list[tuple[str, int, str]]:
    try:
        repo = git.Repo(repo_path, search_parent_directories=True)
    except git.InvalidGitRepositoryError:
        repo = None

    candidates: list[str] = []
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if any(filename.endswith(ext) for ext in extensions):
                candidates.append(os.path.join(dirpath, filename))

    ignored: set[str] = set(repo.ignored(*candidates)) if repo and candidates else set()

    results: list[tuple[str, int, str]] = []
    for full_path in candidates:
        if full_path in ignored or _is_binary(full_path):
            continue
        try:
            with open(full_path, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            continue
        if len(lines) > 5000:
            continue
        for i, line in enumerate(lines, start=1):
            results.append((full_path, i, line.rstrip("\n")))

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <path>")
        sys.exit(1)

    lines = collect_files(sys.argv[1])
    files = len({p for p, _, _ in lines})
    print(f"{len(lines)} lines across {files} files")
