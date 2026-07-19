"""Collect evidence from a local git repository.

Produces three evidence types:

- ``git.commits``     — commit metadata, authors, GPG signature status
- ``git.secret_scan`` — regex scan of recent patches/messages for leaked secrets
- ``git.changelog``   — release tags cross-checked against CHANGELOG.md
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from . import CollectorError, Evidence

_SEP = "\x1f"  # unit separator: never appears in normal git metadata

# Signature status letters from `git log --pretty=%G?` that mean "a signature
# is present" (valid or not); "N" means unsigned.
_SIGNED_STATUSES = {"G", "B", "U", "X", "Y", "R", "E"}

SECRET_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    (
        "generic-credential",
        re.compile(r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"),
    ),
)


class GitCollector:
    def __init__(self, repo_path: str | Path, max_commits: int = 50):
        self.repo_path = Path(repo_path)
        self.max_commits = max_commits

    def _git(self, *args: str) -> str:
        try:
            proc = subprocess.run(
                ["git", "-C", str(self.repo_path), *args],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError as exc:  # pragma: no cover - git is a test prerequisite
            raise CollectorError("git binary not found on PATH") from exc
        if proc.returncode != 0:
            raise CollectorError(f"git {args[0]} failed: {proc.stderr.strip()[:200]}")
        return proc.stdout

    def collect_commits(self) -> Evidence:
        fmt = _SEP.join(["%H", "%an", "%ae", "%G?", "%s"])
        out = self._git("log", f"-n{self.max_commits}", f"--pretty=format:{fmt}")
        commits = []
        for line in out.splitlines():
            parts = line.split(_SEP)
            if len(parts) != 5:
                continue
            sha, author, email, sig, subject = parts
            commits.append({"hash": sha, "author": author, "signature": sig, "subject": subject})
        if not commits:
            raise CollectorError(f"no commits found in {self.repo_path}")
        signed = sum(1 for c in commits if c["signature"] in _SIGNED_STATUSES)
        payload = {
            "count": len(commits),
            "signed": signed,
            "signed_ratio": round(signed / len(commits), 3),
            "authors": sorted({c["author"] for c in commits}),
            "latest": commits[0],
        }
        return Evidence("git", "git.commits", ("ISO-A12-SIGNED",), payload)

    def collect_secret_scan(self) -> Evidence:
        out = self._git(
            "log", f"-n{self.max_commits}", "-p", "--pretty=format:COMMIT\x1e%H\x1e%B\x1e"
        )
        findings: list[dict] = []
        current = "unknown"
        scanned = 0
        # NB: split on "\n" only — str.splitlines() also breaks on \x1e,
        # the very separator the pretty-format uses.
        for line in out.split("\n"):
            if line.startswith("COMMIT\x1e"):
                current = line.split("\x1e")[1][:12]
                scanned += 1
            if line.startswith("+++") or line.startswith("---"):
                continue
            for name, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    # Never store the matched secret itself — pattern + commit only.
                    findings.append({"pattern": name, "commit": current})
        payload = {
            "commits_scanned": scanned,
            "findings": len(findings),
            "patterns": [name for name, _ in SECRET_PATTERNS],
            "details": findings[:50],
        }
        return Evidence("git", "git.secret_scan", ("ISO-A12-SECRETS",), payload)

    def collect_changelog(self, changelog_name: str = "CHANGELOG.md") -> Evidence:
        tags = [t for t in self._git("tag", "--list").splitlines() if t.strip()]
        changelog_path = self.repo_path / changelog_name
        content = changelog_path.read_text(encoding="utf-8") if changelog_path.exists() else ""
        documented = [t for t in tags if t in content or t.lstrip("v") in content]
        payload = {
            "tags": sorted(tags),
            "documented_versions": sorted(documented),
            "missing": sorted(set(tags) - set(documented)),
            "changelog_path": changelog_name,
            "changelog_exists": changelog_path.exists(),
        }
        return Evidence("git", "git.changelog", ("ISO-A5-CHANGELOG",), payload)

    def collect(self) -> list[Evidence]:
        return [self.collect_commits(), self.collect_secret_scan(), self.collect_changelog()]
