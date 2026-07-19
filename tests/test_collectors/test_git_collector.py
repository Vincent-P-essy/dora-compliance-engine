import re

import pytest

from engine.collectors import CollectorError, canonical_json
from engine.collectors.git_collector import GitCollector


def test_collect_commits_metadata(git_repo):
    evidence = GitCollector(git_repo).collect_commits()
    assert evidence.type == "git.commits"
    assert evidence.control_ids == ("ISO-A12-SIGNED",)
    assert evidence.payload["count"] == 2
    assert evidence.payload["authors"] == ["Test Dev"]
    assert evidence.payload["signed"] == 0  # gpgsign disabled in the fixture
    assert evidence.payload["signed_ratio"] == 0.0
    assert evidence.payload["latest"]["subject"] == "docs: add changelog"


def test_commits_error_on_repo_without_commits(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(CollectorError):
        GitCollector(empty).collect_commits()


def test_secret_scan_clean_history(git_repo):
    evidence = GitCollector(git_repo).collect_secret_scan()
    assert evidence.payload["findings"] == 0
    assert evidence.payload["commits_scanned"] == 2
    assert evidence.payload["details"] == []


def test_secret_scan_detects_planted_aws_key(git_repo):
    leaked = 'aws_access = "AKIAIOSFODNN7EXAMPLE"\n'
    (git_repo / "settings.py").write_text(leaked, encoding="utf-8")
    git_repo.git("add", ".")
    git_repo.git("commit", "-q", "-m", "oops: config")

    evidence = GitCollector(git_repo).collect_secret_scan()
    assert evidence.payload["findings"] >= 1
    assert any(d["pattern"] == "aws-access-key" for d in evidence.payload["details"])
    # The vault must never store the secret itself — only pattern + commit.
    assert "AKIAIOSFODNN7EXAMPLE" not in canonical_json(evidence.payload)


def test_changelog_all_releases_documented(git_repo):
    evidence = GitCollector(git_repo).collect_changelog()
    assert evidence.payload["tags"] == ["v1.0.0"]
    assert evidence.payload["missing"] == []
    assert evidence.payload["changelog_exists"] is True


def test_changelog_flags_undocumented_release(git_repo):
    (git_repo / "feature.py").write_text("x = 1\n", encoding="utf-8")
    git_repo.git("add", ".")
    git_repo.git("commit", "-q", "-m", "feat: v2 feature")
    git_repo.git("tag", "v2.0.0")

    evidence = GitCollector(git_repo).collect_changelog()
    assert evidence.payload["missing"] == ["v2.0.0"]
    assert "v1.0.0" in evidence.payload["documented_versions"]


def test_collect_returns_three_hashed_evidences(git_repo):
    evidences = GitCollector(git_repo).collect()
    assert [e.type for e in evidences] == ["git.commits", "git.secret_scan", "git.changelog"]
    for evidence in evidences:
        assert re.fullmatch(r"[0-9a-f]{64}", evidence.digest())
