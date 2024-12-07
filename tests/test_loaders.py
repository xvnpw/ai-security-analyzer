from pathlib import Path

from ai_security_analyzer.loaders import RepoDirectoryLoader


def _in_path(substring, paths):
    return any(substring in path for path in paths)


def test_loader():
    root_project_dir = Path(__file__).resolve().parent
    test_target_dir = root_project_dir / "testdata"

    loader = RepoDirectoryLoader(test_target_dir, "python")
    docs = loader.load()
    sourcePaths = [d.metadata["source"] for d in docs]
    sourcePaths = sorted(set(sourcePaths))

    assert _in_path("ci.yaml", sourcePaths)
    assert _in_path("Dockerfile", sourcePaths)
    assert not _in_path(".pytest_cache", sourcePaths)
    assert not _in_path(".mypy_cache", sourcePaths)
    assert not _in_path(".ruff_cache", sourcePaths)
    assert not _in_path(".venv", sourcePaths)
