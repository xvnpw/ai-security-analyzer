from pathlib import Path

from ai_security_analyzer.loaders import RepoDirectoryLoader

root_project_dir = Path(__file__).resolve().parent
test_target_dir = root_project_dir / "testdata"


def _anywhere_in_path(substring, paths):
    return any(substring in path for path in paths)


def _in_path(substring, paths):
    return any(str(Path(test_target_dir / substring)) == str(Path(path)) for path in paths)


def test_loader():

    loader = RepoDirectoryLoader(test_target_dir, "python")
    docs = loader.load()
    sourcePaths = [d.metadata["source"] for d in docs]
    sourcePaths = sorted(set(sourcePaths))

    assert _in_path("Dockerfile", sourcePaths)
    assert _in_path(".drone.yml", sourcePaths)
    assert _in_path(".gitlab-ci.yml", sourcePaths)
    assert _in_path(".circleci/config.yml", sourcePaths)
    assert _in_path(".jenkins/config.yml", sourcePaths)
    assert _in_path(".github/workflows/ci.yaml", sourcePaths)
    assert not _anywhere_in_path(".pytest_cache", sourcePaths)
    assert not _anywhere_in_path(".mypy_cache", sourcePaths)
    assert not _anywhere_in_path(".ruff_cache", sourcePaths)
    assert not _anywhere_in_path(".venv", sourcePaths)
