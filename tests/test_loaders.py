from pathlib import Path

from ai_security_analyzer.loaders import RepoDirectoryLoader

root_project_dir = Path(__file__).resolve().parent
test_python_dir = root_project_dir / "testdata" / "python"
test_java_dir = root_project_dir / "testdata" / "java"
test_javascript_dir = root_project_dir / "testdata" / "javascript"
test_android_dir = root_project_dir / "testdata" / "android"


def _anywhere_in_path(substring, paths):
    return any(substring in path for path in paths)


def _in_path(base_path, substring, paths):
    return any(str(Path(base_path / substring)) == str(Path(path)) for path in paths)


def test_loader_default():
    """Test default loader behavior with python project type."""
    loader = RepoDirectoryLoader(test_python_dir, "python")
    docs = loader.load()
    source_paths = [d.metadata["source"] for d in docs]
    source_paths = sorted(set(source_paths))

    assert _in_path(test_python_dir, "Dockerfile", source_paths)
    assert _in_path(test_python_dir, ".drone.yml", source_paths)
    assert _in_path(test_python_dir, ".gitlab-ci.yml", source_paths)
    assert _in_path(test_python_dir, ".circleci/config.yml", source_paths)
    assert _in_path(test_python_dir, ".jenkins/config.yml", source_paths)
    assert _in_path(test_python_dir, ".github/workflows/ci.yaml", source_paths)
    assert _in_path(test_python_dir, "README.md", source_paths)
    assert _in_path(test_python_dir, "fabric_agent_action/app.py", source_paths)
    assert _in_path(test_python_dir, "pyproject.toml", source_paths)

    assert not _anywhere_in_path(".pytest_cache", source_paths)
    assert not _anywhere_in_path(".mypy_cache", source_paths)
    assert not _anywhere_in_path(".ruff_cache", source_paths)
    assert not _anywhere_in_path(".venv", source_paths)


def test_loader_generic_project():
    """Test loader with generic project type, should include generic files."""
    loader = RepoDirectoryLoader(test_python_dir, "generic")
    docs = loader.load()
    source_paths = [d.metadata["source"] for d in docs]
    source_paths = sorted(set(source_paths))

    assert _in_path(test_python_dir, "Dockerfile", source_paths)
    assert _in_path(test_python_dir, ".drone.yml", source_paths)
    assert _in_path(test_python_dir, ".gitlab-ci.yml", source_paths)
    assert _in_path(test_python_dir, ".circleci/config.yml", source_paths)
    assert _in_path(test_python_dir, ".jenkins/config.yml", source_paths)
    assert _in_path(test_python_dir, ".github/workflows/ci.yaml", source_paths)
    assert _in_path(test_python_dir, "README.md", source_paths)
    assert _in_path(test_python_dir, "pyproject.toml", source_paths)

    assert not _in_path(test_python_dir, "app.py", source_paths)  # python files should be excluded


def test_loader_exclude_add_mode():
    """Test exclude_mode='add' with additional exclude patterns."""
    loader = RepoDirectoryLoader(test_python_dir, "python", exclude_patterns=["**/*.md"], exclude_mode="add")
    docs = loader.load()
    source_paths = [d.metadata["source"] for d in docs]
    source_paths = sorted(set(source_paths))

    assert not _in_path(test_python_dir, "README.md", source_paths)  # excluded by exclude_patterns
    assert not _in_path(test_python_dir, "LICENSE", source_paths)  # excluded by default
    assert _in_path(
        test_python_dir, "fabric_agent_action/app.py", source_paths
    )  # still included as default python include


def test_loader_exclude_override_mode():
    """Test exclude_mode='override' should only use provided exclude patterns."""
    loader = RepoDirectoryLoader(test_python_dir, "python", exclude_patterns=["**/*.md"], exclude_mode="override")
    docs = loader.load()
    source_paths = [d.metadata["source"] for d in docs]
    source_paths = sorted(set(source_paths))

    assert not _in_path(test_python_dir, "README.md", source_paths)  # excluded by exclude_patterns
    assert _in_path(
        test_python_dir, "fabric_agent_action/app.py", source_paths
    )  # still included as default python include


def test_loader_include_add_mode():
    """Test include_mode='add' with additional include patterns."""
    loader = RepoDirectoryLoader(test_python_dir, "generic", include_patterns=["**/*.txt"], include_mode="add")
    docs = loader.load()
    source_paths = [d.metadata["source"] for d in docs]
    source_paths = sorted(set(source_paths))

    assert _in_path(test_python_dir, "README.md", source_paths)  # default generic include
    assert _in_path(test_python_dir, "docs/included_file.txt", source_paths)  # included by include_patterns
    assert _in_path(test_python_dir, "docs/excluded_file.txt", source_paths)  # included by include_patterns
    assert not _in_path(
        test_python_dir, "fabric_agent_action/app.py", source_paths
    )  # not included as default generic include


def test_loader_include_override_mode():
    """Test include_mode='override' should only use provided include patterns."""
    loader = RepoDirectoryLoader(test_python_dir, "generic", include_patterns=["**/*.txt"], include_mode="override")
    docs = loader.load()
    source_paths = [d.metadata["source"] for d in docs]
    source_paths = sorted(set(source_paths))

    assert not _in_path(test_python_dir, "README.md", source_paths)  # default generic include is overridden
    assert _in_path(test_python_dir, "docs/included_file.txt", source_paths)  # included by include_patterns
    assert _in_path(test_python_dir, "docs/excluded_file.txt", source_paths)  # included by include_patterns
    assert not _in_path(test_python_dir, "fabric_agent_action/app.py", source_paths)  # not included


def test_loader_include_exclude_combined():
    """Test combination of include and exclude patterns."""
    loader = RepoDirectoryLoader(
        test_python_dir,
        "generic",
        include_patterns=["**/*.txt", "**/*.md"],
        include_mode="override",
        exclude_patterns=["**/docs/excluded*"],
        exclude_mode="add",
    )
    docs = loader.load()
    source_paths = [d.metadata["source"] for d in docs]
    source_paths = sorted(set(source_paths))

    assert _in_path(test_python_dir, "README.md", source_paths)  # included by include_patterns
    assert _in_path(test_python_dir, "docs/included_file.txt", source_paths)  # included by include_patterns
    assert not _in_path(test_python_dir, "docs/excluded_file.txt", source_paths)  # excluded by exclude_patterns
    assert not _in_path(test_python_dir, "fabric_agent_action/app.py", source_paths)  # not included by generic include


def test_loader_java_project():
    """Test loader with java project type, should include java files."""
    loader = RepoDirectoryLoader(test_java_dir, "java")
    docs = loader.load()
    source_paths = [d.metadata["source"] for d in docs]
    source_paths = sorted(set(source_paths))

    assert _in_path(test_java_dir, "dockers/Dockerfile", source_paths)
    assert _in_path(test_java_dir, "README.md", source_paths)
    assert _in_path(test_java_dir, "build.gradle", source_paths)
    assert _anywhere_in_path(
        "UserAuditingEntityEventListener.java",
        source_paths,
    )


def test_loader_android_project():
    """Test loader with android project type."""
    loader = RepoDirectoryLoader(test_android_dir, "android")
    docs = loader.load()
    source_paths = [d.metadata["source"] for d in docs]
    source_paths = sorted(set(source_paths))

    assert _in_path(test_android_dir, "README.md", source_paths)
    assert _in_path(test_android_dir, "pom.xml", source_paths)  # from java includes
    assert _in_path(
        test_android_dir, "app/src/main/java/com/termux/app/TermuxService.java", source_paths
    )  # from java includes
    assert _in_path(test_android_dir, "app/src/main/AndroidManifest.xml", source_paths)  # android specific


def test_loader_javascript_project():
    """Test loader with javascript project type."""
    loader = RepoDirectoryLoader(test_javascript_dir, "javascript")
    docs = loader.load()
    source_paths = [d.metadata["source"] for d in docs]
    source_paths = sorted(set(source_paths))

    assert _in_path(test_javascript_dir, "Dockerfile", source_paths)
    assert _in_path(test_javascript_dir, "README.md", source_paths)
    assert _in_path(test_javascript_dir, "src/index.js", source_paths)  # javascript specific
    assert _in_path(test_javascript_dir, "@types/index.d.ts", source_paths)  # javascript specific


def test_readme_load():
    loader = RepoDirectoryLoader(test_python_dir, "python")
    readme = loader.load_readme()
    assert "README.md" in readme.metadata["source"]
    assert len(readme.page_content) > 0
