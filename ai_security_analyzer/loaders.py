import logging
from pathlib import Path
from typing import Any, Iterator, List, Optional, Type
import fnmatch

import concurrent
from typing_extensions import Literal
from langchain_community.document_loaders import DirectoryLoader, PythonLoader
from langchain_community.document_loaders.text import TextLoader
from langchain_core.documents import Document

logger = logging.getLogger(__name__)

# Map file extensions to loader classes
LOADERS: dict[str, Type[Any]] = {
    ".py": PythonLoader,
    ".md": TextLoader,
    ".txt": TextLoader,
}

GENERIC_FILES_GLOB = ["**/*.md", "**/Dockerfile", "**/*.yml", "**/*.sh", "**/*.bash", "**/*.yaml", "**/*.toml"]
PYTHON_FILES_GLOB = ["**/*.py", "pyproject.toml", "requirements.txt"]
GO_FILES_GLOB = ["**/*.go", "**/go.mod", "Makefile"]
JAVA_FILES_GLOB = [
    "**/*.java",
    "**/pom.xml",
    "**/build.gradle",
    "**/*.properties",
]

ANDROID_FILES_GLOB = ["**/AndroidManifest.xml", "**/proguard-rules.pro", "**/*.kts", "**/*.kt"]

JAVASCRIPT_FILES_GLOB = ["**/*.js", "**/*.ts"]

FILES_GLOB: dict[str, List[str]] = {
    "generic": GENERIC_FILES_GLOB,
    "python": GENERIC_FILES_GLOB + PYTHON_FILES_GLOB,
    "go": GENERIC_FILES_GLOB + GO_FILES_GLOB,
    "java": GENERIC_FILES_GLOB + JAVA_FILES_GLOB,
    "android": GENERIC_FILES_GLOB + JAVA_FILES_GLOB + ANDROID_FILES_GLOB,
    "javascript": GENERIC_FILES_GLOB + JAVASCRIPT_FILES_GLOB,
}

DEFAULT_EXCLUDE = ["LICENSE", "**/dist/**", "**/bin/**", "**/build/**", "**/node_modules/**", "**/lib/**", "**/libs/**"]


def _is_visible(p: Path) -> bool:
    return not any(part.startswith(".") for part in p.parts)


# function to check if the file is ci/cd related, e.g. github actions, gitlab ci, etc.
def _is_ci_cd(p: Path) -> bool:
    CICD = [".github", ".gitlab", ".circleci", ".jenkins", ".drone", ".gitlab-ci", ".drone.yml"]
    return any(p.parts[0].startswith(cicd) for cicd in CICD)


class RepoDirectoryLoader(DirectoryLoader):
    """Custom directory loader for repository files."""

    def __init__(
        self,
        path: str,
        project_type: str,
        exclude_patterns: Optional[List[str]] = None,
        exclude_mode: Literal["add", "override"] = "add",
        include_patterns: Optional[List[str]] = None,
        include_mode: Literal["add", "override"] = "add",
    ):
        if exclude_mode == "add":
            exclude = DEFAULT_EXCLUDE + (exclude_patterns or [])
        elif exclude_mode == "override":
            exclude = exclude_patterns or []
        else:
            raise ValueError(f"Invalid exclude_mode: {exclude_mode}")

        logger.info(f"exclude config: mode={exclude_mode}, patterns={exclude}")

        if include_mode == "add":
            include = FILES_GLOB[project_type] + (include_patterns or [])
        elif include_mode == "override":
            include = include_patterns or []
        else:
            raise ValueError(f"Invalid include_mode: {include_mode}")

        logger.info(f"include config: mode={include_mode}, patterns={include}")

        super().__init__(path, glob=include, exclude=exclude)

    def load_readme(self) -> Document:
        """Load documents lazily."""
        p = Path(self.path)
        if not p.exists():
            raise FileNotFoundError(f"Directory not found: '{self.path}'")
        if not p.is_dir():
            raise ValueError(f"Expected directory, got file: '{self.path}'")

        readme_path = p / "README.md"
        if not readme_path.exists():
            raise FileNotFoundError(f"README.md not found in directory: '{self.path}'")

        loader = TextLoader(str(readme_path))
        docs = loader.load()
        if len(docs) == 0:
            raise ValueError(f"No documents found in README.md: '{self.path}'")
        return docs[0]

    def lazy_load(self) -> Iterator[Document]:
        """Load documents lazily."""
        p = Path(self.path)
        if not p.exists():
            raise FileNotFoundError(f"Directory not found: '{self.path}'")
        if not p.is_dir():
            raise ValueError(f"Expected directory, got file: '{self.path}'")

        # Glob multiple patterns if a list is provided
        if isinstance(self.glob, (list, tuple)):
            paths = []
            for pattern in self.glob:
                paths.extend(list(p.rglob(pattern) if self.recursive else p.glob(pattern)))
        elif isinstance(self.glob, str):
            paths = list(p.rglob(self.glob) if self.recursive else p.glob(self.glob))
        else:
            raise TypeError(f"Expected glob to be str or sequence of str, but got {type(self.glob)}")

        # Filter out excluded files using fnmatch.fnmatch
        if self.exclude:
            paths = [path for path in paths if not any(fnmatch.fnmatch(str(path), pattern) for pattern in self.exclude)]
        else:
            paths = [path for path in paths]

        pbar = None
        if self.show_progress:
            try:
                from tqdm import tqdm

                pbar = tqdm(total=len(paths))
            except ImportError as e:
                logger.warning("To log the progress of DirectoryLoader you need to install tqdm, " "`pip install tqdm`")
                if self.silent_errors:
                    logger.warning(e)
                else:
                    raise ImportError(
                        "To log the progress of DirectoryLoader " "you need to install tqdm, " "`pip install tqdm`"
                    )

        if self.use_multithreading:
            futures = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrency) as executor:
                for i in paths:
                    futures.append(
                        executor.submit(
                            self._lazy_load_file_to_non_generator(self._lazy_load_file),
                            i,
                            p,
                            pbar,
                        )
                    )
                for future in concurrent.futures.as_completed(futures):
                    for item in future.result():
                        yield item
        else:
            for i in paths:
                yield from self._lazy_load_file(i, p, pbar)

        if pbar:
            pbar.close()

    def _lazy_load_file(self, item: Path, path: Path, pbar: Optional[Any]) -> Iterator[Document]:
        """Load a file lazily.

        Args:
            item: File path.
            path: Directory path.
            pbar: Progress bar. Defaults to None.
        """
        if item.is_file():
            relative_path = item.relative_to(path)
            if _is_visible(relative_path) or self.load_hidden or _is_ci_cd(relative_path):
                try:
                    logger.debug(f"Processing file: {str(item)}")
                    loader_cls = LOADERS.get(item.suffix, TextLoader)
                    loader = loader_cls(str(item), **self.loader_kwargs)
                    try:
                        for subdoc in loader.lazy_load():
                            yield subdoc
                    except NotImplementedError:
                        for subdoc in loader.load():
                            yield subdoc
                except Exception as e:
                    if self.silent_errors:
                        logger.warning(f"Error loading file {str(item)}: {e}")
                    else:
                        logger.error(f"Error loading file {str(item)}")
                        raise e
                finally:
                    if pbar:
                        pbar.update(1)
