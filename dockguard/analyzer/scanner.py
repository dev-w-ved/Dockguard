"""Safe local and public git repository acquisition."""
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

class RepositoryScanner:
    """Acquire a repository, yielding a temporary checkout for remote sources."""
    def __init__(self, source: str, timeout: int = 120):
        self.source = source if isinstance(source, str) else ""
        self.timeout = timeout

    @staticmethod
    def is_public_git_url(value: str) -> bool:
        try:
            parsed = urlparse(value)
            return parsed.scheme in ("https", "http", "ssh", "git") and bool(parsed.netloc)
        except (TypeError, ValueError):
            return False

    @contextmanager
    def checkout(self) -> Iterator[Path]:
        if not self.source:
            raise ValueError("repository source is required")
        local = Path(self.source).expanduser().resolve()
        if local.exists():
            if not local.is_dir():
                raise ValueError("repository path must be a directory")
            yield local
            return
        if not self.is_public_git_url(self.source):
            raise ValueError("source is not an existing directory or public git URL")
        temp = Path(tempfile.mkdtemp(prefix="dockguard-repo-"))
        try:
            target = temp / "repo"
            command = ["git", "clone", "--depth", "1", "--no-tags", self.source, str(target)]
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=self.timeout)
            yield target
        except FileNotFoundError as exc:
            raise RuntimeError("git is required to scan a remote repository") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or "clone failed").strip()[-500:]
            raise RuntimeError("git clone failed: " + detail) from exc
        finally:
            shutil.rmtree(temp, ignore_errors=True)
