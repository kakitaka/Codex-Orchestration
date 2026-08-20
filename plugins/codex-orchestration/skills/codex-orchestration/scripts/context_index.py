"""Content-addressed, metadata-only repository index.

This module deliberately does not build embeddings, summaries, snippets, or
any other copy of source text.  Source bytes are read only while deriving a
Git blob ID and small structural metadata.  A requested line range is read
from the live file after the indexed blob is checked and is never inserted in
SQLite.
"""

from __future__ import annotations

import ast
import contextlib
import functools
import hashlib
import json
import ntpath
import os
import re
import sqlite3
import subprocess
import threading
import time
import warnings
from pathlib import Path
from typing import Any, Iterable, Sequence

try:  # package import
    from .safe_state import (
        StateCorruptError,
        UnsafePathError,
        normalize_relative_path,
        quarantine_file,
        read_bytes,
        resolve_state_path,
    )
except ImportError:  # direct script/module import
    from safe_state import (  # type: ignore
        StateCorruptError,
        UnsafePathError,
        normalize_relative_path,
        quarantine_file,
        read_bytes,
        resolve_state_path,
    )


INDEX_FORMAT_VERSION = 1
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS index_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY,
    blob_id TEXT NOT NULL,
    language TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS headings (
    path TEXT NOT NULL,
    level INTEGER NOT NULL,
    name TEXT NOT NULL,
    line INTEGER NOT NULL,
    FOREIGN KEY(path) REFERENCES files(path) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS symbols (
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    line INTEGER NOT NULL,
    FOREIGN KEY(path) REFERENCES files(path) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS dependencies (
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    FOREIGN KEY(path) REFERENCES files(path) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS adr_playbooks (
    path TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    validated_at TEXT NOT NULL,
    source_files TEXT NOT NULL,
    FOREIGN KEY(path) REFERENCES files(path) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS headings_name ON headings(name);
CREATE INDEX IF NOT EXISTS symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS dependencies_name ON dependencies(name);
"""
DEFAULT_SOURCE_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_QUERY_LIMIT = 50
MAX_REPOSITORY_PATH_BYTES = 8 * 1024 * 1024
MAX_REPOSITORY_FILES = 20_000
MAX_REPOSITORY_WARNING_LENGTH = 192
MAX_METADATA_ITEMS_PER_KIND = 2_048
MAX_RESULT_ITEMS_PER_KIND = 64
_HASH_RE = re.compile(r"^[0-9a-fA-F]{40,128}$")
_HEADING_RE = re.compile(r"^ {0,3}(#{1,6})\s+(.+?)\s*$")
_PY_SYMBOL_KINDS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_PY_IMPORT_KINDS = (ast.Import, ast.ImportFrom)
_PATH_FORBIDDEN = re.compile(r"[\x00\r\n]")
_QUERY_TOKEN_RE = re.compile(r"[^\w.:%_-]+", re.UNICODE)
_EXCLUDED_COMPONENTS = frozenset(
    {
        ".git",
        ".codex-state",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "target",
        "generated",
        "__pycache__",
    }
)
_EXCLUDED_NAMES = frozenset(
    {
        ".env",
        "cargo.lock",
        "go.sum",
        "package-lock.json",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "yarn.lock",
        "credentials.json",
        "secrets.json",
        "secrets.yaml",
        "secrets.yml",
    }
)
_BINARY_SUFFIXES = frozenset(
    {
        ".7z",
        ".bin",
        ".dll",
        ".exe",
        ".gif",
        ".gz",
        ".ico",
        ".jar",
        ".jpeg",
        ".jpg",
        ".pdf",
        ".png",
        ".pyc",
        ".so",
        ".tar",
        ".webp",
        ".zip",
        ".key",
        ".p12",
        ".pem",
        ".pfx",
    }
)
_DB_LOCKS: dict[str, threading.RLock] = {}
_DB_LOCKS_GUARD = threading.RLock()


class ContextIndexError(ValueError):
    """Base error for metadata index operations."""


class InvalidSourceEncoding(ContextIndexError):
    """A source file is not valid UTF-8 and cannot be structurally indexed."""


class StaleIndexError(ContextIndexError):
    """A live source file no longer has the blob recorded in the index."""


class CorruptIndexError(ContextIndexError):
    """SQLite state was corrupt and had to be quarantined/rebuilt."""


class RepeatedReadError(ContextIndexError):
    """The same live blob/range was already returned in this index session."""


def git_blob_id(data: bytes) -> str:
    """Return the Git SHA-1 blob ID for bytes without invoking Git."""

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _db_lock(path: str) -> threading.RLock:
    with _DB_LOCKS_GUARD:
        return _DB_LOCKS.setdefault(path, threading.RLock())


def _schema_signature(connection: sqlite3.Connection) -> tuple[tuple[str, ...], ...]:
    """Return the exact user table/index definition without row content."""

    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%' "
        "ORDER BY type, name"
    )
    return tuple(
        (
            str(row[0]),
            str(row[1]),
            str(row[2]),
            re.sub(r"\s+", " ", str(row[3]).strip()).casefold(),
        )
        for row in rows
    )


@functools.lru_cache(maxsize=1)
def _expected_schema_signature() -> tuple[tuple[str, ...], ...]:
    with contextlib.closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(_SCHEMA_SQL)
        return _schema_signature(connection)


def _clean_text(value: Any, *, field: str, max_length: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ContextIndexError(f"invalid {field}")
    if _PATH_FORBIDDEN.search(value):
        raise ContextIndexError(f"invalid characters in {field}")
    return value


def _clean_hash(value: Any, *, field: str) -> str:
    text = _clean_text(value, field=field, max_length=128).lower()
    if _HASH_RE.fullmatch(text) is None:
        raise ContextIndexError(f"invalid {field}")
    return text


def _language_for(path: str) -> str:
    suffix = Path(path).suffix.lower()
    return {
        ".py": "python",
        ".pyi": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".md": "markdown",
        ".markdown": "markdown",
        ".json": "json",
        ".toml": "toml",
        ".yaml": "yaml",
        ".yml": "yaml",
    }.get(suffix, "text")


def _indexable_path(path: str) -> bool:
    pure = Path(path.replace("\\", "/"))
    lowered_parts = tuple(part.lower() for part in pure.parts)
    name = pure.name.lower()
    if any(part in _EXCLUDED_COMPONENTS for part in lowered_parts[:-1]):
        return False
    if name in _EXCLUDED_NAMES or pure.suffix.lower() in _BINARY_SUFFIXES:
        return False
    if name.endswith((".min.js", ".min.css")):
        return False
    return True


def _headings(lines: Sequence[str]) -> list[tuple[int, str, int]]:
    result: list[tuple[int, str, int]] = []
    for line_number, line in enumerate(lines, 1):
        match = _HEADING_RE.match(line)
        if not match:
            continue
        name = match.group(2).strip()
        name = re.sub(r"\s+#+\s*$", "", name).strip()
        if name:
            result.append((len(match.group(1)), name[:512], line_number))
    return result


def _python_metadata(text: str) -> tuple[list[tuple[str, str, int]], list[str]]:
    symbols: list[tuple[str, str, int]] = []
    imports: list[str] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                symbols.append((node.name, "class", int(node.lineno)))
            elif isinstance(node, ast.AsyncFunctionDef):
                symbols.append((node.name, "async_function", int(node.lineno)))
            elif isinstance(node, ast.FunctionDef):
                symbols.append((node.name, "function", int(node.lineno)))
            elif isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)
    else:
        # A malformed Python file still contributes safe, derived import names.
        for match in re.finditer(r"^\s*(?:import|from)\s+([A-Za-z_][\w.]*)", text, re.MULTILINE):
            imports.append(match.group(1))
        for match in re.finditer(
            r"^\s*(?:async\s+def|def|class)\s+([A-Za-z_]\w*)", text, re.MULTILINE
        ):
            kind = "class" if text[match.start() :].lstrip().startswith("class") else "function"
            symbols.append((match.group(1), kind, text.count("\n", 0, match.start()) + 1))
    return symbols, imports


def _generic_metadata(text: str, language: str) -> tuple[list[tuple[str, str, int]], list[str]]:
    symbols: list[tuple[str, str, int]] = []
    imports: list[str] = []
    patterns = [
        (r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)", "function"),
        (r"^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)", "class"),
        (r"^\s*func\s+([A-Za-z_]\w*)", "function"),
        (r"^\s*(?:pub\s+)?fn\s+([A-Za-z_]\w*)", "function"),
        (r"^\s*(?:public\s+)?class\s+([A-Za-z_]\w*)", "class"),
    ]
    for line_number, line in enumerate(text.splitlines(), 1):
        for pattern, kind in patterns:
            match = re.match(pattern, line)
            if match:
                symbols.append((match.group(1), kind, line_number))
        import_match = re.match(
            r"^\s*(?:import|require\s*\(|use\s+|#include\s*[<\"])([A-Za-z0-9_./@:-]+)",
            line,
        )
        if import_match:
            imports.append(import_match.group(1).rstrip("\">)"))
    return symbols, imports


def _line_metadata(data: bytes, path: str) -> tuple[str, list[tuple[int, str, int]], list[tuple[str, str, int]], list[str], str]:
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise InvalidSourceEncoding(path) from exc
    language = _language_for(path)
    lines = text.splitlines()
    # Markdown headings are structural metadata.  A leading ``#`` in Python
    # or shell source is a comment, not a heading; retaining that comment
    # would accidentally preserve arbitrary source text.
    headings = _headings(lines) if language == "markdown" else []
    if language == "python":
        symbols, imports = _python_metadata(text)
    else:
        symbols, imports = _generic_metadata(text, language)
    if language in {"text", "toml", "yaml", "json"}:
        # Requirements and simple dependency files still have useful names.
        if Path(path).name.lower() in {"requirements.txt", "pyproject.toml", "package.json"}:
            imports.extend(
                match.group(1)
                for match in re.finditer(r"^\s*([A-Za-z][A-Za-z0-9_.-]{1,127})", text, re.MULTILINE)
            )
    headings = headings[:MAX_METADATA_ITEMS_PER_KIND]
    symbols = sorted(set(symbols), key=lambda item: (item[2], item[1], item[0]))[
        :MAX_METADATA_ITEMS_PER_KIND
    ]
    imports = sorted({item[:256] for item in imports if item}, key=str.casefold)[
        :MAX_METADATA_ITEMS_PER_KIND
    ]
    return language, headings, symbols, imports, text


def _artifact_metadata(path: str, headings: Sequence[tuple[int, str, int]]) -> tuple[str, str, str, str, str] | None:
    lower = path.lower()
    components = lower.split("/")
    stem = Path(path).stem.lower()
    is_adr = any(component in {"adr", "adrs", "architecture-decision-records"} for component in components[:-1]) or stem.startswith("adr-") or stem.startswith("adr_")
    is_playbook = any(component in {"playbook", "playbooks"} for component in components[:-1]) or "playbook" in stem
    if not (is_adr or is_playbook):
        return None
    kind = "adr" if is_adr else "playbook"
    title = next((heading[1] for heading in headings if heading[0] == 1), Path(path).stem)
    status = ""
    validated_at = ""
    source_files: list[str] = []
    # Only front-matter scalar metadata is retained.  The body remains absent.
    # The caller passes text separately when it wants these fields; defaults
    # here make the metadata table safe even when no front matter is present.
    return kind, title[:512], status, validated_at, json.dumps(source_files, separators=(",", ":"))


def _parse_artifact_frontmatter(
    text: str,
    path: str,
    headings: Sequence[tuple[int, str, int]],
) -> tuple[str, str, str, str, str] | None:
    metadata = _artifact_metadata(path, headings)
    if metadata is None:
        return None
    kind, title, status, validated_at, source_files_json = metadata
    lines = text.splitlines()
    if lines and lines[0].strip() == "---":
        for line in lines[1:]:
            if line.strip() == "---":
                break
            key, separator, raw_value = line.partition(":")
            if not separator:
                continue
            key = key.strip().lower()
            value = raw_value.strip().strip("'\"")
            if len(value) > 512 or _PATH_FORBIDDEN.search(value):
                continue
            if key == "title" and value:
                title = value
            elif key == "status" and value.lower() in {"confirmed", "provisional", "stale", "draft"}:
                status = value.lower()
            elif key in {"validated_at", "validated"} and value:
                validated_at = value[:128]
            elif key in {"source_files", "sources"}:
                values = [part.strip() for part in value.strip("[]").split(",") if part.strip()]
                normalized: list[str] = []
                for part in values:
                    try:
                        normalized.append(normalize_relative_path(part.strip("'\"")))
                    except UnsafePathError:
                        continue
                source_files_json = json.dumps(sorted(set(normalized)), separators=(",", ":"))
    return kind, title[:512], status, validated_at, source_files_json


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _query_terms(query: str) -> list[str]:
    if not isinstance(query, str) or "\x00" in query:
        raise ContextIndexError("query must be valid text")
    if len(query) > 512:
        raise ContextIndexError("query exceeds bound")
    return [term for term in _QUERY_TOKEN_RE.split(query.strip()) if term][:16]


class ContextIndex:
    """SQLite metadata index scoped to one repository root."""

    def __init__(
        self,
        repo_root: os.PathLike[str] | str,
        db_path: os.PathLike[str] | str | None = None,
        *,
        source_max_bytes: int = DEFAULT_SOURCE_MAX_BYTES,
        query_limit: int = DEFAULT_QUERY_LIMIT,
    ) -> None:
        self.repo_root = os.path.abspath(os.fspath(repo_root))
        self.source_max_bytes = int(source_max_bytes)
        self.query_limit = int(query_limit)
        if self.source_max_bytes <= 0 or self.query_limit <= 0 or self.query_limit > 1000:
            raise ValueError("invalid index bounds")
        self.db_target = db_path if db_path is not None else os.path.join(".codex-state", "context", "index.sqlite")
        self.db_path = resolve_state_path(self.repo_root, self.db_target, create_parents=True)
        self._lock = _db_lock(self.db_path)
        self._connection = self._open_connection_with_recovery()
        self._live_reads: set[tuple[str, str, int, int]] = set()
        self._repository_status: dict[str, Any] = {
            "status": "not_started",
            "tracked_files": 0,
            "warning": None,
        }
        self._initialize_schema_with_recovery()

    @property
    def repository_status(self) -> dict[str, Any]:
        """Return the bounded status from the latest repository discovery."""

        return dict(self._repository_status)

    def _repository_discovery_failed(self, error: BaseException) -> list[dict[str, Any]]:
        warning = f"context_index: git ls-files unavailable ({type(error).__name__})"
        warning = warning[:MAX_REPOSITORY_WARNING_LENGTH]
        self._repository_status = {
            "status": "unavailable",
            "tracked_files": 0,
            "warning": warning,
        }
        warnings.warn(warning, RuntimeWarning, stacklevel=2)
        return []

    def _connect(self) -> sqlite3.Connection:
        self.db_path = resolve_state_path(
            self.repo_root, self.db_target, create_parents=True
        )
        connection = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA foreign_keys=ON")
            with contextlib.suppress(OSError):
                os.chmod(self.db_path, 0o600)
            return connection
        except Exception:
            # On Windows a failed PRAGMA can leave the handle open.  Close it
            # before quarantine tries to move a corrupt database aside.
            with contextlib.suppress(Exception):
                connection.close()
            raise

    def _open_connection_with_recovery(self) -> sqlite3.Connection:
        try:
            connection = self._connect()
            connection.execute("PRAGMA schema_version")
            return connection
        except (sqlite3.DatabaseError, OSError):
            with contextlib.suppress(Exception):
                connection.close()  # type: ignore[name-defined]
            with contextlib.suppress(Exception):
                quarantine_file(self.repo_root, self.db_target, suffix="sqlite-corrupt")
            return self._connect()

    def _create_schema(self) -> None:
        with self._lock:
            existing_signature = _schema_signature(self._connection)
            if (
                existing_signature
                and existing_signature != _expected_schema_signature()
            ):
                raise CorruptIndexError("context index logical schema mismatch")
            if existing_signature:
                meta_rows = [
                    (str(row[0]), str(row[1]))
                    for row in self._connection.execute(
                        "SELECT key, value FROM index_meta ORDER BY key"
                    )
                ]
                if meta_rows != [("format_version", str(INDEX_FORMAT_VERSION))]:
                    raise CorruptIndexError("context index format version mismatch")
            self._connection.executescript(_SCHEMA_SQL)
            if not existing_signature:
                self._connection.execute(
                    "INSERT INTO index_meta(key, value) VALUES (?, ?)",
                    ("format_version", str(INDEX_FORMAT_VERSION)),
                )

    def _initialize_schema_with_recovery(self) -> None:
        try:
            self._create_schema()
        except (CorruptIndexError, sqlite3.DatabaseError, OSError) as exc:
            try:
                self._connection.close()
            except Exception as close_error:
                raise CorruptIndexError(
                    "context index schema mismatch and database could not be closed"
                ) from close_error
            quarantined = quarantine_file(
                self.repo_root,
                self.db_target,
                suffix="sqlite-schema",
            )
            if quarantined is None:
                raise CorruptIndexError(
                    "context index schema mismatch and database could not be quarantined"
                ) from exc
            self._connection = self._connect()
            self._create_schema()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "ContextIndex":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _safe_relative(self, path: os.PathLike[str] | str) -> str:
        raw = os.fspath(path)
        if isinstance(raw, str) and (os.path.isabs(raw) or ntpath.isabs(raw) or ntpath.splitdrive(raw)[0]):
            validated = resolve_state_path(self.repo_root, raw, create_parents=False)
            raw = os.path.relpath(validated, self.repo_root).replace(os.sep, "/")
        return normalize_relative_path(raw)

    def _read_source(self, relative_path: str) -> bytes:
        return read_bytes(self.repo_root, relative_path, max_bytes=self.source_max_bytes)

    def _replace_metadata(
        self,
        relative_path: str,
        blob_id: str,
        language: str,
        headings: Sequence[tuple[int, str, int]],
        symbols: Sequence[tuple[str, str, int]],
        imports: Sequence[str],
        artifact: tuple[str, str, str, str, str] | None,
    ) -> None:
        for attempt in range(4):
            try:
                with self._lock:
                    self._connection.execute("BEGIN IMMEDIATE")
                    try:
                        self._connection.execute("DELETE FROM files WHERE path = ?", (relative_path,))
                        self._connection.execute(
                            "INSERT INTO files(path, blob_id, language) VALUES (?, ?, ?)",
                            (relative_path, blob_id, language),
                        )
                        self._connection.executemany(
                            "INSERT INTO headings(path, level, name, line) VALUES (?, ?, ?, ?)",
                            ((relative_path, level, name, line) for level, name, line in headings),
                        )
                        self._connection.executemany(
                            "INSERT INTO symbols(path, name, kind, line) VALUES (?, ?, ?, ?)",
                            ((relative_path, name, kind, line) for name, kind, line in symbols),
                        )
                        self._connection.executemany(
                            "INSERT INTO dependencies(path, name) VALUES (?, ?)",
                            ((relative_path, name) for name in imports),
                        )
                        if artifact is not None:
                            self._connection.execute(
                                "INSERT INTO adr_playbooks(path, kind, title, status, validated_at, source_files) "
                                "VALUES (?, ?, ?, ?, ?, ?)",
                                (relative_path, *artifact),
                            )
                        self._connection.execute("COMMIT")
                    except Exception:
                        self._connection.execute("ROLLBACK")
                        raise
                return
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or attempt == 3:
                    raise
                time.sleep(0.05 * (attempt + 1))

    def index_file(self, path: os.PathLike[str] | str) -> dict[str, Any]:
        """Derive and persist metadata for one contained, non-link file."""

        relative_path = self._safe_relative(path)
        if not _indexable_path(relative_path):
            raise ContextIndexError("source path is excluded from the metadata index")
        data = self._read_source(relative_path)
        blob_id = git_blob_id(data)
        language, headings, symbols, imports, text = _line_metadata(data, relative_path)
        artifact = _parse_artifact_frontmatter(text, relative_path, headings)
        self._replace_metadata(relative_path, blob_id, language, headings, symbols, imports, artifact)
        return {
            "path": relative_path,
            "blob_id": blob_id,
            "language": language,
            "heading_count": len(headings),
            "symbol_count": len(symbols),
            "dependency_count": len(imports),
        }

    def remove(self, path: os.PathLike[str] | str) -> None:
        relative_path = self._safe_relative(path)
        with self._lock:
            self._connection.execute("DELETE FROM files WHERE path = ?", (relative_path,))

    def invalidate_by_blob(self, path: os.PathLike[str] | str, blob_id: str) -> bool:
        relative_path = self._safe_relative(path)
        blob_id = _clean_hash(blob_id, field="blob_id")
        with self._lock:
            row = self._connection.execute(
                "SELECT blob_id FROM files WHERE path = ?", (relative_path,)
            ).fetchone()
            if row is None or row[0] == blob_id:
                return False
            self._connection.execute("DELETE FROM files WHERE path = ?", (relative_path,))
            return True

    def invalidate_stale(self, paths: Iterable[os.PathLike[str] | str] | None = None) -> list[str]:
        """Drop rows whose live blob no longer matches the recorded blob."""

        if paths is None:
            with self._lock:
                rows = self._connection.execute("SELECT path, blob_id FROM files").fetchall()
            candidates = [(str(row[0]), str(row[1])) for row in rows]
        else:
            candidates = []
            for path in paths:
                relative_path = self._safe_relative(path)
                with self._lock:
                    row = self._connection.execute(
                        "SELECT blob_id FROM files WHERE path = ?", (relative_path,)
                    ).fetchone()
                if row is not None:
                    candidates.append((relative_path, str(row[0])))
        stale: list[str] = []
        for relative_path, expected in candidates:
            try:
                actual = git_blob_id(self._read_source(relative_path))
            except (OSError, StateCorruptError, UnsafePathError, InvalidSourceEncoding):
                actual = ""
            if actual != expected:
                self.remove(relative_path)
                stale.append(relative_path)
        return stale

    def query(self, query: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        """Search metadata using escaped, parameterized LIKE predicates."""

        terms = _query_terms(query)
        if not terms:
            return []
        effective_limit = self.query_limit if limit is None else int(limit)
        if effective_limit <= 0 or effective_limit > 1000:
            raise ValueError("invalid query limit")
        clauses: list[str] = []
        parameters: list[str] = []
        for term in terms:
            pattern = f"%{_escape_like(term)}%"
            clauses.append(
                "(f.path LIKE ? ESCAPE '\\' OR f.language LIKE ? ESCAPE '\\' OR "
                "EXISTS (SELECT 1 FROM headings h WHERE h.path=f.path AND h.name LIKE ? ESCAPE '\\') OR "
                "EXISTS (SELECT 1 FROM symbols s WHERE s.path=f.path AND s.name LIKE ? ESCAPE '\\') OR "
                "EXISTS (SELECT 1 FROM dependencies d WHERE d.path=f.path AND d.name LIKE ? ESCAPE '\\') OR "
                "EXISTS (SELECT 1 FROM adr_playbooks a WHERE a.path=f.path AND "
                "(a.title LIKE ? ESCAPE '\\' OR a.status LIKE ? ESCAPE '\\'))"
                ")"
            )
            parameters.extend([pattern] * 7)
        sql = (
            "SELECT f.path, f.blob_id, f.language FROM files f WHERE "
            + " AND ".join(clauses)
            + " ORDER BY f.path LIMIT ?"
        )
        parameters.append(str(effective_limit))
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        return [self._result_for_path(str(row[0]), str(row[1]), str(row[2]), query) for row in rows]

    def _result_for_path(self, path: str, blob_id: str, language: str, query: str) -> dict[str, Any]:
        with self._lock:
            headings = self._connection.execute(
                "SELECT level, name, line FROM headings WHERE path = ? ORDER BY line LIMIT ?",
                (path, MAX_RESULT_ITEMS_PER_KIND),
            ).fetchall()
            symbols = self._connection.execute(
                "SELECT name, kind, line FROM symbols WHERE path = ? ORDER BY line, name LIMIT ?",
                (path, MAX_RESULT_ITEMS_PER_KIND),
            ).fetchall()
            imports = self._connection.execute(
                "SELECT name FROM dependencies WHERE path = ? ORDER BY name LIMIT ?",
                (path, MAX_RESULT_ITEMS_PER_KIND),
            ).fetchall()
            artifact = self._connection.execute(
                "SELECT kind, title, status, validated_at, source_files FROM adr_playbooks WHERE path = ?",
                (path,),
            ).fetchone()
        result: dict[str, Any] = {
            "path": path,
            "blob_id": blob_id,
            "language": language,
            "headings": [
                {"level": int(row[0]), "name": str(row[1]), "line": int(row[2])} for row in headings
            ],
            "symbols": [
                {"name": str(row[0]), "kind": str(row[1]), "line": int(row[2])} for row in symbols
            ],
            "imports": [str(row[0]) for row in imports],
            "score": self._score_result(path, query, headings, symbols, imports),
        }
        if artifact is not None:
            try:
                source_files = json.loads(str(artifact[4]))
                if not isinstance(source_files, list):
                    source_files = []
            except (TypeError, ValueError, json.JSONDecodeError):
                source_files = []
            result["artifact"] = {
                "kind": str(artifact[0]),
                "title": str(artifact[1]),
                "status": str(artifact[2]),
                "validated_at": str(artifact[3]),
                "source_files": source_files,
            }
        return result

    @staticmethod
    def _score_result(path: str, query: str, headings: Sequence[sqlite3.Row], symbols: Sequence[sqlite3.Row], imports: Sequence[sqlite3.Row]) -> int:
        terms = [term.casefold() for term in _query_terms(query)]
        score = sum(term in path.casefold() for term in terms) * 2
        score += sum(any(term in str(row[1]).casefold() for term in terms) for row in headings) * 3
        score += sum(any(term in str(row[0]).casefold() for term in terms) for row in symbols) * 3
        score += sum(any(term in str(row[0]).casefold() for term in terms) for row in imports)
        return int(score)

    def fetch_lines(
        self,
        path: os.PathLike[str] | str,
        start_line: int,
        end_line: int,
        *,
        deduplicate: bool = False,
    ) -> list[str]:
        """Read an explicitly requested live range after blob verification."""

        relative_path = self._safe_relative(path)
        if type(start_line) is not int or type(end_line) is not int:
            raise ValueError("line bounds must be integers")
        if start_line < 1 or end_line < start_line or end_line - start_line > 1000:
            raise ValueError("invalid line range")
        data = self._read_source(relative_path)
        actual_blob = git_blob_id(data)
        with self._lock:
            row = self._connection.execute(
                "SELECT blob_id FROM files WHERE path = ?", (relative_path,)
            ).fetchone()
        if row is None or str(row[0]) != actual_blob:
            if row is not None:
                self.remove(relative_path)
            raise StaleIndexError(relative_path)
        read_key = (relative_path, actual_blob, start_line, end_line)
        if deduplicate and read_key in self._live_reads:
            raise RepeatedReadError(relative_path)
        try:
            text = data.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise InvalidSourceEncoding(relative_path) from exc
        result = text.splitlines(keepends=True)[start_line - 1 : end_line]
        if deduplicate:
            self._live_reads.add(read_key)
        return result

    def fetch_line_range(self, path: os.PathLike[str] | str, start_line: int, end_line: int) -> list[str]:
        return self.fetch_lines(path, start_line, end_line)

    def fetch_once(
        self, path: os.PathLike[str] | str, start_line: int, end_line: int
    ) -> list[str]:
        return self.fetch_lines(path, start_line, end_line, deduplicate=True)

    def indexed_blob(self, path: os.PathLike[str] | str) -> str | None:
        relative_path = self._safe_relative(path)
        with self._lock:
            row = self._connection.execute(
                "SELECT blob_id FROM files WHERE path = ?", (relative_path,)
            ).fetchone()
        return None if row is None else str(row[0])

    def index_paths(self, paths: Iterable[os.PathLike[str] | str]) -> list[dict[str, Any]]:
        return [self.index_file(path) for path in paths]

    def index_repository(self) -> list[dict[str, Any]]:
        """Index Git-tracked regular files, excluding local state and binaries."""

        try:
            completed = subprocess.run(
                ["git", "-C", self.repo_root, "ls-files", "-z"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            if len(completed.stdout) > MAX_REPOSITORY_PATH_BYTES:
                raise ContextIndexError("tracked path list exceeds bound")
            paths = [item for item in completed.stdout.decode("utf-8", "strict").split("\0") if item]
            if len(paths) > MAX_REPOSITORY_FILES:
                raise ContextIndexError("tracked file count exceeds bound")
        except (ContextIndexError, OSError, subprocess.SubprocessError, UnicodeDecodeError) as exc:
            # Git is the authority for repository scope.  A failed discovery
            # must never widen scope to an arbitrary filesystem walk.
            return self._repository_discovery_failed(exc)
        self._repository_status = {
            "status": "ok",
            "tracked_files": len(paths),
            "warning": None,
        }
        indexed: list[dict[str, Any]] = []
        for path in sorted(set(paths)):
            if path.startswith(".codex-state/") or path.startswith(".git/"):
                continue
            try:
                indexed.append(self.index_file(path))
            except (OSError, StateCorruptError, UnsafePathError, InvalidSourceEncoding, ContextIndexError):
                continue
        return indexed


KnowledgeIndex = ContextIndex
MetadataIndex = ContextIndex
blob_id_for_bytes = git_blob_id


def build_context_index(
    repo_root: os.PathLike[str] | str,
    paths: Iterable[os.PathLike[str] | str] | None = None,
    *,
    db_path: os.PathLike[str] | str | None = None,
) -> list[dict[str, Any]]:
    """Build one index using the small class API for script callers."""

    with ContextIndex(repo_root, db_path=db_path) as context:
        return context.index_repository() if paths is None else context.index_paths(paths)


def fetch_live_lines(
    index: ContextIndex,
    path: os.PathLike[str] | str,
    start_line: int,
    end_line: int,
) -> list[str]:
    return index.fetch_lines(path, start_line, end_line)


__all__ = [
    "ContextIndex",
    "ContextIndexError",
    "CorruptIndexError",
    "InvalidSourceEncoding",
    "KnowledgeIndex",
    "MetadataIndex",
    "RepeatedReadError",
    "StaleIndexError",
    "blob_id_for_bytes",
    "build_context_index",
    "fetch_live_lines",
    "git_blob_id",
]
