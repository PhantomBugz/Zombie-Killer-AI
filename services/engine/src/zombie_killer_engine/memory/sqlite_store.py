"""Schema-derived SQLite Memory Vault adapter without caller-supplied SQL."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import tempfile
import time
from contextlib import closing, suppress
from datetime import datetime
from pathlib import Path
from typing import Literal, cast
from urllib.parse import quote

from pydantic import ValidationError

from zombie_killer_engine.memory.base import (
    FileIdentity,
    JsonValue,
    MemoryError,
    MemoryReceipt,
    MemoryRecord,
    MemoryStateStore,
    MutationKind,
    MutationOperation,
    MutationPlan,
    NamespaceInventory,
    ProbeResult,
    QueryFilter,
    QueryPage,
    Snapshot,
    SnapshotStatus,
    VaultCapabilities,
    VaultFormat,
    VaultSource,
    canonical_hash,
    capture_file_security,
    exclusive_file_lock,
    fsync_directory,
    identity_from_stat,
    new_plan,
    new_restore_plan,
    path_binding,
    prepare_backup_directory,
    read_pinned,
    read_prefix_pinned,
    same_identity,
    secure_created_file,
    sha256_bytes,
    source_id,
    utc_now,
    validate_local_file_path,
    validate_write_deadline,
    verify_authority,
    verify_plan,
    verify_write_deadline,
)

_SUPPORTED_TYPES = {"INTEGER", "INT", "REAL", "FLOAT", "DOUBLE", "TEXT", "BLOB", "NUMERIC"}
_EMBEDDING_NAMES = {"embedding", "embeddings", "vector", "vectors"}


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _declared_type(value: str) -> str:
    return value.strip().upper().split("(", 1)[0].split(" ", 1)[0]


def _safe_scalar(value: object) -> JsonValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {"blob_sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
    raise MemoryError("SQLite row contains an unsupported runtime value")


def _hashable_scalar(value: object) -> object:
    if isinstance(value, bytes):
        return {"blob_sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
    return value


class SQLiteMemoryAdapter:
    """Browse known schema objects and mutate only a derived single-PK allowlist."""

    def __init__(
        self,
        path: Path,
        *,
        backups_dir: Path,
        state_store: MemoryStateStore,
        max_bytes: int = 512 * 1024 * 1024,
        max_rows: int = 10_000,
        busy_timeout_ms: int = 2_000,
        operation_timeout_seconds: float = 10.0,
    ) -> None:
        if not 4096 <= max_bytes <= 4 * 1024 * 1024 * 1024:
            raise ValueError("max_bytes is outside the supported bound")
        if not 1 <= max_rows <= 100_000:
            raise ValueError("max_rows is outside the supported bound")
        if not 0 <= busy_timeout_ms <= 30_000:
            raise ValueError("busy_timeout_ms is outside the supported bound")
        if not 0.0001 <= operation_timeout_seconds <= 300:
            raise ValueError("operation_timeout_seconds is outside the supported bound")
        validate_local_file_path(path)
        prepare_backup_directory(backups_dir)
        self.path = path
        self.backups_dir = backups_dir
        self.max_bytes = max_bytes
        self.max_rows = max_rows
        self.busy_timeout_ms = busy_timeout_ms
        self.operation_timeout_seconds = operation_timeout_seconds
        self._state_store = state_store
        self._read_only = False
        self._applied_plans: set[str] = set()
        detected = self.probe(path)
        self._recognized_format = detected.format
        self._state_store.register_vault_source(
            VaultSource(
                source_id=source_id(path),
                path=str(path),
                format=detected.format,
                capabilities=detected.capabilities,
                revision=self.current_revision(),
            )
        )
        if self._recognized_format is VaultFormat.SQLITE:
            self._reconcile_interrupted()

    @classmethod
    def probe(cls, path: Path) -> ProbeResult:
        validate_local_file_path(path)
        prefix, _identity = read_prefix_pinned(path, prefix_bytes=4096)
        if not prefix.startswith(b"SQLite format 3\x00"):
            return ProbeResult(
                format=VaultFormat.UNSUPPORTED,
                recognized=False,
                capabilities=VaultCapabilities(reason="SQLite header was not found"),
                reason="SQLite header was not found",
            )
        names: set[str] = set()
        restore_reason: str | None = "SQLite restore schema could not be verified"
        try:
            uri = cls._uri_for(path, "ro")
            with closing(sqlite3.connect(uri, uri=True, timeout=1.0)) as connection:
                connection.execute("PRAGMA query_only = ON")
                connection.execute("PRAGMA trusted_schema = OFF")
                names = {
                    str(row[0]).casefold()
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                restore_reason = cls._restore_schema_reason(connection)
        except sqlite3.Error:
            pass
        is_chroma = {"collections", "embeddings"}.issubset(names)
        format = VaultFormat.CHROMA if is_chroma else VaultFormat.SQLITE
        reason = "recognized Chroma layout is inventory-only" if is_chroma else restore_reason
        return ProbeResult(
            format=format,
            recognized=True,
            capabilities=VaultCapabilities(
                readable=True,
                queryable=not is_chroma,
                editable=not is_chroma,
                snapshot=not is_chroma,
                restore=not is_chroma and restore_reason is None,
                reason=reason,
            ),
            reason=reason,
        )

    @staticmethod
    def _uri_for(path: Path, mode: str) -> str:
        normalized = str(path).replace("\\", "/")
        return f"file:{quote(normalized, safe='/:')}?mode={mode}"

    def _configure(self, connection: sqlite3.Connection, *, read_only: bool) -> None:
        connection.row_factory = sqlite3.Row
        connection.enable_load_extension(False)
        bounded_busy = min(
            self.busy_timeout_ms,
            max(1, int(self.operation_timeout_seconds * 1000)),
        )
        connection.execute(f"PRAGMA busy_timeout = {bounded_busy}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        if read_only:
            connection.execute("PRAGMA query_only = ON")
        setlimit = getattr(connection, "setlimit", None)
        if setlimit is not None:
            for category, value in (
                (getattr(sqlite3, "SQLITE_LIMIT_LENGTH", 0), min(self.max_bytes, 16 * 1024 * 1024)),
                (getattr(sqlite3, "SQLITE_LIMIT_SQL_LENGTH", 1), 1_048_576),
                (getattr(sqlite3, "SQLITE_LIMIT_COLUMN", 2), 512),
                (getattr(sqlite3, "SQLITE_LIMIT_EXPR_DEPTH", 3), 100),
                (getattr(sqlite3, "SQLITE_LIMIT_COMPOUND_SELECT", 4), 50),
                (getattr(sqlite3, "SQLITE_LIMIT_ATTACHED", 7), 0),
            ):
                setlimit(category, value)
        deadline = time.monotonic() + self.operation_timeout_seconds
        connection.set_progress_handler(
            lambda: 1 if time.monotonic() >= deadline else 0,
            100,
        )

    def _backup_database(self, source: sqlite3.Connection, target: sqlite3.Connection) -> None:
        deadline = time.monotonic() + self.operation_timeout_seconds

        def check_deadline(_status: int, _remaining: int, _total: int) -> None:
            if time.monotonic() >= deadline:
                raise MemoryError("SQLite backup exceeded its operation deadline")

        try:
            source.backup(target, pages=128, progress=check_deadline, sleep=0.0)
        except sqlite3.Error as error:
            raise MemoryError("SQLite backup failed safely") from error

    def _connect_read_only(self, path: Path | None = None) -> sqlite3.Connection:
        selected = path or self.path
        try:
            connection = sqlite3.connect(
                self._uri_for(selected, "ro"),
                uri=True,
                timeout=self.busy_timeout_ms / 1000,
                isolation_level=None,
            )
            self._configure(connection, read_only=True)
            return connection
        except sqlite3.Error as error:
            raise MemoryError("SQLite vault could not be opened read-only") from error

    def _connect_read_write(self, path: Path | None = None) -> sqlite3.Connection:
        selected = path or self.path
        try:
            connection = sqlite3.connect(
                self._uri_for(selected, "rw"),
                uri=True,
                timeout=self.busy_timeout_ms / 1000,
                isolation_level=None,
            )
            self._configure(connection, read_only=False)
            return connection
        except sqlite3.Error as error:
            raise MemoryError("SQLite vault could not be opened for a transaction") from error

    def open(self, *, read_only: bool) -> SQLiteMemoryAdapter:
        if self._recognized_format is VaultFormat.CHROMA and not read_only:
            raise MemoryError("recognized Chroma storage is read-only and inventory-only")
        self._read_only = read_only
        self.healthcheck()
        return self

    def _reject_active_wal(self) -> None:
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.path}{suffix}")
            if os.path.lexists(sidecar):
                validate_local_file_path(sidecar)
        try:
            with closing(self._connect_read_write()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.rollback()
        except MemoryError:
            raise
        except sqlite3.Error as error:
            raise MemoryError("active SQLite writer prevents exclusive maintenance") from error

    def _inventory(self, connection: sqlite3.Connection) -> tuple[NamespaceInventory, ...]:
        try:
            rows = connection.execute(
                "SELECT name, type, sql FROM sqlite_master "
                "WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name"
            ).fetchall()
        except sqlite3.Error as error:
            raise MemoryError("SQLite schema inventory failed") from error
        result: list[NamespaceInventory] = []
        for row in rows:
            name = str(row["name"])
            kind = cast(str, row["type"])
            sql = str(row["sql"] or "")
            try:
                columns = connection.execute(
                    f"PRAGMA table_xinfo({_quote_identifier(name)})"
                ).fetchall()
            except sqlite3.Error as error:
                raise MemoryError("SQLite column inventory failed") from error
            visible = [column for column in columns if int(column[6]) == 0]
            column_names = tuple(str(column[1]) for column in visible)
            pk_columns = sorted(
                ((int(column[5]), str(column[1])) for column in visible if int(column[5]) > 0),
                key=lambda item: item[0],
            )
            supported = all(
                _declared_type(str(column[2])) in _SUPPORTED_TYPES for column in visible
            )
            virtual = sql.lstrip().upper().startswith("CREATE VIRTUAL TABLE")
            pk_declared_type = next(
                (_declared_type(str(column[2])) for column in visible if int(column[5]) == 1),
                "",
            )
            editable = (
                kind == "table"
                and not virtual
                and len(pk_columns) == 1
                and supported
                and pk_declared_type != "BLOB"
            )
            if kind != "table":
                reason = "views are inventory-only"
            elif virtual:
                reason = "virtual tables are read-only"
            elif len(pk_columns) != 1:
                reason = "table requires exactly one declared primary key"
            elif not supported:
                reason = "table contains unsupported declared column types"
            elif pk_declared_type == "BLOB":
                reason = "BLOB primary-key tables are browse-only"
            else:
                reason = None
            result.append(
                NamespaceInventory(
                    name=name,
                    kind=cast(Literal["table", "view"], kind),
                    columns=column_names,
                    primary_key=pk_columns[0][1] if len(pk_columns) == 1 else None,
                    editable=editable,
                    reason=reason,
                )
            )
        return tuple(result)

    def inventory(self) -> tuple[NamespaceInventory, ...]:
        with closing(self._connect_read_only()) as connection:
            return self._inventory(connection)

    def list_namespaces(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.inventory())

    def _revision_parts(self) -> tuple[str, FileIdentity]:
        try:
            for suffix in ("-wal", "-shm"):
                sidecar = Path(f"{self.path}{suffix}")
                if os.path.lexists(sidecar):
                    validate_local_file_path(sidecar)
            with closing(self._connect_read_only()) as connection:
                schema_version = int(connection.execute("PRAGMA schema_version").fetchone()[0])
                page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
                data, identity = read_pinned(self.path, max_bytes=self.max_bytes)
                wal_values: list[object] = []
                # The WAL is durable database state.  The SHM file is transient lock/index
                # coordination and can be handle-locked by an innocent reader on Windows;
                # writer exclusion below probes SQLite's actual locking protocol instead.
                for suffix in ("-wal",):
                    sidecar = Path(f"{self.path}{suffix}")
                    if not os.path.lexists(sidecar):
                        wal_values.append(None)
                        continue
                    side_data, side_identity = read_pinned(sidecar, max_bytes=self.max_bytes)
                    if not side_data:
                        wal_values.append(None)
                        continue
                    wal_values.append(
                        {
                            "hash": sha256_bytes(side_data),
                            "size": side_identity.size,
                            "inode": side_identity.inode,
                        }
                    )
        except sqlite3.Error as error:
            raise MemoryError("SQLite revision metadata could not be read") from error
        revision = canonical_hash(
            {
                "file_hash": sha256_bytes(data),
                "identity": identity.model_dump(mode="json"),
                "schema_version": schema_version,
                "page_count": page_count,
                "sidecars": wal_values,
            }
        )
        return revision, identity

    def current_revision(self) -> str:
        self._reject_active_wal()
        revision, source_identity = self._revision_parts()
        return revision

    def _namespace(
        self, connection: sqlite3.Connection, namespace: str | None
    ) -> NamespaceInventory:
        inventory = self._inventory(connection)
        if namespace is None:
            for item in inventory:
                if item.kind == "table":
                    return item
            raise MemoryError("SQLite vault contains no browsable table namespaces")
        for item in inventory:
            if item.name == namespace:
                if item.kind != "table":
                    raise MemoryError("SQLite views are inventory-only and not queryable")
                return item
        raise MemoryError("SQLite namespace was not found")

    def _rows(
        self, connection: sqlite3.Connection, item: NamespaceInventory
    ) -> tuple[sqlite3.Row, ...]:
        order_columns = (
            (item.primary_key,)
            + tuple(column for column in item.columns if column != item.primary_key)
            if item.primary_key is not None
            else item.columns
        )
        order = " ORDER BY " + ", ".join(
            f"{_quote_identifier(column)} COLLATE BINARY" for column in order_columns
        )
        try:
            cursor = connection.execute(
                f"SELECT * FROM {_quote_identifier(item.name)}{order} LIMIT ?",
                (self.max_rows + 1,),
            )
            rows: list[sqlite3.Row] = []
            aggregate = 0
            while True:
                batch = cursor.fetchmany(128)
                if not batch:
                    break
                for row in batch:
                    row_size = 0
                    for value in row:
                        if isinstance(value, str):
                            cell_size = len(value.encode("utf-8"))
                        elif isinstance(value, bytes):
                            cell_size = len(value)
                        else:
                            cell_size = 8
                        if cell_size > min(self.max_bytes, 1_048_576):
                            raise MemoryError("SQLite cell exceeds configured byte limit")
                        row_size += cell_size
                    aggregate += row_size
                    if aggregate > min(self.max_bytes, 16 * 1024 * 1024):
                        raise MemoryError("SQLite rows exceed aggregate byte limit")
                    rows.append(row)
        except MemoryError:
            raise
        except (sqlite3.Error, UnicodeError, ValueError) as error:
            raise MemoryError("SQLite namespace browse failed") from error
        if len(rows) > self.max_rows:
            raise MemoryError("SQLite browse exceeds configured row limit")
        return tuple(rows)

    def _record(
        self,
        item: NamespaceInventory,
        row: sqlite3.Row,
        revision: str,
        fallback_index: int,
    ) -> MemoryRecord:
        if item.primary_key is not None:
            pk = row[item.primary_key]
            token = self._encode_pk(pk)
        else:
            token = f"row-{fallback_index}"
        record_id = f"{item.name}:{token}"
        if len(record_id) > 256:
            raise MemoryError("SQLite record id exceeds configured bound")
        content_column = next(
            (name for name in item.columns if name.casefold() in {"content", "text", "document"}),
            None,
        )
        content_value = row[content_column] if content_column is not None else ""
        content = (
            content_value
            if isinstance(content_value, str)
            else json.dumps(_safe_scalar(content_value), sort_keys=True, separators=(",", ":"))
        )
        metadata: dict[str, JsonValue] = {}
        embedding_present = False
        for name in item.columns:
            if name == content_column or name == item.primary_key:
                continue
            if name.casefold() in _EMBEDDING_NAMES:
                embedding_present = embedding_present or row[name] is not None
                continue
            metadata[name] = _safe_scalar(row[name])
        try:
            return MemoryRecord(
                record_id=record_id,
                namespace=item.name,
                content=content,
                metadata=metadata,
                embedding_present=embedding_present,
                source_revision=revision,
            )
        except (ValidationError, UnicodeError, ValueError, TypeError) as error:
            raise MemoryError("SQLite row validation failed") from error

    @staticmethod
    def _matches(record: MemoryRecord, filter: QueryFilter | None) -> bool:
        if filter is None:
            return True
        if filter.ids and record.record_id not in filter.ids:
            return False
        if filter.text is not None:
            rendered = (
                record.record_id
                + "\n"
                + record.content
                + "\n"
                + json.dumps(record.metadata, sort_keys=True)
            )
            if filter.text.casefold() not in rendered.casefold():
                return False
        if any(record.metadata.get(key) != value for key, value in filter.metadata.items()):
            return False
        tags = record.metadata.get("tags", record.metadata.get("tag", []))
        available = {str(item) for item in tags} if isinstance(tags, list) else {str(tags)}
        return not filter.tags or set(filter.tags).issubset(available)

    def query(
        self,
        *,
        cursor: str | None = None,
        limit: int = 100,
        filter: QueryFilter | None = None,
        namespace: str | None = None,
    ) -> QueryPage:
        if self._recognized_format is VaultFormat.CHROMA:
            raise MemoryError("recognized Chroma storage is inventory-only and not queryable")
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        try:
            offset = int(cursor or "0")
        except ValueError as error:
            raise MemoryError("query cursor is invalid") from error
        if offset < 0:
            raise MemoryError("query cursor is invalid")
        revision = self.current_revision()
        with closing(self._connect_read_only()) as connection:
            item = self._namespace(connection, namespace)
            rows = self._rows(connection, item)
        records = [self._record(item, row, revision, index) for index, row in enumerate(rows)]
        filtered = [record for record in records if self._matches(record, filter)]
        page = tuple(filtered[offset : offset + limit])
        next_offset = offset + len(page)
        return QueryPage(
            records=page,
            next_cursor=str(next_offset) if next_offset < len(filtered) else None,
            total=len(filtered),
        )

    def get(self, record_id: str) -> MemoryRecord:
        if self._recognized_format is VaultFormat.CHROMA:
            raise MemoryError("recognized Chroma storage is inventory-only and not queryable")
        namespace, separator, token = record_id.partition(":")
        if not separator:
            raise MemoryError("SQLite record id is invalid")
        revision = self.current_revision()
        with closing(self._connect_read_only()) as connection:
            item = self._namespace(connection, namespace)
            if item.primary_key is None:
                raise MemoryError("SQLite namespace has no direct record identity")
            pk = self._decode_pk(token)
            operator = "IS" if pk is None else "="
            row = connection.execute(
                f"SELECT * FROM {_quote_identifier(item.name)} "
                f"WHERE {_quote_identifier(item.primary_key)} {operator} ? LIMIT 2",
                (pk,),
            ).fetchall()
        if len(row) != 1:
            raise MemoryError("SQLite record was not found or was not unique")
        return self._record(item, row[0], revision, 0)

    @staticmethod
    def _encode_pk(value: object) -> str:
        if value is None:
            return "n:"
        if isinstance(value, bool):
            return f"i:{int(value)}"
        if isinstance(value, int):
            return f"i:{value}"
        if isinstance(value, float):
            return "r:" + value.hex()
        if isinstance(value, str):
            encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")
            return "s:" + encoded.rstrip("=")
        if isinstance(value, bytes):
            return "b:" + base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
        raise MemoryError("SQLite primary key has an unsupported runtime type")

    @staticmethod
    def _decode_pk(token: str) -> object:
        kind, separator, payload = token.partition(":")
        if not separator or (not payload and kind != "n"):
            raise MemoryError("SQLite typed primary-key token is invalid")
        try:
            if kind == "n" and not payload:
                value: object = None
            elif kind == "i":
                value = int(payload)
            elif kind == "r":
                value = float.fromhex(payload)
            elif kind in {"s", "b"}:
                padded = payload + "=" * (-len(payload) % 4)
                decoded = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
                value = decoded.decode("utf-8") if kind == "s" else decoded
            else:
                raise MemoryError("SQLite typed primary-key token type is unsupported")
        except (ValueError, UnicodeError) as error:
            raise MemoryError("SQLite typed primary-key token is invalid") from error
        if SQLiteMemoryAdapter._encode_pk(value) != token:
            raise MemoryError("SQLite typed primary-key token is not canonical")
        return value

    def _parse_target(
        self, connection: sqlite3.Connection, operation: MutationOperation
    ) -> tuple[NamespaceInventory, str, object, str, object, str]:
        table_name, separator, token = operation.record_id.partition(":")
        if not separator:
            raise MemoryError("SQLite record id is invalid")
        item = self._namespace(connection, table_name)
        if not item.editable or item.primary_key is None:
            raise MemoryError("SQLite namespace is read-only and not editable")
        column_info = connection.execute(
            f"PRAGMA table_xinfo({_quote_identifier(item.name)})"
        ).fetchall()
        declarations = {str(row[1]): _declared_type(str(row[2])) for row in column_info}
        pk = self._decode_pk(token)
        if operation.kind is MutationKind.UPDATE_CONTENT:
            field = next(
                (
                    name
                    for name in item.columns
                    if name.casefold() in {"content", "text", "document"}
                ),
                "",
            )
        elif operation.kind is MutationKind.UPDATE_FIELD:
            field = cast(str, operation.field)
        elif operation.kind is MutationKind.UPDATE_METADATA:
            field = cast(str, operation.metadata_key)
        elif operation.kind is MutationKind.EXCLUDE:
            field = "excluded_from_retrieval"
        elif operation.kind in {MutationKind.QUARANTINE, MutationKind.RESTORE_RECORD}:
            field = "zombie_killer_quarantined"
        else:
            field = ""
        if (
            not field
            or field not in item.columns
            or field == item.primary_key
            or field.casefold() in _EMBEDDING_NAMES
        ):
            raise MemoryError("SQLite mutation field is not in the editable schema allowlist")
        value = operation.unsealed_value()
        if operation.kind in {MutationKind.EXCLUDE, MutationKind.QUARANTINE}:
            value = 1
        elif operation.kind is MutationKind.RESTORE_RECORD:
            value = 0
        if declarations[field] == "BLOB" and not isinstance(value, bytes):
            raise MemoryError("SQLite BLOB updates require bytes")
        operator = "IS" if pk is None else "="
        query = (
            f"SELECT * FROM {_quote_identifier(item.name)} "
            f"WHERE {_quote_identifier(item.primary_key)} {operator} ?"
        )
        rows = connection.execute(query + " LIMIT 2", (pk,)).fetchall()
        if len(rows) != 1:
            raise MemoryError("SQLite record was not found or was not unique")
        row = rows[0]
        row_hash = canonical_hash({name: _hashable_scalar(row[name]) for name in item.columns})
        return item, field, pk, item.primary_key, row[field], row_hash

    def _logical_hash(self, connection: sqlite3.Connection) -> str:
        inventory = self._inventory(connection)
        payload: list[object] = []
        for item in inventory:
            if item.kind != "table":
                continue
            rows = self._rows(connection, item)
            payload.append(
                {
                    "table": item.name,
                    "columns": item.columns,
                    "rows": [
                        [_hashable_scalar(row[name]) for name in item.columns] for row in rows
                    ],
                }
            )
        sequence = []
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'"
        ).fetchone():
            sequence = [
                tuple(row)
                for row in connection.execute(
                    "SELECT name,seq FROM sqlite_sequence ORDER BY name COLLATE BINARY"
                )
            ]
        return canonical_hash(
            {
                "schema": self._schema_signature(connection),
                "tables": payload,
                "sequence": sequence,
                "user_version": int(connection.execute("PRAGMA user_version").fetchone()[0]),
                "application_id": int(connection.execute("PRAGMA application_id").fetchone()[0]),
            }
        )

    @staticmethod
    def _schema_signature(connection: sqlite3.Connection) -> str:
        return canonical_hash(
            [
                tuple(row)
                for row in connection.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
                )
            ]
        )

    @staticmethod
    def _restore_schema_reason(connection: sqlite3.Connection) -> str | None:
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='trigger' LIMIT 1"
        ).fetchone():
            return "SQLite restore is unavailable for databases with triggers"
        for row in connection.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"):
            name, sql = str(row[0]), str(row[1] or "")
            if name.startswith("sqlite_"):
                continue
            if sql.lstrip().upper().startswith("CREATE VIRTUAL TABLE"):
                return "SQLite restore is unavailable for virtual tables"
            columns = connection.execute(
                f"PRAGMA table_xinfo({_quote_identifier(name)})"
            ).fetchall()
            if any(int(column[6]) != 0 for column in columns):
                return "SQLite restore is unavailable for generated or hidden columns"
            if any(_declared_type(str(column[2])) not in _SUPPORTED_TYPES for column in columns):
                return "SQLite restore is unavailable for unsupported declared column types"
        return None

    def _execute_update(
        self,
        connection: sqlite3.Connection,
        operation: MutationOperation,
        *,
        expected_old_hash: str | None,
        expected_record_hash: str | None = None,
    ) -> tuple[object, object, str, str]:
        item, field, pk, pk_field, old, record_hash = self._parse_target(connection, operation)
        if expected_record_hash is not None and record_hash != expected_record_hash:
            raise MemoryError("SQLite record identity changed before apply")
        if (
            expected_old_hash is not None
            and canonical_hash(_hashable_scalar(old)) != expected_old_hash
        ):
            raise MemoryError("SQLite field changed before apply")
        value: object = operation.unsealed_value()
        if operation.kind in {MutationKind.EXCLUDE, MutationKind.QUARANTINE}:
            value = 1
        elif operation.kind is MutationKind.RESTORE_RECORD:
            value = 0
        before_changes = connection.total_changes
        operator = "IS" if pk is None else "="
        cursor = connection.execute(
            f"UPDATE {_quote_identifier(item.name)} SET {_quote_identifier(field)} = ? "
            f"WHERE {_quote_identifier(pk_field)} {operator} ?",
            (value, pk),
        )
        changed = connection.total_changes - before_changes
        if cursor.rowcount != 1 or changed != 1:
            raise MemoryError("SQLite update or trigger changed more than one row")
        row = connection.execute(
            f"SELECT {_quote_identifier(field)} FROM {_quote_identifier(item.name)} "
            f"WHERE {_quote_identifier(pk_field)} {operator} ?",
            (pk,),
        ).fetchone()
        if row is None:
            raise MemoryError("SQLite updated row disappeared")
        return old, row[0], field, record_hash

    def _temporary_clone(self) -> Path:
        destination: Path | None = None
        try:
            descriptor, name = tempfile.mkstemp(
                prefix=".zombie-killer-plan-",
                suffix=".sqlite3",
                dir=self.backups_dir,
            )
            os.close(descriptor)
            destination = Path(name)
            os.chmod(destination, 0o600)
            secure_created_file(destination)
            with (
                closing(self._connect_read_only()) as source,
                closing(self._connect_read_write(destination)) as target,
            ):
                self._backup_database(source, target)
        except MemoryError:
            if destination is not None:
                with suppress(OSError):
                    destination.unlink(missing_ok=True)
            raise
        except OSError as error:
            if destination is not None:
                with suppress(OSError):
                    destination.unlink(missing_ok=True)
            raise MemoryError("SQLite planning clone failed safely") from error
        except BaseException:
            if destination is not None:
                with suppress(OSError):
                    destination.unlink(missing_ok=True)
            raise
        if destination is None:
            raise MemoryError("SQLite planning clone was not created")
        return destination

    def plan_mutation(
        self, operation: MutationOperation, *, expected_revision: str
    ) -> MutationPlan:
        if self._read_only:
            raise MemoryError("SQLite vault was opened read-only")
        if self._recognized_format is VaultFormat.CHROMA:
            raise MemoryError("recognized Chroma storage is read-only")
        self._reject_active_wal()
        revision, identity = self._revision_parts()
        if revision != expected_revision:
            raise MemoryError("SQLite revision or WAL state changed before planning")
        clone = self._temporary_clone()
        try:
            with closing(self._connect_read_write(clone)) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    old_store_hash = self._logical_hash(connection)
                    old, new, field, record_hash = self._execute_update(
                        connection, operation, expected_old_hash=None
                    )
                    new_store_hash = self._logical_hash(connection)
                finally:
                    connection.rollback()
        finally:
            try:
                clone.unlink(missing_ok=True)
            except OSError as error:
                raise MemoryError("SQLite planning clone cleanup failed safely") from error
        plan = new_plan(
            source=self.path,
            revision=revision,
            identity=identity,
            operation=operation,
            record_hash=record_hash,
            field_name=field,
            old_hash=canonical_hash(_hashable_scalar(old)),
            old_store_hash=old_store_hash,
            new_hash=canonical_hash(_hashable_scalar(new)),
            new_store_hash=new_store_hash,
        )
        self._state_store.save_memory_plan(plan)
        return plan

    def _check_database(self, path: Path) -> None:
        with closing(self._connect_read_only(path)) as connection:
            try:
                integrity = connection.execute("PRAGMA integrity_check").fetchall()
                foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
            except sqlite3.Error as error:
                raise MemoryError("SQLite healthcheck failed") from error
        if [str(row[0]) for row in integrity] != ["ok"]:
            raise MemoryError("SQLite integrity_check failed")
        if foreign_keys:
            raise MemoryError("SQLite foreign_key_check failed")

    def backup(self, *, expected_revision: str) -> Snapshot:
        if self._recognized_format is VaultFormat.CHROMA:
            raise MemoryError("recognized Chroma storage is read-only; snapshots are unsupported")
        snapshot_id = "memory-snapshot-" + secrets.token_hex(16)
        destination = self.backups_dir / f"{snapshot_id}.sqlite3.snapshot"
        complete = False
        try:
            with closing(self._connect_read_write()) as maintenance:
                try:
                    maintenance.execute("BEGIN IMMEDIATE")
                except sqlite3.Error as error:
                    raise MemoryError("active SQLite writer prevents snapshot") from error
                try:
                    revision, source_identity = self._revision_parts()
                    if revision != expected_revision:
                        raise MemoryError("SQLite revision changed before snapshot")
                    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    os.close(descriptor)
                    secure_created_file(destination)
                    with (
                        closing(self._connect_read_only()) as source,
                        closing(self._connect_read_write(destination)) as target,
                    ):
                        self._backup_database(source, target)
                    with destination.open("r+b") as snapshot_file:
                        os.fsync(snapshot_file.fileno())
                    fsync_directory(self.backups_dir)
                    self._check_database(destination)
                    copied, _copied_identity = read_pinned(destination, max_bytes=self.max_bytes)
                    post_revision, post_identity = self._revision_parts()
                    if post_revision != revision or post_identity != source_identity:
                        raise MemoryError("SQLite source changed during snapshot")
                    snapshot = Snapshot(
                        snapshot_id=snapshot_id,
                        source_id=source_id(self.path),
                        source_path_binding=path_binding(self.path),
                        source_revision=revision,
                        source_identity=source_identity,
                        digest=sha256_bytes(copied),
                        size=len(copied),
                        backup_identity=_copied_identity,
                        backup_path=str(destination),
                        status=SnapshotStatus.VERIFIED,
                        created_at=utc_now(),
                    )
                    self._state_store.save_memory_snapshot(snapshot)
                    complete = True
                finally:
                    if maintenance.in_transaction:
                        maintenance.rollback()
        except MemoryError:
            raise
        except (OSError, sqlite3.Error) as error:
            raise MemoryError("SQLite snapshot file operation failed safely") from error
        except BaseException:
            raise
        finally:
            if not complete:
                with suppress(OSError):
                    destination.unlink(missing_ok=True)
        if not complete:
            raise MemoryError("SQLite snapshot was not completed")
        return snapshot

    def snapshot(self, snapshot_id: str) -> Snapshot:
        if self._recognized_format is VaultFormat.CHROMA:
            raise MemoryError("recognized Chroma storage is read-only; snapshots are unsupported")
        snapshot = self._state_store.get_memory_snapshot(snapshot_id)
        if snapshot is None:
            raise MemoryError("snapshot was not found")
        return snapshot

    def apply(self, plan: MutationPlan) -> MemoryReceipt:
        if self._read_only:
            raise MemoryError("SQLite vault was opened read-only")
        if self._recognized_format is VaultFormat.CHROMA:
            raise MemoryError("recognized Chroma storage is read-only")
        verify_plan(plan)
        authority = self._state_store.claim_memory_plan(plan.plan_id, expected_digest=plan.digest)
        try:
            verify_authority(plan, authority)
        except BaseException:
            self._state_store.fail_memory_plan(plan.plan_id, interrupted=False)
            raise
        try:
            receipt = self._apply_claimed(plan)
        except BaseException:
            interrupted = True
            try:
                with closing(self._connect_read_only()) as connection:
                    interrupted = self._logical_hash(connection) != plan.old_store_hash
            except BaseException:
                interrupted = True
            try:
                self._state_store.fail_memory_plan(plan.plan_id, interrupted=interrupted)
            except Exception:
                raise MemoryError(
                    "SQLite mutation journal is unavailable; reconciliation is required"
                ) from None
            raise
        self._applied_plans.add(plan.plan_id)
        return receipt

    def _apply_claimed(self, plan: MutationPlan) -> MemoryReceipt:
        if plan.plan_id in self._applied_plans:
            raise MemoryError("mutation plan replay was rejected")
        if plan.source_id != source_id(self.path):
            raise MemoryError("mutation plan is bound to another vault")
        self._reject_active_wal()
        with exclusive_file_lock(self.path):
            revision, identity = self._revision_parts()
            if revision != plan.source_revision:
                raise MemoryError("SQLite revision changed before apply")
            if identity != plan.source_identity:
                raise MemoryError("SQLite file identity changed before apply")
            source_security = capture_file_security(self.path)
            snapshot = self.backup(expected_revision=revision)
            self._verified_snapshot_model(snapshot)
            self._state_store.update_memory_plan_phase(
                plan.plan_id,
                "snapshot_verified",
                snapshot_id=snapshot.snapshot_id,
            )
            post_snapshot_revision, post_snapshot_identity = self._revision_parts()
            if post_snapshot_revision != revision or post_snapshot_identity != identity:
                raise MemoryError("SQLite source changed after snapshot")
            source_committed = False
            try:
                with closing(self._connect_read_write()) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        in_transaction_revision, in_transaction_identity = self._revision_parts()
                        if (
                            in_transaction_revision != revision
                            or in_transaction_identity != identity
                        ):
                            raise MemoryError("SQLite source changed inside transaction")
                        self._state_store.update_memory_plan_phase(plan.plan_id, "write_issuing")
                        old, new, field, _record_hash = self._execute_update(
                            connection,
                            plan.operation,
                            expected_old_hash=plan.expected_old_hash,
                            expected_record_hash=plan.record_hash,
                        )
                        if canonical_hash(_hashable_scalar(new)) != plan.diff[0].new_hash:
                            raise MemoryError("SQLite updated value does not match plan")
                        if self._logical_hash(connection) != plan.new_store_hash:
                            raise MemoryError("SQLite transaction changed unexpected data")
                        integrity = connection.execute("PRAGMA integrity_check").fetchall()
                        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
                        if [str(row[0]) for row in integrity] != ["ok"] or foreign_keys:
                            raise MemoryError("SQLite transaction failed integrity checks")
                        validate_local_file_path(self.path)
                        if not same_identity(
                            identity,
                            identity_from_stat(os.lstat(self.path)),
                            content_change=True,
                        ):
                            raise MemoryError("SQLite source identity changed before commit")
                        if capture_file_security(self.path) != source_security:
                            raise MemoryError("SQLite source permissions changed before commit")
                        verify_write_deadline(plan.expires_at, now=utc_now())
                        connection.commit()
                        source_committed = True
                    except sqlite3.Error as error:
                        if connection.in_transaction:
                            connection.rollback()
                        raise MemoryError(
                            "SQLite transaction was blocked by an active writer"
                        ) from error
                    except BaseException:
                        if connection.in_transaction:
                            connection.rollback()
                        raise
                self._state_store.update_memory_plan_phase(plan.plan_id, "committed")
                self._state_store.update_memory_plan_phase(plan.plan_id, "post_verifying")
                descriptor = os.open(self.path, os.O_RDWR | getattr(os, "O_BINARY", 0))
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                self._check_database(self.path)
                with closing(self._connect_read_write()) as verified:
                    # Bind the logical proof and receipt revision to one writer-
                    # excluded interval; a read transaction alone permits WAL
                    # writers to commit between those two observations.
                    verified.execute("BEGIN IMMEDIATE")
                    if self._logical_hash(verified) != plan.new_store_hash:
                        raise MemoryError("SQLite source changed after commit")
                    after, _verified_identity = self._revision_parts()
                    receipt = MemoryReceipt(
                        receipt_id="memory-receipt-" + secrets.token_hex(16),
                        plan_id=plan.plan_id,
                        snapshot_id=snapshot.snapshot_id,
                        source_id=source_id(self.path),
                        operation=plan.operation_kind.value,
                        field_names=(field,),
                        before_revision=revision,
                        after_revision=after,
                        created_at=utc_now(),
                    )
                    self._state_store.finish_memory_plan(receipt)
            except BaseException as post_commit_error:
                if not source_committed:
                    if isinstance(post_commit_error, sqlite3.Error):
                        raise MemoryError(
                            "SQLite transaction was blocked by an active writer"
                        ) from post_commit_error
                    if isinstance(post_commit_error, OSError):
                        raise MemoryError(
                            "SQLite file operation failed safely"
                        ) from post_commit_error
                    raise
                raise MemoryError(
                    "SQLite post-commit outcome is uncertain; snapshot and journal retained"
                ) from None
        return receipt

    def healthcheck(self) -> None:
        self._check_database(self.path)

    def _reconcile_interrupted(self) -> None:
        mutation_authorities = self._state_store.list_memory_reconciliation(source_id(self.path))
        restore_authorities = self._state_store.list_memory_restore_reconciliation(
            source_id(self.path)
        )
        if not mutation_authorities and not restore_authorities:
            return
        current_revision = self.current_revision()
        with closing(self._connect_read_only()) as connection:
            current_logical = self._logical_hash(connection)
        for authority in mutation_authorities:
            if authority.snapshot_id is None:
                continue
            snapshot = self._state_store.get_memory_snapshot(authority.snapshot_id)
            if snapshot is None:
                continue
            try:
                self._verified_snapshot_model(snapshot)
            except MemoryError:
                continue
            if current_logical == authority.new_store_hash:
                succeeded = True
                operation = "reconciled_apply"
            elif current_logical == authority.old_store_hash:
                succeeded = False
                operation = "reconciled_rollback"
            else:
                continue
            receipt = MemoryReceipt(
                receipt_id="memory-receipt-" + secrets.token_hex(16),
                plan_id=authority.plan_id,
                snapshot_id=snapshot.snapshot_id,
                source_id=authority.source_id,
                operation=operation,
                field_names=authority.field_names,
                before_revision=authority.source_revision,
                after_revision=current_revision,
                created_at=utc_now(),
            )
            self._state_store.finish_memory_reconciliation(receipt, succeeded=succeeded)
        for restore_authority in restore_authorities:
            try:
                target_snapshot = self._state_store.get_memory_snapshot(
                    restore_authority.snapshot_id
                )
                rollback_id = restore_authority.rollback_snapshot_id
                rollback = (
                    self._state_store.get_memory_snapshot(rollback_id) if rollback_id else None
                )
                if target_snapshot is None or rollback is None:
                    continue
                if target_snapshot.digest != restore_authority.snapshot_digest:
                    continue
                for evidence, expected in (
                    (target_snapshot, restore_authority.target_hash),
                    (rollback, restore_authority.before_hash),
                ):
                    evidence_path = self._verified_snapshot_model(evidence)
                    with closing(self._connect_read_only(evidence_path)) as evidence_connection:
                        if self._logical_hash(evidence_connection) != expected:
                            raise MemoryError("restore snapshot logical evidence differs")
            except MemoryError:
                continue
            if current_logical == restore_authority.target_hash:
                operation = "reconciled_restore"
            elif current_logical == restore_authority.before_hash:
                operation = "reconciled_restore_rollback"
            else:
                continue
            receipt = MemoryReceipt(
                receipt_id="memory-receipt-" + secrets.token_hex(16),
                restore_plan_id=restore_authority.restore_plan_id,
                snapshot_id=restore_authority.snapshot_id,
                source_id=restore_authority.source_id,
                operation=operation,
                before_revision=restore_authority.expected_revision,
                after_revision=current_revision,
                created_at=utc_now(),
            )
            self._state_store.finish_memory_restore(receipt)

    def _verified_snapshot_model(self, snapshot: Snapshot) -> Path:
        if snapshot.source_id != source_id(
            self.path
        ) or snapshot.source_path_binding != path_binding(self.path):
            raise MemoryError("snapshot is bound to another vault")
        if snapshot.status is not SnapshotStatus.VERIFIED:
            raise MemoryError("snapshot is not eligible for restore")
        path = Path(snapshot.backup_path)
        if ".." in path.parts or path.parent != self.backups_dir:
            raise MemoryError("snapshot backup path is not a direct secure descendant")
        data, backup_identity = read_pinned(path, max_bytes=self.max_bytes)
        if backup_identity != snapshot.backup_identity:
            raise MemoryError("snapshot file identity changed")
        if len(data) != snapshot.size or sha256_bytes(data) != snapshot.digest:
            raise MemoryError("snapshot physical verification failed")
        self._check_database(path)
        return path

    def _restore_from(
        self,
        snapshot_path: Path,
        *,
        expected_revision: str | None = None,
        expected_identity: FileIdentity | None = None,
        expected_snapshot: Snapshot | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        """Restore bounded rows in one SQLite transaction, retaining the named file.

        Replacing a SQLite file defeats its writer locks and may leave an open
        connection writing an unlinked database. A transaction preserves the
        inode, existing permissions, readers, and SQLite's writer exclusion.
        Schema changes require database-native recovery outside this adapter.
        """
        revision, identity = self._revision_parts()
        reviewed_revision = expected_revision or revision
        reviewed_identity = expected_identity or identity
        source_security = capture_file_security(self.path)
        try:
            if (
                expected_snapshot is not None
                and self._verified_snapshot_model(expected_snapshot) != snapshot_path
            ):
                raise MemoryError("SQLite restore snapshot authority changed")
            with (
                closing(self._connect_read_only(snapshot_path)) as snapshot,
                closing(self._connect_read_write()) as target,
            ):
                snapshot.execute("BEGIN")
                reason = self._restore_schema_reason(snapshot) or self._restore_schema_reason(
                    target
                )
                if reason is not None:
                    raise MemoryError(reason)
                # Disabling FK actions prevents DELETE CASCADE from changing
                # rows as each table is replaced. The completed transaction is
                # checked with foreign_key_check before it can commit.
                target.execute("PRAGMA foreign_keys = OFF")
                target.execute("BEGIN IMMEDIATE")
                try:
                    current, current_identity = self._revision_parts()
                    if current != reviewed_revision or current_identity != reviewed_identity:
                        raise MemoryError("SQLite source changed at restore transaction boundary")
                    if self._schema_signature(target) != self._schema_signature(snapshot):
                        raise MemoryError("SQLite restore requires an unchanged schema")
                    desired_hash = self._logical_hash(snapshot)
                    inventory = self._inventory(snapshot)
                    for item in inventory:
                        if item.kind != "table":
                            continue
                        rows = self._rows(snapshot, item)
                        columns = ",".join(_quote_identifier(column) for column in item.columns)
                        placeholders = ",".join("?" for _column in item.columns)
                        target.execute(f"DELETE FROM {_quote_identifier(item.name)}")
                        target.executemany(
                            f"INSERT INTO {_quote_identifier(item.name)} ({columns}) "
                            f"VALUES ({placeholders})",
                            (tuple(row[column] for column in item.columns) for row in rows),
                        )
                    if snapshot.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'"
                    ).fetchone():
                        target.execute("DELETE FROM sqlite_sequence")
                        target.executemany(
                            "INSERT INTO sqlite_sequence(name,seq) VALUES (?,?)",
                            (
                                tuple(row)
                                for row in snapshot.execute("SELECT name,seq FROM sqlite_sequence")
                            ),
                        )
                    for pragma in ("user_version", "application_id"):
                        value = int(snapshot.execute(f"PRAGMA {pragma}").fetchone()[0])
                        target.execute(f"PRAGMA {pragma} = {value}")
                    if self._logical_hash(target) != desired_hash:
                        raise MemoryError("SQLite restored transaction changed unexpected data")
                    integrity = target.execute("PRAGMA integrity_check").fetchall()
                    foreign_keys = target.execute("PRAGMA foreign_key_check").fetchall()
                    if [str(row[0]) for row in integrity] != ["ok"] or foreign_keys:
                        raise MemoryError("SQLite restore transaction failed integrity checks")
                    validate_local_file_path(self.path)
                    if not same_identity(
                        reviewed_identity,
                        identity_from_stat(os.lstat(self.path)),
                        content_change=True,
                    ):
                        raise MemoryError("SQLite source identity changed before restore commit")
                    if capture_file_security(self.path) != source_security:
                        raise MemoryError("SQLite source permissions changed before restore commit")
                    if expected_snapshot is not None:
                        self._verified_snapshot_model(expected_snapshot)
                    verify_write_deadline(expires_at, now=utc_now())
                    target.commit()
                finally:
                    if target.in_transaction:
                        target.rollback()
            fsync_directory(self.path.parent)
        except MemoryError:
            raise
        except sqlite3.Error as error:
            raise MemoryError("SQLite restore transaction was blocked or failed safely") from error
        except OSError as error:
            raise MemoryError("SQLite restore file operation failed safely") from error

    def restore(
        self,
        snapshot_id: str,
        *,
        expected_snapshot_digest: str,
        expected_revision: str,
        reviewed_expires_at: datetime | None = None,
    ) -> MemoryReceipt:
        if self._recognized_format is VaultFormat.CHROMA:
            raise MemoryError("recognized Chroma storage is read-only; restore is unsupported")
        if self._read_only:
            raise MemoryError("SQLite vault was opened read-only")
        reviewed_deadline = validate_write_deadline(reviewed_expires_at)
        if not isinstance(snapshot_id, str):
            raise TypeError("snapshot_id must be a string")
        snapshot = self._state_store.get_memory_snapshot(snapshot_id)
        if snapshot is None:
            raise MemoryError("snapshot was not found")
        if not secrets.compare_digest(snapshot.digest, expected_snapshot_digest):
            raise MemoryError("snapshot digest authority does not match")
        snapshot_path = self._verified_snapshot_model(snapshot)
        with closing(self._connect_read_only(snapshot_path)) as snapshot_connection:
            expected_snapshot_logical = self._logical_hash(snapshot_connection)
        self._reject_active_wal()
        with exclusive_file_lock(self.path):
            current, current_identity = self._revision_parts()
            with closing(self._connect_read_only()) as current_connection:
                current_logical = self._logical_hash(current_connection)
            draft = new_restore_plan(
                source=self.path,
                snapshot=snapshot,
                expected_revision=expected_revision,
                source_identity=current_identity,
                before_hash=current_logical,
                target_hash=expected_snapshot_logical,
            )
            authority = self._state_store.save_memory_restore_plan(draft)
            claimed = self._state_store.claim_memory_restore(
                authority.restore_plan_id, expected_digest=authority.digest
            )
            if claimed.status == "succeeded":
                receipt = self._state_store.get_memory_restore_receipt(claimed.restore_plan_id)
                with closing(self._connect_read_only()) as completed:
                    completed_hash = self._logical_hash(completed)
                if receipt is None or completed_hash != claimed.target_hash:
                    raise MemoryError("completed restore could not be physically verified")
                return receipt
            if (
                current != expected_revision
                or claimed.before_hash != current_logical
                or claimed.source_identity != current_identity
            ):
                self._state_store.fail_memory_restore(claimed.restore_plan_id, interrupted=False)
                raise MemoryError("SQLite revision changed before restore")
            rollback = self.backup(expected_revision=current)
            self._state_store.update_memory_restore_phase(
                claimed.restore_plan_id,
                "rollback_verified",
                rollback_snapshot_id=rollback.snapshot_id,
            )
            committed = False
            try:
                self._state_store.update_memory_restore_phase(
                    claimed.restore_plan_id, "restore_issuing"
                )
                self._restore_from(
                    snapshot_path,
                    expected_revision=current,
                    expected_identity=current_identity,
                    expected_snapshot=snapshot,
                    expires_at=min(claimed.expires_at, reviewed_deadline or claimed.expires_at),
                )
                self._check_database(self.path)
                with closing(self._connect_read_write()) as restored_connection:
                    restored_connection.execute("BEGIN IMMEDIATE")
                    if self._logical_hash(restored_connection) != expected_snapshot_logical:
                        raise MemoryError("restored SQLite logical state differs")
                    after, _verified_identity = self._revision_parts()
                    committed = True
                    self._state_store.update_memory_restore_phase(
                        claimed.restore_plan_id, "committed"
                    )
                    receipt = MemoryReceipt(
                        receipt_id="memory-receipt-" + secrets.token_hex(16),
                        restore_plan_id=claimed.restore_plan_id,
                        snapshot_id=snapshot.snapshot_id,
                        source_id=source_id(self.path),
                        operation="restore",
                        before_revision=current,
                        after_revision=after,
                        created_at=utc_now(),
                    )
                    self._state_store.finish_memory_restore(receipt)
            except Exception as restore_error:
                if committed:
                    try:
                        self._state_store.fail_memory_restore(
                            claimed.restore_plan_id, interrupted=True
                        )
                    except Exception:
                        raise MemoryError(
                            "SQLite restore outcome is uncertain; journal persistence failed"
                        ) from None
                    raise MemoryError(
                        "SQLite restore committed; receipt reconciliation is required"
                    ) from None
                uncertain = True
                try:
                    with closing(self._connect_read_only()) as observed:
                        uncertain = self._logical_hash(observed) != current_logical
                    uncertain = uncertain or not same_identity(
                        current_identity,
                        identity_from_stat(os.lstat(self.path)),
                        content_change=True,
                    )
                except Exception:
                    pass
                try:
                    self._state_store.fail_memory_restore(
                        claimed.restore_plan_id, interrupted=uncertain
                    )
                except Exception:
                    raise MemoryError(
                        "SQLite restore outcome is uncertain; journal persistence failed"
                    ) from None
                if uncertain:
                    raise MemoryError(
                        "SQLite restore outcome is uncertain; snapshots and journal retained"
                    ) from None
                if isinstance(restore_error, MemoryError):
                    raise
                raise MemoryError(
                    "SQLite restore transaction failed; source was preserved"
                ) from None
        return receipt


__all__ = ["SQLiteMemoryAdapter"]
