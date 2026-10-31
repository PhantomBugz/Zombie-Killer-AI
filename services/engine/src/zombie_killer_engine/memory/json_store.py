"""Bounded JSON and JSONL Memory Vault adapter with verified replacement writes."""

from __future__ import annotations

import copy
import json
import os
import secrets
import tempfile
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import cast

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
    ProbeResult,
    QueryFilter,
    QueryPage,
    Snapshot,
    SnapshotStatus,
    VaultCapabilities,
    VaultFormat,
    VaultSource,
    apply_file_security,
    canonical_hash,
    capture_file_security,
    exclusive_file_lock,
    fsync_directory,
    new_plan,
    new_restore_plan,
    path_binding,
    prepare_backup_directory,
    read_pinned,
    read_prefix_pinned,
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


@dataclass(frozen=True, slots=True)
class _ParsedRecord:
    record_id: str
    namespace: str
    raw: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class _ParsedStore:
    format: VaultFormat
    root: list[JsonValue] | dict[str, JsonValue]
    records: tuple[_ParsedRecord, ...]
    line_numbers: tuple[int, ...] = ()


class JsonMemoryAdapter:
    """Treat an entire JSON store as one revision and one atomic mutation unit."""

    def __init__(
        self,
        path: Path,
        *,
        backups_dir: Path,
        state_store: MemoryStateStore,
        max_bytes: int = 16 * 1024 * 1024,
        max_records: int = 10_000,
        max_depth: int = 16,
        max_string_chars: int = 65_536,
    ) -> None:
        if not 1 <= max_bytes <= 256 * 1024 * 1024:
            raise ValueError("max_bytes is outside the supported bound")
        if not 1 <= max_records <= 100_000:
            raise ValueError("max_records is outside the supported bound")
        if not 2 <= max_depth <= 64:
            raise ValueError("max_depth is outside the supported bound")
        if not 32 <= max_string_chars <= 1_048_576:
            raise ValueError("max_string_chars is outside the supported bound")
        validate_local_file_path(path)
        prepare_backup_directory(backups_dir)
        self.path = path
        self.backups_dir = backups_dir
        self.max_bytes = max_bytes
        self.max_records = max_records
        self.max_depth = max_depth
        self.max_string_chars = max_string_chars
        self._state_store = state_store
        self._read_only = False
        self._applied_plans: set[str] = set()
        self._state_store.register_vault_source(
            VaultSource(
                source_id=source_id(path),
                path=str(path),
                format=self.probe(path).format,
                capabilities=VaultCapabilities(
                    readable=True,
                    queryable=True,
                    editable=True,
                    snapshot=True,
                    restore=True,
                ),
                revision=self.current_revision(),
            )
        )
        self._reconcile_interrupted()

    @classmethod
    def probe(cls, path: Path) -> ProbeResult:
        validate_local_file_path(path)
        try:
            prefix, _ = read_prefix_pinned(path, prefix_bytes=4096)
            text = prefix.decode("utf-8-sig")
        except (UnicodeDecodeError, MemoryError) as error:
            return ProbeResult(
                format=VaultFormat.UNSUPPORTED,
                recognized=False,
                capabilities=VaultCapabilities(reason="not bounded UTF-8 JSON"),
                reason=type(error).__name__,
            )
        stripped = text.lstrip()
        is_json = stripped.startswith(("[", "{"))
        is_jsonl = path.suffix.casefold() in {".jsonl", ".ndjson"}
        format = VaultFormat.JSONL if is_jsonl else VaultFormat.JSON
        return ProbeResult(
            format=format,
            recognized=is_json or is_jsonl,
            capabilities=VaultCapabilities(
                readable=True,
                queryable=True,
                editable=True,
                snapshot=True,
                restore=True,
            ),
            reason=None if is_json or is_jsonl else "file does not look like JSON",
        )

    def open(self, *, read_only: bool) -> JsonMemoryAdapter:
        self._read_only = read_only
        self.healthcheck()
        return self

    def _read(self) -> tuple[bytes, _ParsedStore, FileIdentity]:
        data, identity = read_pinned(self.path, max_bytes=self.max_bytes)
        return data, self._parse(data), identity

    def _parse(self, data: bytes) -> _ParsedStore:
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise MemoryError("vault is not valid UTF-8") from error
        is_jsonl = self.path.suffix.casefold() in {".jsonl", ".ndjson"}
        if is_jsonl:
            root: list[JsonValue] = []
            line_numbers: list[int] = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(
                        line,
                        parse_constant=self._reject_constant,
                        object_pairs_hook=self._unique_object,
                    )
                except (TypeError, ValueError, RecursionError, json.JSONDecodeError) as error:
                    raise MemoryError(f"invalid JSONL record at line {line_number}") from error
                if not isinstance(value, dict):
                    raise MemoryError(f"JSONL line {line_number} is not an object")
                root.append(cast(dict[str, JsonValue], value))
                line_numbers.append(line_number)
            return self._validate_root(root, VaultFormat.JSONL, line_numbers=tuple(line_numbers))
        try:
            value = json.loads(
                text,
                parse_constant=self._reject_constant,
                object_pairs_hook=self._unique_object,
            )
        except (TypeError, ValueError, RecursionError, json.JSONDecodeError) as error:
            raise MemoryError("vault is malformed JSON") from error
        if not isinstance(value, (list, dict)):
            raise MemoryError("JSON vault root must be an array or keyed object")
        return self._validate_root(
            cast(list[JsonValue] | dict[str, JsonValue], value), VaultFormat.JSON
        )

    @staticmethod
    def _reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant {value}")

    @staticmethod
    def _unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        value: dict[str, JsonValue] = {}
        for key, item in pairs:
            if key in value:
                raise MemoryError("JSON contains a duplicate object key")
            value[key] = item
        return value

    def _validate_value(self, value: JsonValue, *, depth: int = 0) -> None:
        if depth > self.max_depth:
            raise MemoryError("JSON nesting depth exceeds configured limit")
        if isinstance(value, str):
            if len(value) > self.max_string_chars:
                raise MemoryError("JSON string exceeds configured limit")
            return
        if value is None or isinstance(value, (bool, int)):
            return
        if isinstance(value, float):
            if value != value or value in {float("inf"), float("-inf")}:
                raise MemoryError("JSON contains a non-finite number")
            return
        if isinstance(value, list):
            for item in value:
                self._validate_value(item, depth=depth + 1)
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str) or len(key) > 128:
                    raise MemoryError("JSON object key is invalid or oversized")
                self._validate_value(item, depth=depth + 1)
            return
        raise MemoryError("JSON contains an unsupported value")

    def _validate_root(
        self,
        root: list[JsonValue] | dict[str, JsonValue],
        format: VaultFormat,
        *,
        line_numbers: tuple[int, ...] = (),
    ) -> _ParsedStore:
        self._validate_value(root)
        records: list[_ParsedRecord] = []
        if isinstance(root, list):
            items = tuple(
                (
                    str(line_numbers[index])
                    if format is VaultFormat.JSONL and line_numbers
                    else str(index),
                    item,
                )
                for index, item in enumerate(root)
            )
        else:
            items = tuple(root.items())
        if len(items) > self.max_records:
            raise MemoryError("vault record count exceeds configured limit")
        seen: set[str] = set()
        fallback_occurrences: dict[str, int] = {}
        for locator, item in items:
            if not isinstance(item, dict):
                raise MemoryError("every memory record must be an object")
            raw = cast(dict[str, JsonValue], item)
            declared = raw.get("id")
            if declared is not None and not isinstance(declared, (str, int)):
                raise MemoryError("record id must be a string or integer")
            if declared is not None:
                record_id = str(declared).strip()
            elif isinstance(root, dict):
                record_id = locator.strip()
            elif format is VaultFormat.JSONL:
                # Content-derived identity survives unrelated insertions. Identical
                # lines are disambiguated by their occurrence among identical lines;
                # inserting an identical record before them intentionally renumbers
                # that duplicate group because the records are indistinguishable.
                fallback = canonical_hash(raw)[:32]
                occurrence = fallback_occurrences.get(fallback, 0) + 1
                fallback_occurrences[fallback] = occurrence
                record_id = f"record-{fallback}-{occurrence}"
            else:
                record_id = f"record-{locator}"
            if not record_id or len(record_id) > 256:
                raise MemoryError("record id is blank or oversized")
            if record_id in seen:
                raise MemoryError("vault contains a duplicate record id")
            seen.add(record_id)
            namespace_value = raw.get("namespace", "default")
            if not isinstance(namespace_value, str) or not namespace_value.strip():
                raise MemoryError("record namespace must be a non-blank string")
            namespace = namespace_value.strip()
            if len(namespace) > 256:
                raise MemoryError("record namespace is oversized")
            content = raw.get("content", raw.get("text", ""))
            if not isinstance(content, str):
                raise MemoryError("record content must be a string")
            metadata = raw.get("metadata", {})
            if not isinstance(metadata, dict):
                raise MemoryError("record metadata must be an object")
            records.append(_ParsedRecord(record_id, namespace, raw))
        return _ParsedStore(format, root, tuple(records), line_numbers)

    def _revision(self, data: bytes) -> str:
        return sha256_bytes(data)

    def current_revision(self) -> str:
        data, parsed, _identity = self._read()
        del parsed
        return self._revision(data)

    def list_namespaces(self) -> tuple[str, ...]:
        _data, parsed, _identity = self._read()
        return tuple(sorted({record.namespace for record in parsed.records}))

    def _public_record(self, record: _ParsedRecord, revision: str) -> MemoryRecord:
        content = record.raw.get("content", record.raw.get("text", ""))
        metadata = record.raw.get("metadata", {})
        return MemoryRecord(
            record_id=record.record_id,
            namespace=record.namespace,
            content=cast(str, content),
            metadata=copy.deepcopy(cast(dict[str, JsonValue], metadata)),
            embedding_present=record.raw.get("embedding") is not None,
            source_revision=revision,
        )

    @staticmethod
    def _retrievable(record: _ParsedRecord) -> bool:
        metadata = record.raw.get("metadata", {})
        if not isinstance(metadata, dict):
            return False
        return not bool(
            metadata.get("excluded_from_retrieval") or metadata.get("zombie_killer_quarantined")
        )

    @staticmethod
    def _matches(record: MemoryRecord, filter: QueryFilter | None) -> bool:
        if filter is None:
            return True
        if filter.ids and record.record_id not in filter.ids:
            return False
        if filter.text is not None:
            needle = filter.text.casefold()
            searchable = (
                record.record_id
                + "\n"
                + record.content
                + "\n"
                + json.dumps(record.metadata, ensure_ascii=False)
            )
            if needle not in searchable.casefold():
                return False
        tags = record.metadata.get("tags", record.metadata.get("tag", []))
        available = {str(item) for item in tags} if isinstance(tags, list) else {str(tags)}
        if filter.tags and not set(filter.tags).issubset(available):
            return False
        return not any(record.metadata.get(key) != value for key, value in filter.metadata.items())

    def query(
        self,
        *,
        cursor: str | None = None,
        limit: int = 100,
        filter: QueryFilter | None = None,
        namespace: str | None = None,
    ) -> QueryPage:
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        try:
            offset = int(cursor or "0")
        except ValueError as error:
            raise MemoryError("query cursor is invalid") from error
        if offset < 0:
            raise MemoryError("query cursor is invalid")
        data, parsed, source_identity = self._read()
        revision = self._revision(data)
        records = [
            self._public_record(record, revision)
            for record in parsed.records
            if (namespace is None or record.namespace == namespace) and self._retrievable(record)
        ]
        filtered = [record for record in records if self._matches(record, filter)]
        page = tuple(filtered[offset : offset + limit])
        next_offset = offset + len(page)
        return QueryPage(
            records=page,
            next_cursor=str(next_offset) if next_offset < len(filtered) else None,
            total=len(filtered),
        )

    def get(self, record_id: str) -> MemoryRecord:
        data, parsed, _identity = self._read()
        revision = self._revision(data)
        for record in parsed.records:
            if record.record_id == record_id:
                return self._public_record(record, revision)
        raise MemoryError("memory record was not found")

    def _locate(self, parsed: _ParsedStore, record_id: str) -> _ParsedRecord:
        for record in parsed.records:
            if record.record_id == record_id:
                return record
        raise MemoryError("memory record was not found")

    def _mutate(
        self, parsed: _ParsedStore, operation: MutationOperation
    ) -> tuple[_ParsedStore, JsonValue, JsonValue, str]:
        cloned_root = copy.deepcopy(parsed.root)
        cloned = self._validate_root(cloned_root, parsed.format, line_numbers=parsed.line_numbers)
        record = self._locate(cloned, operation.record_id)
        raw = record.raw
        value = cast(JsonValue, operation.unsealed_value())
        if operation.kind is MutationKind.UPDATE_CONTENT:
            if not isinstance(value, str):
                raise MemoryError("content updates require a string")
            key = "content" if "content" in raw or "text" not in raw else "text"
            old = raw.get(key, "")
            raw[key] = value
            field_name = key
        elif operation.kind is MutationKind.UPDATE_FIELD:
            field_name = cast(str, operation.field)
            if field_name in {"id", "namespace", "embedding", "metadata"}:
                raise MemoryError("this record field is not editable")
            if field_name not in raw:
                raise MemoryError("record field is not in the editable allowlist")
            existing = raw[field_name]
            if isinstance(existing, (list, dict)):
                raise MemoryError("record field is not scalar and editable")
            if isinstance(value, (list, dict)):
                raise MemoryError("record field updates must be scalar")
            old = existing
            raw[field_name] = value
        else:
            metadata_value = raw.setdefault("metadata", {})
            if not isinstance(metadata_value, dict):
                raise MemoryError("record metadata is invalid")
            metadata = cast(dict[str, JsonValue], metadata_value)
            if operation.kind is MutationKind.UPDATE_METADATA:
                key = cast(str, operation.metadata_key)
                old = metadata.get(key)
                metadata[key] = value
                field_name = f"metadata.{key}"
            elif operation.kind is MutationKind.EXCLUDE:
                key = "excluded_from_retrieval"
                old = metadata.get(key)
                metadata[key] = True
                value = True
                field_name = key
            elif operation.kind is MutationKind.QUARANTINE:
                key = "zombie_killer_quarantined"
                old = metadata.get(key)
                metadata[key] = True
                value = True
                field_name = key
            elif operation.kind is MutationKind.RESTORE_RECORD:
                key = "zombie_killer_quarantined"
                old = metadata.get(key)
                metadata.pop(key, None)
                value = None
                field_name = key
            else:
                raise MemoryError("unsupported JSON mutation")
        self._validate_value(cloned_root)
        reparsed = self._validate_root(cloned_root, parsed.format, line_numbers=parsed.line_numbers)
        return reparsed, old, value, field_name

    def _render(self, parsed: _ParsedStore) -> bytes:
        if parsed.format is VaultFormat.JSONL:
            assert isinstance(parsed.root, list)
            rendered = "\n".join(
                json.dumps(
                    item,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                for item in parsed.root
            ) + ("\n" if parsed.root else "")
        else:
            rendered = json.dumps(
                parsed.root,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        data = rendered.encode("utf-8")
        if len(data) > self.max_bytes:
            raise MemoryError("mutated vault exceeds configured size limit")
        self._parse(data)
        return data

    def plan_mutation(
        self, operation: MutationOperation, *, expected_revision: str
    ) -> MutationPlan:
        if self._read_only:
            raise MemoryError("JSON vault was opened read-only")
        data, parsed, identity = self._read()
        revision = self._revision(data)
        if not secrets.compare_digest(revision, expected_revision):
            raise MemoryError("vault revision changed before planning")
        mutated, old, new, field_name = self._mutate(parsed, operation)
        rendered = self._render(mutated)
        plan = new_plan(
            source=self.path,
            revision=revision,
            identity=identity,
            operation=operation,
            record_hash=canonical_hash(self._locate(parsed, operation.record_id).raw),
            field_name=field_name,
            old_hash=canonical_hash(old),
            old_store_hash=sha256_bytes(data),
            new_hash=canonical_hash(new),
            new_store_hash=sha256_bytes(rendered),
        )
        self._state_store.save_memory_plan(plan)
        return plan

    def backup(self, *, expected_revision: str) -> Snapshot:
        data, parsed, source_identity = self._read()
        revision = self._revision(data)
        if not secrets.compare_digest(revision, expected_revision):
            raise MemoryError("vault revision changed before snapshot")
        del parsed
        snapshot_id = "memory-snapshot-" + secrets.token_hex(16)
        destination = self.backups_dir / f"{snapshot_id}{self.path.suffix}.snapshot"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = -1
        complete = False
        try:
            descriptor = os.open(destination, flags, 0o600)
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise MemoryError("snapshot write made no progress")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            secure_created_file(destination)
            fsync_directory(self.backups_dir)
            copied, _snapshot_identity = read_pinned(destination, max_bytes=self.max_bytes)
            self._parse(copied)
            digest = sha256_bytes(copied)
            if not secrets.compare_digest(digest, revision):
                raise MemoryError("snapshot verification failed")
            snapshot = Snapshot(
                snapshot_id=snapshot_id,
                source_id=source_id(self.path),
                source_path_binding=path_binding(self.path),
                source_revision=revision,
                source_identity=source_identity,
                digest=digest,
                size=len(copied),
                backup_identity=_snapshot_identity,
                backup_path=str(destination),
                status=SnapshotStatus.VERIFIED,
                created_at=utc_now(),
            )
            self._state_store.save_memory_snapshot(snapshot)
            complete = True
        except MemoryError:
            raise
        except OSError as error:
            raise MemoryError("snapshot file operation failed safely") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not complete:
                with suppress(OSError):
                    destination.unlink(missing_ok=True)
        return snapshot

    def snapshot(self, snapshot_id: str) -> Snapshot:
        snapshot = self._state_store.get_memory_snapshot(snapshot_id)
        if snapshot is None:
            raise MemoryError("snapshot was not found")
        return snapshot

    def _replace(
        self,
        data: bytes,
        *,
        expected_revision: str | None = None,
        expected_identity: FileIdentity | None = None,
        expires_at: datetime | None = None,
        on_write_issuing: Callable[[], None] | None = None,
    ) -> None:
        descriptor = -1
        temporary: Path | None = None
        replaced = False
        try:
            original, _parsed, original_identity = self._read()
            revision = expected_revision or self._revision(original)
            identity = expected_identity or original_identity
            if self._revision(original) != revision or original_identity != identity:
                raise MemoryError("vault source changed before replacement")
            source_security = capture_file_security(self.path)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".zombie-killer-memory-", suffix=".tmp", dir=self.path.parent
            )
            temporary = Path(temporary_name)
            os.chmod(temporary, 0o600)
            secure_created_file(temporary)
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise MemoryError("replacement write made no progress")
                view = view[written:]
            apply_file_security(temporary, descriptor, source_security)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            check, _identity = read_pinned(temporary, max_bytes=self.max_bytes)
            self._parse(check)
            if not secrets.compare_digest(sha256_bytes(check), sha256_bytes(data)):
                raise MemoryError("replacement file verification failed")
            # The persistent sidecar serializes cooperating writers across inode
            # replacements. POSIX does not provide a compare-and-swap rename;
            # noncooperating writers still require the documented quiescent-store
            # contract. Check after all slow preparation, at the rename boundary.
            current, _parsed, current_identity = self._read()
            if self._revision(current) != revision or current_identity != identity:
                raise MemoryError("vault source changed at replacement boundary")
            if capture_file_security(self.path) != source_security:
                raise MemoryError("vault source permissions changed before replacement")
            verify_write_deadline(expires_at, now=utc_now())
            if on_write_issuing is not None:
                on_write_issuing()
            os.replace(temporary, self.path)
            replaced = True
            if capture_file_security(self.path) != source_security:
                raise MemoryError("replacement permissions changed after rename")
            fsync_directory(self.path.parent)
        except MemoryError:
            raise
        except OSError as error:
            raise MemoryError("vault replacement failed safely") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary is not None and not replaced:
                with suppress(FileNotFoundError):
                    temporary.unlink()

    def apply(self, plan: MutationPlan) -> MemoryReceipt:
        if self._read_only:
            raise MemoryError("JSON vault was opened read-only")
        verify_plan(plan)
        if plan.plan_id in self._applied_plans:
            raise MemoryError("mutation plan replay was rejected")
        if plan.source_id != source_id(self.path):
            raise MemoryError("mutation plan is bound to another vault")
        authority = self._state_store.claim_memory_plan(plan.plan_id, expected_digest=plan.digest)
        try:
            verify_authority(plan, authority)
        except BaseException:
            self._state_store.fail_memory_plan(plan.plan_id, interrupted=False)
            raise
        write_issued = False

        def mark_write_issuing() -> None:
            nonlocal write_issued
            write_issued = True

        try:
            with exclusive_file_lock(self.path):
                data, parsed, identity = self._read()
                revision = self._revision(data)
                if revision != plan.source_revision:
                    raise MemoryError("vault revision changed before apply")
                if identity != plan.source_identity:
                    raise MemoryError("vault file identity changed before apply")
                record = self._locate(parsed, plan.record_id)
                if canonical_hash(record.raw) != plan.record_hash:
                    raise MemoryError("vault record identity changed before apply")
                mutated, old, _new, field_name = self._mutate(parsed, plan.operation)
                if canonical_hash(old) != plan.expected_old_hash:
                    raise MemoryError("record field changed before apply")
                rendered = self._render(mutated)
                if sha256_bytes(rendered) != plan.new_store_hash:
                    raise MemoryError("mutation plan output hash does not match")
                snapshot = self.backup(expected_revision=revision)
                self._state_store.update_memory_plan_phase(
                    plan.plan_id,
                    "snapshot_verified",
                    snapshot_id=snapshot.snapshot_id,
                )
                current_data, _current_parsed, current_identity = self._read()
                if self._revision(current_data) != revision or current_identity != identity:
                    raise MemoryError("vault changed after snapshot")
                self._state_store.update_memory_plan_phase(plan.plan_id, "write_issuing")
                self._replace(
                    rendered,
                    expected_revision=revision,
                    expected_identity=identity,
                    expires_at=plan.expires_at,
                    on_write_issuing=mark_write_issuing,
                )
                self._state_store.update_memory_plan_phase(plan.plan_id, "committed")
                after = self.current_revision()
                if after != plan.new_store_hash:
                    raise MemoryError("vault failed post-write verification")
                receipt = MemoryReceipt(
                    receipt_id="memory-receipt-" + secrets.token_hex(16),
                    plan_id=plan.plan_id,
                    snapshot_id=snapshot.snapshot_id,
                    source_id=source_id(self.path),
                    operation=plan.operation_kind.value,
                    field_names=(field_name,),
                    before_revision=revision,
                    after_revision=after,
                    created_at=utc_now(),
                )
                self._state_store.finish_memory_plan(receipt)
        except Exception as apply_error:
            interrupted = write_issued
            try:
                # Equal observed bytes cannot disprove a known syscall issuance:
                # another writer may have restored the prior contents afterward.
                interrupted = write_issued or self.current_revision() != plan.source_revision
            except Exception:
                interrupted = True
            try:
                self._state_store.fail_memory_plan(plan.plan_id, interrupted=interrupted)
            except Exception:
                raise MemoryError(
                    "JSON mutation journal is unavailable; reconciliation is required"
                ) from None
            if interrupted and write_issued:
                raise MemoryError(
                    "JSON mutation outcome is uncertain; snapshot and journal retained"
                ) from None
            if isinstance(apply_error, MemoryError):
                raise
            raise MemoryError("JSON mutation failed safely") from apply_error
        self._applied_plans.add(plan.plan_id)
        return receipt

    def healthcheck(self) -> None:
        _data, _parsed, _identity = self._read()

    def _verified_snapshot(self, snapshot_id: str, expected_digest: str) -> tuple[Snapshot, bytes]:
        snapshot = self._state_store.get_memory_snapshot(snapshot_id)
        if snapshot is None:
            raise MemoryError("snapshot was not found")
        if not secrets.compare_digest(snapshot.digest, expected_digest):
            raise MemoryError("snapshot digest authority does not match")
        if snapshot.source_id != source_id(
            self.path
        ) or snapshot.source_path_binding != path_binding(self.path):
            raise MemoryError("snapshot is bound to another vault")
        if snapshot.status is not SnapshotStatus.VERIFIED:
            raise MemoryError("snapshot is not eligible for restore")
        backup = Path(snapshot.backup_path)
        if ".." in backup.parts or backup.parent != self.backups_dir:
            raise MemoryError("snapshot backup path is not a direct secure descendant")
        data, backup_identity = read_pinned(backup, max_bytes=self.max_bytes)
        if backup_identity != snapshot.backup_identity:
            raise MemoryError("snapshot file identity changed")
        if len(data) != snapshot.size or sha256_bytes(data) != snapshot.digest:
            raise MemoryError("snapshot physical verification failed")
        self._parse(data)
        return snapshot, data

    def _reconcile_interrupted(self) -> None:
        current = self.current_revision()
        for authority in self._state_store.list_memory_reconciliation(source_id(self.path)):
            if authority.snapshot_id is None:
                continue
            snapshot = self._state_store.get_memory_snapshot(authority.snapshot_id)
            if snapshot is None:
                continue
            try:
                self._verified_snapshot(snapshot.snapshot_id, snapshot.digest)
            except MemoryError:
                continue
            if current == authority.new_store_hash:
                succeeded = True
                operation = "reconciled_apply"
            elif current == authority.source_revision:
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
                after_revision=current,
                created_at=utc_now(),
            )
            self._state_store.finish_memory_reconciliation(receipt, succeeded=succeeded)
        for restore_authority in self._state_store.list_memory_restore_reconciliation(
            source_id(self.path)
        ):
            try:
                target_snapshot, _target = self._verified_snapshot(
                    restore_authority.snapshot_id, restore_authority.snapshot_digest
                )
                if target_snapshot.source_revision != restore_authority.target_hash:
                    continue
                rollback_id = restore_authority.rollback_snapshot_id
                if rollback_id is None:
                    continue
                rollback = self._state_store.get_memory_snapshot(rollback_id)
                if rollback is None:
                    continue
                self._verified_snapshot(rollback.snapshot_id, rollback.digest)
                if rollback.source_revision != restore_authority.before_hash:
                    continue
            except MemoryError:
                continue
            if current == restore_authority.target_hash:
                operation = "reconciled_restore"
            elif current == restore_authority.before_hash:
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
                after_revision=current,
                created_at=utc_now(),
            )
            self._state_store.finish_memory_restore(receipt)

    def restore(
        self,
        snapshot_id: str,
        *,
        expected_snapshot_digest: str,
        expected_revision: str,
        reviewed_expires_at: datetime | None = None,
    ) -> MemoryReceipt:
        if self._read_only:
            raise MemoryError("JSON vault was opened read-only")
        reviewed_deadline = validate_write_deadline(reviewed_expires_at)
        if not isinstance(snapshot_id, str):
            raise TypeError("snapshot_id must be a string")
        snapshot, data = self._verified_snapshot(snapshot_id, expected_snapshot_digest)
        with exclusive_file_lock(self.path):
            current_data, _parsed, current_identity = self._read()
            current = self._revision(current_data)
            draft = new_restore_plan(
                source=self.path,
                snapshot=snapshot,
                expected_revision=expected_revision,
                source_identity=current_identity,
                before_hash=current,
                target_hash=snapshot.source_revision,
            )
            authority = self._state_store.save_memory_restore_plan(draft)
            claimed = self._state_store.claim_memory_restore(
                authority.restore_plan_id, expected_digest=authority.digest
            )
            if claimed.status == "succeeded":
                receipt = self._state_store.get_memory_restore_receipt(claimed.restore_plan_id)
                if receipt is None or self.current_revision() != claimed.target_hash:
                    raise MemoryError("completed restore could not be physically verified")
                return receipt
            if current != expected_revision or claimed.before_hash != current:
                self._state_store.fail_memory_restore(claimed.restore_plan_id, interrupted=False)
                raise MemoryError("vault revision changed before restore")
            if claimed.source_identity != current_identity:
                self._state_store.fail_memory_restore(claimed.restore_plan_id, interrupted=False)
                raise MemoryError("restore source identity authority changed")
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
                self._replace(
                    data,
                    expected_revision=current,
                    expected_identity=current_identity,
                    expires_at=min(claimed.expires_at, reviewed_deadline or claimed.expires_at),
                )
                after = self.current_revision()
                if after != snapshot.source_revision:
                    raise MemoryError("restored vault failed revision verification")
                committed = True
                self._state_store.update_memory_restore_phase(claimed.restore_plan_id, "committed")
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
                # Replacement is atomic, but a later writer may own the named
                # source now. Never roll a post-write failure back by path.
                uncertain = committed
                try:
                    observed, _parsed, observed_identity = self._read()
                    uncertain = (
                        self._revision(observed) != current or observed_identity != current_identity
                    )
                except Exception:
                    uncertain = True
                try:
                    self._state_store.fail_memory_restore(
                        claimed.restore_plan_id, interrupted=uncertain
                    )
                except Exception:
                    raise MemoryError(
                        "JSON restore outcome is uncertain; journal persistence failed"
                    ) from None
                if committed:
                    raise MemoryError(
                        "JSON restore committed; receipt reconciliation is required"
                    ) from restore_error
                if uncertain:
                    raise MemoryError(
                        "JSON restore outcome is uncertain; snapshots and journal retained"
                    ) from None
                if isinstance(restore_error, MemoryError):
                    raise
                raise MemoryError("JSON restore failed safely") from restore_error
        return receipt


__all__ = ["JsonMemoryAdapter"]
