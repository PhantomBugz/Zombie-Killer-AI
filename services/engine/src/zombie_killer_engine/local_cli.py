"""Finite headless commands for operator-selected local recovery workflows."""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, Protocol

import typer
from pydantic import ValidationError

from zombie_killer_engine.memory.base import MemoryError, validate_local_path_lexical
from zombie_killer_engine.service import PAYLOAD_MODELS, Capability, Method

if TYPE_CHECKING:
    from zombie_killer_engine.cli import CliFailure

MAX_SCALAR_JSON_BYTES = 8_192
JsonOption = Annotated[bool, typer.Option("--json", help="Emit JSON (the default for workflows).")]
PlanArgument = Annotated[str, typer.Argument(help="Exact reviewed plan ID.")]
DigestArgument = Annotated[str, typer.Argument(help="Exact reviewed 64-character plan digest.")]
ConfirmOption = Annotated[
    bool, typer.Option("--confirm", help="Authorize this exact plan; never prompts.")
]
SourceArgument = Annotated[str, typer.Argument(help="Exact registered source ID.")]
RecordArgument = Annotated[str, typer.Argument(help="Exact record ID.")]
RevisionOption = Annotated[
    str, typer.Option("--expected-revision", help="Reviewed source revision digest.")
]


class ServiceCall(Protocol):
    def __call__(
        self,
        method: Method,
        payload: dict[str, object],
        *,
        capability: Capability = Capability.READ,
    ) -> object: ...


class _InputFailure(ValueError):
    pass


def _scalar_json(text: str) -> str | int | float | bool | None:
    """Decode only one bounded finite JSON scalar, never echoing its contents."""
    try:
        if len(text.encode("utf-8")) > MAX_SCALAR_JSON_BYTES:
            raise ValueError("oversized")

        def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
            output: dict[str, object] = {}
            for key, value in pairs:
                if key in output:
                    raise ValueError("duplicate key")
                output[key] = value
            return output

        def reject_constant(_value: str) -> None:
            raise ValueError("non-finite")

        value: object = json.loads(
            text, object_pairs_hook=reject_duplicate_keys, parse_constant=reject_constant
        )
        if value is None or type(value) in {str, int, bool}:
            return value  # type: ignore[return-value]
        if type(value) is float and math.isfinite(value):
            return value
        raise ValueError("not a finite scalar")
    except (ValueError, UnicodeError, RecursionError):
        raise _InputFailure(
            "--value-json must contain one finite JSON scalar within the 8192-byte bound."
        ) from None


def _lexical_selected_path(text: str) -> str:
    try:
        # Path normalizes a literal '.' component; validate it before constructing Path.
        if any(part in {".", ".."} for part in text.replace("\\", "/").split("/")):
            raise MemoryError("lexical dot segment")
        validate_local_path_lexical(Path(text))
    except (MemoryError, ValueError):
        raise _InputFailure("The selected path must be a lexical absolute local path.") from None
    # Do not resolve links, normalize spelling, or pre-open the selected path.
    return text


def install_local_workflows(
    app: typer.Typer,
    vault_app: typer.Typer,
    call_service: ServiceCall,
    encode_json: Callable[[object], str],
    fail: Callable[[CliFailure], None],
    failure_type: type[CliFailure],
) -> None:
    """Install only explicit public methods; injected callbacks avoid a CLI import cycle."""
    quarantine_app = typer.Typer(help="Preview declared-resource cleanup and exact restore.")
    diagnostics_app = typer.Typer(help="Plan an explicit local redacted diagnostics export.")
    receipt_app = typer.Typer(help="Read a durable local operation receipt.")
    app.add_typer(quarantine_app, name="quarantine")
    app.add_typer(diagnostics_app, name="diagnostics")
    app.add_typer(receipt_app, name="receipt")

    def abort(message: str) -> None:
        fail(failure_type(message))
        raise typer.Exit(2)

    def selected_path(text: str) -> str:
        try:
            return _lexical_selected_path(text)
        except _InputFailure as error:
            abort(str(error))
            raise AssertionError("unreachable") from None

    def scalar_value(text: str | None) -> str | int | float | bool | None:
        if text is None:
            return None
        try:
            return _scalar_json(text)
        except _InputFailure as error:
            abort(str(error))
            raise AssertionError("unreachable") from None

    def emit(
        method: Method | str,
        payload: dict[str, object],
        capability: Capability = Capability.READ,
        *,
        confirm: bool | None = None,
    ) -> None:
        if confirm is False:
            abort("Execution requires the explicit --confirm flag.")
        try:
            selected_method = Method(method)
            # Reuse the finite protocol models without showing validation input values.
            PAYLOAD_MODELS[selected_method].model_validate(payload)
        except (ValidationError, ValueError):
            abort("The local workflow arguments are invalid; no request was issued.")
        try:
            result = call_service(selected_method, payload, capability=capability)
        except failure_type as error:
            fail(error)
            raise typer.Exit(error.exit_code) from None
        # Receipts retain the engine's exact certainty/no-action/partial fields.
        typer.echo(encode_json(result))

    @vault_app.command("register")
    def vault_register(
        path: Annotated[str, typer.Argument(help="Operator-selected lexical absolute local file.")],
        json_output: JsonOption = False,
    ) -> None:
        """Register one selected source without resolving a link on the caller's behalf."""
        emit(Method.VAULT_REGISTER, {"path": selected_path(path)}, Capability.PLANNING)

    @vault_app.command("list")
    def vault_list(
        limit: Annotated[int, typer.Option("--limit", min=1, max=500)] = 100,
        cursor: Annotated[str | None, typer.Option("--cursor")] = None,
        json_output: JsonOption = False,
    ) -> None:
        """List registered sources with bounded pagination."""
        payload: dict[str, object] = {"limit": limit}
        if cursor is not None:
            payload["cursor"] = cursor
        emit(Method.VAULT_LIST, payload)

    @vault_app.command("query")
    def vault_query(
        source_id: SourceArgument,
        namespace: Annotated[str | None, typer.Option("--namespace")] = None,
        text: Annotated[str | None, typer.Option("--text")] = None,
        cursor: Annotated[str | None, typer.Option("--cursor")] = None,
        limit: Annotated[int, typer.Option("--limit", min=1, max=500)] = 100,
        json_output: JsonOption = False,
    ) -> None:
        """Read bounded records from one supported registered source; never execute SQL."""
        payload: dict[str, object] = {"source_id": source_id, "limit": limit}
        for key, item in (("namespace", namespace), ("text", text), ("cursor", cursor)):
            if item is not None:
                payload[key] = item
        emit(Method.VAULT_QUERY, payload)

    @vault_app.command("get")
    def vault_get(
        source_id: SourceArgument,
        record_id: RecordArgument,
        json_output: JsonOption = False,
    ) -> None:
        """Read one exact record from a supported registered source."""
        emit(Method.VAULT_GET, {"source_id": source_id, "record_id": record_id})

    @vault_app.command("snapshots")
    def vault_snapshots(
        source_id: SourceArgument,
        limit: Annotated[int, typer.Option("--limit", min=1, max=500)] = 100,
        json_output: JsonOption = False,
    ) -> None:
        """List verified backup history for one source."""
        emit(Method.VAULT_SNAPSHOT_LIST, {"source_id": source_id, "limit": limit})

    @vault_app.command("restore-plan")
    def vault_restore_plan(
        source_id: SourceArgument,
        snapshot_id: Annotated[str, typer.Argument(help="Exact verified snapshot ID.")],
        snapshot_digest: Annotated[
            str, typer.Option("--snapshot-digest", help="Exact verified snapshot digest.")
        ],
        expected_revision: RevisionOption,
        json_output: JsonOption = False,
    ) -> None:
        """Preview a digest-bound snapshot restore against the reviewed current source."""
        emit(
            Method.VAULT_RESTORE_PLAN,
            {
                "source_id": source_id,
                "snapshot_id": snapshot_id,
                "snapshot_digest": snapshot_digest,
                "expected_revision": expected_revision,
            },
            Capability.PLANNING,
        )

    @vault_app.command("mutation-plan")
    def vault_mutation_plan(
        source_id: SourceArgument,
        record_id: RecordArgument,
        expected_revision: RevisionOption,
        operation: Annotated[
            Literal[
                "update_content",
                "update_field",
                "update_metadata",
                "exclude_from_retrieval",
                "quarantine",
                "restore_record",
            ],
            typer.Option("--operation", help="Finite scalar mutation to preview."),
        ],
        field: Annotated[str | None, typer.Option("--field")] = None,
        metadata_key: Annotated[str | None, typer.Option("--metadata-key")] = None,
        value_json: Annotated[
            str | None, typer.Option("--value-json", help="One finite JSON scalar, <=8192 bytes.")
        ] = None,
        json_output: JsonOption = False,
    ) -> None:
        """Preview a revision-bound change; the proposed value is never echoed on errors."""
        payload: dict[str, object] = {
            "source_id": source_id,
            "record_id": record_id,
            "expected_revision": expected_revision,
            "operation": operation,
        }
        if field is not None:
            payload["field"] = field
        if metadata_key is not None:
            payload["metadata_key"] = metadata_key
        if value_json is not None:
            payload["value"] = scalar_value(value_json)
        emit(Method.VAULT_MUTATION_PLAN, payload, Capability.PLANNING)

    @vault_app.command("mutation-execute")
    def vault_mutation_execute(
        plan_id: PlanArgument,
        digest: DigestArgument,
        confirm: ConfirmOption = False,
        json_output: JsonOption = False,
    ) -> None:
        """Execute exactly one reviewed memory mutation and emit its original receipt."""
        emit(
            Method.VAULT_MUTATION_EXECUTE,
            {"plan_id": plan_id, "digest": digest},
            Capability.EXECUTION,
            confirm=confirm,
        )

    @vault_app.command("restore-execute")
    def vault_restore_execute(
        plan_id: PlanArgument,
        digest: DigestArgument,
        confirm: ConfirmOption = False,
        json_output: JsonOption = False,
    ) -> None:
        """Execute one reviewed snapshot restore without upgrading its receipt certainty."""
        emit(
            Method.VAULT_RESTORE_EXECUTE,
            {"plan_id": plan_id, "digest": digest},
            Capability.EXECUTION,
            confirm=confirm,
        )

    @quarantine_app.command("execute")
    def quarantine_execute(
        plan_id: PlanArgument,
        digest: DigestArgument,
        confirm: ConfirmOption = False,
        json_output: JsonOption = False,
    ) -> None:
        """Execute reviewed declared-resource cleanup, never a supplied filesystem path."""
        emit(
            "quarantine.execute",
            {"plan_id": plan_id, "digest": digest},
            Capability.EXECUTION,
            confirm=confirm,
        )

    @quarantine_app.command("resources")
    def quarantine_resources(
        agent_id: Annotated[str, typer.Argument(help="Exact managed agent ID.")],
        expected_pid: Annotated[int | None, typer.Option("--expected-pid", min=1)] = None,
        expected_process_instance_id: Annotated[
            str | None, typer.Option("--expected-process-instance-id")
        ] = None,
        json_output: JsonOption = False,
    ) -> None:
        """Inspect declared temporary resources; legacy declarations may be read-only."""
        payload: dict[str, object] = {"agent_id": agent_id}
        if expected_pid is not None:
            payload["expected_pid"] = expected_pid
        if expected_process_instance_id is not None:
            payload["expected_process_instance_id"] = expected_process_instance_id
        emit("quarantine.resource-list", payload)

    @quarantine_app.command("plan")
    def quarantine_plan(
        agent_id: Annotated[str, typer.Argument(help="Exact managed agent ID.")],
        resource_index: Annotated[
            int, typer.Option("--resource-index", min=0, max=63, help="Reviewed declaration index.")
        ],
        declaration_digest: Annotated[
            str,
            typer.Option("--declaration-digest", help="Exact declaration digest from resources."),
        ],
        expected_pid: Annotated[int | None, typer.Option("--expected-pid", min=1)] = None,
        expected_process_instance_id: Annotated[
            str | None, typer.Option("--expected-process-instance-id")
        ] = None,
        json_output: JsonOption = False,
    ) -> None:
        """Preview one declared resource; the engine resolves its protected path and identity."""
        payload: dict[str, object] = {
            "agent_id": agent_id,
            "resource_index": resource_index,
            "expected_declaration_digest": declaration_digest,
        }
        if expected_pid is not None:
            payload["expected_pid"] = expected_pid
        if expected_process_instance_id is not None:
            payload["expected_process_instance_id"] = expected_process_instance_id
        emit(
            "quarantine.plan",
            payload,
            Capability.PLANNING,
        )

    @quarantine_app.command("list")
    def quarantine_list(
        limit: Annotated[int, typer.Option("--limit", min=1, max=500)] = 100,
        cursor: Annotated[str | None, typer.Option("--cursor")] = None,
        json_output: JsonOption = False,
    ) -> None:
        """List durable Graveyard entries with bounded pagination."""
        payload: dict[str, object] = {"limit": limit}
        if cursor is not None:
            payload["cursor"] = cursor
        emit(Method.QUARANTINE_LIST, payload)

    @quarantine_app.command("restore-plan")
    def quarantine_restore_plan(
        entry_id: Annotated[str, typer.Argument(help="Exact restorable Graveyard entry ID.")],
        json_output: JsonOption = False,
    ) -> None:
        """Preview restoring one exact Graveyard entry to its recorded original path."""
        emit(Method.QUARANTINE_RESTORE_PLAN, {"entry_id": entry_id}, Capability.PLANNING)

    @quarantine_app.command("restore-execute")
    def quarantine_restore_execute(
        plan_id: PlanArgument,
        digest: DigestArgument,
        confirm: ConfirmOption = False,
        json_output: JsonOption = False,
    ) -> None:
        """Execute a reviewed Graveyard restore, refusing occupied original destinations."""
        emit(
            Method.QUARANTINE_RESTORE_EXECUTE,
            {"plan_id": plan_id, "digest": digest},
            Capability.EXECUTION,
            confirm=confirm,
        )

    @diagnostics_app.command("execute")
    def diagnostics_execute(
        plan_id: PlanArgument,
        digest: DigestArgument,
        confirm: ConfirmOption = False,
        json_output: JsonOption = False,
    ) -> None:
        """Execute one reviewed no-overwrite local export and emit its original receipt."""
        emit(
            Method.DIAGNOSTICS_EXPORT_EXECUTE,
            {"plan_id": plan_id, "digest": digest},
            Capability.EXECUTION,
            confirm=confirm,
        )

    @diagnostics_app.command("plan")
    def diagnostics_plan(
        destination: Annotated[
            str, typer.Argument(help="Selected lexical absolute local JSON destination.")
        ],
        include_receipts: Annotated[
            bool, typer.Option("--include-receipts/--no-include-receipts")
        ] = True,
        include_settings: Annotated[
            bool, typer.Option("--include-settings/--no-include-settings")
        ] = True,
        json_output: JsonOption = False,
    ) -> None:
        """Preview a redacted local export to a new destination; no upload or overwrite."""
        emit(
            Method.DIAGNOSTICS_EXPORT_PLAN,
            {
                "destination": selected_path(destination),
                "include_receipts": include_receipts,
                "include_settings": include_settings,
            },
            Capability.PLANNING,
        )

    @receipt_app.command("get")
    def receipt_get(
        receipt_id: Annotated[str, typer.Argument(help="Exact durable local receipt ID.")],
        json_output: JsonOption = False,
    ) -> None:
        """Retrieve the engine's original receipt without inventing an outcome."""
        emit(Method.RECEIPT_GET, {"receipt_id": receipt_id})
