from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from zombie_killer_engine.cli import CliFailure
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.service import Capability, EngineService, Method

runner = CliRunner()


def _workflow_app(
    observed: list[tuple[Method, dict[str, object], Capability]],
    result: object,
) -> typer.Typer:
    try:
        workflows = importlib.import_module("zombie_killer_engine.local_cli")
    except ModuleNotFoundError:
        pytest.fail("The finite local workflow CLI has not been implemented.")
    app = typer.Typer(pretty_exceptions_enable=False)
    vault = typer.Typer()
    app.add_typer(vault, name="vault")

    def call(
        method: Method,
        payload: dict[str, object],
        *,
        capability: Capability = Capability.READ,
    ) -> object:
        observed.append((method, payload, capability))
        return result

    def fail(error: CliFailure) -> None:
        typer.echo(f"Error: {error.message}", err=True)
        raise typer.Exit(error.exit_code)

    workflows.install_local_workflows(app, vault, call, json.dumps, fail, CliFailure)
    return app


def test_registration_preserves_operator_selected_lexical_path(tmp_path: Path) -> None:
    selected = str(tmp_path / "selected-link.json")
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, {"recognized": True})

    result = runner.invoke(app, ["vault", "register", selected, "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"recognized": True}
    assert observed == [(Method.VAULT_REGISTER, {"path": selected}, Capability.PLANNING)]


@pytest.mark.parametrize(
    "arguments",
    [
        ["vault", "mutation-execute", "plan-1", "a" * 64],
        ["vault", "restore-execute", "plan-1", "a" * 64],
        ["quarantine", "execute", "plan-1", "a" * 64],
        ["quarantine", "restore-execute", "plan-1", "a" * 64],
        ["diagnostics", "execute", "plan-1", "a" * 64],
    ],
)
def test_execute_never_dispatches_without_explicit_confirmation(arguments: list[str]) -> None:
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, {"outcome": "completed"})

    result = runner.invoke(app, [*arguments, "--json"], input="yes\n")

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "--confirm" in result.stderr
    assert observed == []


@pytest.mark.parametrize(
    "private_value",
    [
        '{"private-fixture":"one","private-fixture":"two"}',
        '{"private-fixture":"one"}',
        '["private-fixture"]',
        '"private-fixture" "extra"',
        "NaN",
        "Infinity",
        "-Infinity",
        "1e9999",
        '"' + "private-fixture" * 1_000 + '"',
    ],
)
def test_invalid_or_oversized_scalar_is_rejected_without_leaking_it(private_value: str) -> None:
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, {"plan_id": "plan-1"})

    result = runner.invoke(
        app,
        [
            "vault",
            "mutation-plan",
            "source-1",
            "record-1",
            "--expected-revision",
            "b" * 64,
            "--operation",
            "update_content",
            "--value-json",
            private_value,
        ],
    )

    assert result.exit_code == 2
    assert "private-fixture" not in result.output
    assert result.stdout == ""
    assert observed == []


@pytest.mark.parametrize(
    ("arguments", "method", "payload", "capability"),
    [
        (
            ["vault", "list", "--limit", "15", "--cursor", "next-page"],
            Method.VAULT_LIST,
            {"limit": 15, "cursor": "next-page"},
            Capability.READ,
        ),
        (
            [
                "vault",
                "query",
                "source-1",
                "--namespace",
                "notes",
                "--text",
                "selected",
                "--cursor",
                "cursor-1",
                "--limit",
                "17",
            ],
            Method.VAULT_QUERY,
            {
                "source_id": "source-1",
                "namespace": "notes",
                "text": "selected",
                "cursor": "cursor-1",
                "limit": 17,
            },
            Capability.READ,
        ),
        (
            ["vault", "get", "source-1", "record-1"],
            Method.VAULT_GET,
            {"source_id": "source-1", "record_id": "record-1"},
            Capability.READ,
        ),
        (
            ["vault", "snapshots", "source-1", "--limit", "25"],
            Method.VAULT_SNAPSHOT_LIST,
            {"source_id": "source-1", "limit": 25},
            Capability.READ,
        ),
        (
            [
                "vault",
                "restore-plan",
                "source-1",
                "snapshot-1",
                "--snapshot-digest",
                "c" * 64,
                "--expected-revision",
                "b" * 64,
            ],
            Method.VAULT_RESTORE_PLAN,
            {
                "source_id": "source-1",
                "snapshot_id": "snapshot-1",
                "snapshot_digest": "c" * 64,
                "expected_revision": "b" * 64,
            },
            Capability.PLANNING,
        ),
        (
            ["quarantine", "list", "--limit", "12", "--cursor", "cursor-2"],
            Method.QUARANTINE_LIST,
            {"limit": 12, "cursor": "cursor-2"},
            Capability.READ,
        ),
        (
            ["quarantine", "restore-plan", "entry-1"],
            Method.QUARANTINE_RESTORE_PLAN,
            {"entry_id": "entry-1"},
            Capability.PLANNING,
        ),
        (
            ["receipt", "get", "receipt-1"],
            Method.RECEIPT_GET,
            {"receipt_id": "receipt-1"},
            Capability.READ,
        ),
    ],
)
def test_workflows_dispatch_only_exact_typed_payloads(
    arguments: list[str], method: Method, payload: dict[str, object], capability: Capability
) -> None:
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, {"local_fixture": "result"})

    result = runner.invoke(app, [*arguments, "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"local_fixture": "result"}
    assert observed == [(method, payload, capability)]


def test_diagnostics_plan_keeps_the_exact_destination_and_inclusion_choices(tmp_path: Path) -> None:
    selected = str(tmp_path / "operator-chosen.json")
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, {"plan_id": "plan-2"})

    result = runner.invoke(
        app, ["diagnostics", "plan", selected, "--no-include-receipts", "--include-settings"]
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"plan_id": "plan-2"}
    assert observed == [
        (
            Method.DIAGNOSTICS_EXPORT_PLAN,
            {"destination": selected, "include_receipts": False, "include_settings": True},
            Capability.PLANNING,
        )
    ]


@pytest.mark.parametrize(
    "arguments",
    [
        ["vault", "register", "relative.json"],
        ["diagnostics", "plan", "relative.json"],
        ["vault", "list", "--limit", "501"],
        ["vault", "get", " " * 10, "record-1"],
        ["vault", "restore-execute", "plan-1", "not-a-digest", "--confirm"],
    ],
)
def test_invalid_path_identifier_bounds_and_digests_are_rejected_before_dispatch(
    arguments: list[str],
) -> None:
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, {})

    result = runner.invoke(app, arguments)

    assert result.exit_code == 2
    assert result.stdout == ""
    assert observed == []


@pytest.mark.parametrize("scalar", ['"private-fixture"', "17", "-5.25", "true", "false", "null"])
def test_scalar_plans_preserve_the_selected_scalar_type_without_echoing_it(scalar: str) -> None:
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, {"plan_id": "plan-1", "digest": "a" * 64})

    result = runner.invoke(
        app,
        [
            "vault",
            "mutation-plan",
            "source-1",
            "record-1",
            "--expected-revision",
            "b" * 64,
            "--operation",
            "update_metadata",
            "--metadata-key",
            "selected-key",
            "--value-json",
            scalar,
        ],
    )

    assert result.exit_code == 0, result.output
    assert "private-fixture" not in result.stdout
    assert observed == [
        (
            Method.VAULT_MUTATION_PLAN,
            {
                "source_id": "source-1",
                "record_id": "record-1",
                "expected_revision": "b" * 64,
                "operation": "update_metadata",
                "metadata_key": "selected-key",
                "value": json.loads(scalar),
            },
            Capability.PLANNING,
        )
    ]


@pytest.mark.parametrize(
    "receipt",
    [
        {"outcome": "completed", "certainty": "verified", "action_issued": True},
        {"outcome": "failed", "certainty": "failed_before_issue", "action_issued": False},
        {"outcome": "interrupted", "certainty": "uncertain", "action_issued": None},
    ],
)
def test_execute_preserves_receipt_certainty_and_partial_failures(
    receipt: dict[str, object],
) -> None:
    receipt = {
        "receipt_id": "receipt-1",
        "plan_id": "plan-1",
        "created_at": "2026-10-02T12:00:00+00:00",
        "partial_failures": ["bounded local fixture"],
        **receipt,
    }
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, receipt)

    result = runner.invoke(app, ["vault", "mutation-execute", "plan-1", "a" * 64, "--confirm"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == receipt
    assert observed == [
        (
            Method.VAULT_MUTATION_EXECUTE,
            {"plan_id": "plan-1", "digest": "a" * 64},
            Capability.EXECUTION,
        )
    ]


@pytest.mark.parametrize(
    ("arguments", "method", "payload", "capability"),
    [
        (
            ["quarantine", "resources", "agent-1"],
            "quarantine.resource-list",
            {"agent_id": "agent-1"},
            Capability.READ,
        ),
        (
            [
                "quarantine",
                "plan",
                "agent-1",
                "--resource-index",
                "3",
                "--declaration-digest",
                "b" * 64,
            ],
            "quarantine.plan",
            {"agent_id": "agent-1", "resource_index": 3, "expected_declaration_digest": "b" * 64},
            Capability.PLANNING,
        ),
    ],
)
def test_cleanup_commands_never_accept_renderer_selected_paths(
    arguments: list[str], method: str, payload: dict[str, object], capability: Capability
) -> None:
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, {"local_fixture": "cleanup"})

    result = runner.invoke(app, [*arguments, "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"local_fixture": "cleanup"}
    assert len(observed) == 1
    selected_method, selected_payload, selected_capability = observed[0]
    assert selected_method.value == method
    assert selected_payload == payload
    assert selected_capability == capability
    assert "path" not in selected_payload


@pytest.mark.parametrize("index", ["-1", "64", "not-an-index"])
def test_cleanup_rejects_unbounded_resource_indices(index: str) -> None:
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, {})

    result = runner.invoke(
        app,
        [
            "quarantine",
            "plan",
            "agent-1",
            "--resource-index",
            index,
            "--declaration-digest",
            "b" * 64,
        ],
    )

    assert result.exit_code == 2
    assert observed == []


def test_literal_dot_segments_are_not_collapsed_before_engine_selection(tmp_path: Path) -> None:
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, {})

    result = runner.invoke(app, ["vault", "register", f"{tmp_path}/./selected.json"])

    assert result.exit_code == 2
    assert observed == []


@pytest.mark.parametrize("command", ["resources", "plan"])
def test_cleanup_cli_preserves_the_reviewed_process_binding(command: str) -> None:
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, {"local_fixture": "bound cleanup"})
    arguments = [
        "quarantine",
        command,
        "agent-1",
        "--expected-pid",
        "4242",
        "--expected-process-instance-id",
        "c" * 64,
    ]
    payload: dict[str, object] = {
        "agent_id": "agent-1",
        "expected_pid": 4242,
        "expected_process_instance_id": "c" * 64,
    }
    if command == "plan":
        arguments.extend(["--resource-index", "3", "--declaration-digest", "b" * 64])
        payload.update({"resource_index": 3, "expected_declaration_digest": "b" * 64})

    result = runner.invoke(app, arguments)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"local_fixture": "bound cleanup"}
    assert observed[0][1] == payload


@pytest.mark.parametrize("command", ["resources", "plan"])
@pytest.mark.parametrize(
    "binding",
    [
        ["--expected-pid", "4242"],
        ["--expected-process-instance-id", "c" * 64],
        ["--expected-pid", "0", "--expected-process-instance-id", "c" * 64],
        ["--expected-pid", "4242", "--expected-process-instance-id", "not-a-digest"],
    ],
)
def test_cleanup_cli_rejects_partial_or_invalid_binding_before_dispatch(
    command: str, binding: list[str]
) -> None:
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, {})
    arguments = ["quarantine", command, "agent-1", *binding]
    if command == "plan":
        arguments.extend(["--resource-index", "3", "--declaration-digest", "b" * 64])

    result = runner.invoke(app, arguments)

    assert result.exit_code == 2
    assert observed == []


def test_cleanup_cli_requires_a_declaration_digest_even_with_a_valid_index() -> None:
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, {})

    result = runner.invoke(app, ["quarantine", "plan", "agent-1", "--resource-index", "3"])

    assert result.exit_code == 2
    assert "--declaration-digest" in result.output
    assert observed == []


@pytest.mark.parametrize("digest", ["not-a-digest", "B" * 64, "b" * 63])
def test_cleanup_cli_rejects_malformed_reviewed_declaration_digests(digest: str) -> None:
    observed: list[tuple[Method, dict[str, object], Capability]] = []
    app = _workflow_app(observed, {})

    result = runner.invoke(
        app,
        ["quarantine", "plan", "agent-1", "--resource-index", "3", "--declaration-digest", digest],
    )

    assert result.exit_code == 2
    assert observed == []


def test_real_json_workflow_survives_separate_cli_service_instances(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zombie_killer_engine import cli, local_cli

    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "data" / "backups",
        graveyard_dir=tmp_path / "data" / "graveyard",
    )
    opened: list[EngineService] = []

    def build() -> EngineService:
        service = cli.build_default_service(paths=paths)
        opened.append(service)
        return service

    monkeypatch.setattr(cli, "build_service", build)
    app = typer.Typer(pretty_exceptions_enable=False)
    vault = typer.Typer()
    app.add_typer(vault, name="vault")
    local_cli.install_local_workflows(
        app, vault, cli.call_service, cli._json, cli._fail, CliFailure
    )
    source = tmp_path / "memory.json"
    original = b'[{"id":"record-1","content":"original fixture","metadata":{}}]'
    source.write_bytes(original)

    def invoke(arguments: list[str]) -> dict[str, object]:
        result = runner.invoke(app, [*arguments, "--json"])
        assert result.exit_code == 0, result.output
        decoded: object = json.loads(result.stdout)
        assert isinstance(decoded, dict)
        return decoded

    assert invoke(["vault", "register", str(source)])["recognized"] is True
    listed = invoke(["vault", "list"])
    registered = listed["sources"][0]
    source_id = registered["source_id"]
    revision = registered["revision"]
    records = invoke(["vault", "query", source_id])
    assert records["records"][0]["content"] == "original fixture"
    planned = invoke(
        [
            "vault",
            "mutation-plan",
            source_id,
            "record-1",
            "--expected-revision",
            revision,
            "--operation",
            "update_content",
            "--value-json",
            '"edited fixture"',
        ]
    )
    assert "edited fixture" not in json.dumps(planned)
    receipt = invoke(
        ["vault", "mutation-execute", planned["plan_id"], planned["digest"], "--confirm"]
    )
    assert receipt["outcome"] == "completed"
    assert receipt["certainty"] == "verified"
    assert receipt["action_issued"] is True
    assert invoke(["vault", "get", source_id, "record-1"])["record"]["content"] == "edited fixture"
    looked_up = invoke(["receipt", "get", receipt["receipt_id"]])
    assert looked_up["plan_id"] == planned["plan_id"]
    assert looked_up["certainty"] == "verified"
    history = invoke(["vault", "snapshots", source_id])["snapshots"]
    assert len(history) == 1
    assert history[0]["status"] == "verified"
    changed_revision = invoke(["vault", "list"])["sources"][0]["revision"]
    assert changed_revision != revision
    restore = invoke(
        [
            "vault",
            "restore-plan",
            source_id,
            history[0]["snapshot_id"],
            "--snapshot-digest",
            history[0]["digest"],
            "--expected-revision",
            changed_revision,
        ]
    )
    restored = invoke(
        ["vault", "restore-execute", restore["plan_id"], restore["digest"], "--confirm"]
    )
    assert restored["certainty"] == "verified"
    assert restored["action_issued"] is True
    assert source.read_bytes() == original
    replay = runner.invoke(
        app, ["vault", "mutation-execute", planned["plan_id"], planned["digest"], "--confirm"]
    )
    assert replay.exit_code == 4
    assert source.read_bytes() == original
    assert len(opened) >= 12
    assert len({id(service) for service in opened}) == len(opened)
