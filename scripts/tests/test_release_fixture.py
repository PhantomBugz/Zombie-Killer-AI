from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
import sysconfig
from pathlib import Path

from zombie_killer_engine.actions import (
    ProcessDisappeared,
    PsutilProcessController,
    process_instance_id,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RUNNER = REPOSITORY_ROOT / "scripts" / "release-fixture.py"
DEMO_AGENT = REPOSITORY_ROOT / "scripts" / "demo-agent.py"
TARGET_AGENT_ID = "00000000-0000-4000-8000-000000000001"
SIBLING_AGENT_ID = "00000000-0000-4000-8000-000000000002"
TARGET_CONTENT = b"Zombie Killer release fixture target artifact\n"
SIBLING_CONTENT = b"Zombie Killer release fixture sibling artifact\n"


def test_demo_agent_denies_network_before_importing_the_real_sdk() -> None:
    tree = ast.parse(DEMO_AGENT.read_text(encoding="utf-8"))
    sdk_import = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "zombie_killer"
    )
    audit_hook = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "sys"
        and node.func.attr == "addaudithook"
    )

    assert audit_hook.lineno < sdk_import.lineno


def test_real_release_fixture_is_identity_bound_reversible_and_leak_free(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "fixture-workspace"
    environment = {
        key: value
        for key in ("COMSPEC", "PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "WINDIR")
        if (value := os.environ.get(key)) is not None
    }
    environment.update(
        {
            "OPENAI_API_KEY": "fixture-must-not-forward",
            "ANTHROPIC_API_KEY": "fixture-must-not-forward",
            "HACKENPROOF_API_KEY": "fixture-must-not-forward",
        }
    )
    environment["PYTHONPATH"] = os.pathsep.join(
        (
            os.fspath(REPOSITORY_ROOT / "packages" / "sdk-python" / "src"),
            os.fspath(REPOSITORY_ROOT / "services" / "engine" / "src"),
            sysconfig.get_path("purelib"),
        )
    )
    fixture_python = os.fspath(getattr(sys, "_base_executable", sys.executable))

    completed = subprocess.run(
        [
            fixture_python,
            os.fspath(RUNNER),
            "--workspace",
            os.fspath(workspace),
            "--deadline-seconds",
            "20",
        ],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["schema_version"] == 1
    assert report["fixture"] == "zombie-killer-release-fixture"
    assert report["synthetic"] is True
    assert report["scanner"] == {
        "implementation": "production_scan_agents",
        "process_scope": "exact_spawned_processes",
    }
    assert report["spawned"] == {
        "agent_count": 2,
        "same_script": True,
        "distinct_agent_ids": True,
        "provider_credentials_forwarded": False,
        "network_access": False,
    }

    stop = report["cooperative_stop"]
    assert stop["mode"] == "request_stop"
    assert stop["target"]["agent_id"] == TARGET_AGENT_ID
    assert stop["sibling"]["agent_id"] == SIBLING_AGENT_ID
    assert stop["target"]["pid"] != stop["sibling"]["pid"]
    assert len(stop["target"]["process_instance_id"]) == 64
    assert len(stop["sibling"]["process_instance_id"]) == 64
    assert stop["target"]["exited"] is True
    assert stop["sibling"]["alive_after_target_stop"] is True
    assert stop["sibling"]["instance_unchanged"] is True
    sibling_hash = hashlib.sha256(SIBLING_CONTENT).hexdigest()
    assert stop["sibling"]["artifact_sha256_before"] == sibling_hash
    assert stop["sibling"]["artifact_sha256_after"] == sibling_hash
    assert stop["sibling"]["artifact_unchanged"] is True
    assert stop["receipt"]["outcome"] == "completed"
    assert stop["receipt"]["action_issued"] is True

    artifact = report["artifact_round_trip"]
    expected_hash = hashlib.sha256(TARGET_CONTENT).hexdigest()
    assert artifact["automatic_sdk_cleanup_composition"] is False
    assert artifact["exercise"] == "separate_explicit_domain_operation"
    assert artifact["approved_root_explicit"] is True
    assert artifact["quarantined"] is True
    assert artifact["restored"] is True
    assert artifact["sha256_before"] == expected_hash
    assert artifact["sha256_after"] == expected_hash
    assert artifact["sha256_verified"] is True
    assert (workspace / "artifacts" / "target.bin").read_bytes() == TARGET_CONTENT

    cleanup = report["cleanup"]
    assert cleanup["exact_identity_only"] is True
    assert cleanup["process_name_killing"] is False
    assert cleanup["children_remaining"] == 0
    controller = PsutilProcessController()
    for name in ("target", "sibling"):
        expected = stop[name]
        try:
            observed = controller.read_identity(expected["pid"])
        except ProcessDisappeared:
            continue
        assert process_instance_id(observed) != expected["process_instance_id"]
