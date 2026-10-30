from __future__ import annotations

import hashlib
import inspect
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter
from urllib.parse import quote

import pytest

from zombie_killer.lease import (
    LeaseStore,
    ProcessIdentity,
    cancellation_target,
    current_boot_id,
    current_process_identity,
    default_runtime_dir,
    posix_runtime_dir,
    require_protocol_path,
    validate_temp_resource,
)
from zombie_killer.redaction import redact_status


def recognizable_token_fixtures() -> tuple[str, ...]:
    aws_prefixes = ("AKIA", "ASIA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA")
    return (
        "sk-" + "fixture" + "A" * 20,
        "ghp_" + "fixture" + "A" * 20,
        "github_pat_" + "fixture" + "A" * 20,
        *(prefix + "A" * 16 for prefix in aws_prefixes),
        "xoxb-" + "fixture" + "A" * 20,
        "xapp-" + "fixture" + "A" * 20,
        "1//" + "fixture" + "A" * 20,
        "AIza" + "fixture" + "A" * 30,
        "sk_live_" + "fixture" + "A" * 16,
        "npm_" + "fixture" + "A" * 20,
        "ya29." + "fixture" + "A" * 20,
        "MII" + "A" * 60,
    )


def token_near_miss_fixtures() -> tuple[str, ...]:
    return (
        "sk-" + "A" * 19,
        "ghp_" + "A" * 19,
        "AKIA" + "A" * 15,
        "xoxb-" + "A" * 19,
        "xapp-" + "A" * 19,
        "1//" + "A" * 19,
        "AIza" + "A" * 29,
        "sk_live_" + "A" * 15,
        "npm_" + "A" * 19,
        "ya29." + "A" * 19,
        "MII" + "A" * 39,
    )


def test_status_redacts_sensitive_forms_without_partial_truncation() -> None:
    samples = (
        "Authorization: Bearer example-token-value",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signaturefixture00",
        "--api-key='synthetic-value' --client_secret synthetic-other",
        "access_token=synthetic refresh-token: synthetic-refresh",
        "AKIAIOSFODNN7EXAMPLE",
        "https://fixture-user:fixture-password@example.invalid/path",
    )

    rendered = redact_status(" | ".join(samples), max_length=256)

    assert "synthetic" not in rendered
    assert "demo-password" not in rendered
    assert "AKIA" not in rendered
    assert "eyJ" not in rendered
    assert "[REDACTED]" in rendered
    assert len(rendered) <= 256


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("private_key=fixture-private-value", "private_key=[REDACTED]"),
        ("passphrase='fixture passphrase value'", "passphrase='[REDACTED]'"),
        ('seed_phrase="fixture seed phrase words"', 'seed_phrase="[REDACTED]"'),
        ("credential=fixture-credential-value", "credential=[REDACTED]"),
        ("AWS_SESSION_TOKEN=fixture-session-value", "AWS_SESSION_TOKEN=[REDACTED]"),
        ("api.key=fixture-dotted-value", "api.key=[REDACTED]"),
        ("api key=fixture-spaced-value", "api key=[REDACTED]"),
        (
            "aws session token=fixture-spaced-session",
            "aws session token=[REDACTED]",
        ),
        ('password="fixture-secret"fixture-hidden', "password=[REDACTED]"),
        ("api_key='fixture-secret'fixture-hidden", "api_key=[REDACTED]"),
        ("SECRET_KEY=fixture-secret-value", "SECRET_KEY=[REDACTED]"),
        ("SESSION_SECRET=fixture-session-value", "SESSION_SECRET=[REDACTED]"),
        ("SESSION_TOKEN=fixture-session-token", "SESSION_TOKEN=[REDACTED]"),
        ("AUTH_TOKEN=fixture-auth-token", "AUTH_TOKEN=[REDACTED]"),
        ("ID_TOKEN=fixture-id-token", "ID_TOKEN=[REDACTED]"),
        ("PRIVATE_TOKEN=fixture-private-token", "PRIVATE_TOKEN=[REDACTED]"),
        ("CREDENTIALS=fixture-credentials", "CREDENTIALS=[REDACTED]"),
        ("PWD=fixture-password", "PWD=[REDACTED]"),
        ("VENDOR_API_KEY=fixture-vendor-key", "VENDOR_API_KEY=[REDACTED]"),
        ("GITHUB_TOKEN=fixture-github-token", "GITHUB_TOKEN=[REDACTED]"),
        ("SSH_PRIVATE_KEY=fixture-ssh-key", "SSH_PRIVATE_KEY=[REDACTED]"),
        ("SERVICE_PASSWORD=fixture-service-password", "SERVICE_PASSWORD=[REDACTED]"),
        ("APP_CLIENT_SECRET=fixture-app-secret", "APP_CLIENT_SECRET=[REDACTED]"),
        ("vendorApiKey=fixture-camel-key", "vendorApiKey=[REDACTED]"),
    ],
)
def test_status_redacts_extended_sensitive_assignment_vocabulary(
    value: str,
    expected: str,
) -> None:
    assert redact_status(value) == expected


@pytest.mark.parametrize(
    "separator",
    [
        "\t",
        "\n",
        "\r\n",
        "\u00a0",
        "\u2003",
        "\u200b",
        "\u200c",
        "\u200d",
        "\u2060",
        "\ufeff",
        "   ",
    ],
)
@pytest.mark.parametrize(
    "parts",
    [
        ("api", "key"),
        ("aws", "session", "token"),
        ("proxy", "authorization"),
    ],
)
def test_status_redacts_bounded_unicode_sensitive_key_separators(
    separator: str,
    parts: tuple[str, ...],
) -> None:
    key = separator.join(parts)
    normalized_key = key.replace("\r", " ")

    assert redact_status(f"{key}=fixture-alias-value") == f"{normalized_key}=[REDACTED]"


@pytest.mark.parametrize("separator", [" " * 5, "\t" * 5, "\ufeff" * 5, "\u0301"])
def test_status_sensitive_key_separator_budget_preserves_near_misses(separator: str) -> None:
    value = f"api{separator}key=fixture-alias-value"

    assert redact_status(value) == value


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "Authorization: Basic fixture-basic-credential",
            "Authorization: [REDACTED]",
        ),
        ("authorization=fixture-session-secret", "authorization=[REDACTED]"),
        (
            "Proxy-Authorization: Digest fixture-digest-value",
            "Proxy-Authorization: [REDACTED]",
        ),
        (
            'Proxy-Authorization: Digest username="fixture-user", response="fixture-response"',
            "Proxy-Authorization: [REDACTED]",
        ),
        (
            "proxy_authorization=fixture-custom-value",
            "proxy_authorization=[REDACTED]",
        ),
        (
            'authorization="Basic fixture secret" trailing',
            'authorization="[REDACTED]" trailing',
        ),
        (
            '{"authorization": "Basic fixture secret", "status": "ready"}',
            '{"authorization": "[REDACTED]", "status": "ready"}',
        ),
        (
            "Authorization: fixture-header\nstatus ready",
            "Authorization: [REDACTED]\nstatus ready",
        ),
        (
            "Authorization: Bearer [REDACTED] fixture-hidden",
            "Authorization: [REDACTED]",
        ),
        (
            "authorization=Basic fixture credential material",
            "authorization=[REDACTED]",
        ),
        (
            "proxy_authorization Digest fixture response material",
            "proxy_authorization [REDACTED]",
        ),
        (
            'authorization="Basic fixture-secret"fixture-hidden',
            "authorization=[REDACTED]",
        ),
        (
            "Authorization:\r\n Basic fixture-credential\nstatus ready",
            "Authorization: [REDACTED]\nstatus ready",
        ),
        (
            "Proxy-Authorization:\n\tDigest fixture-credential",
            "Proxy-Authorization: [REDACTED]",
        ),
        (
            "authorization: >\n  Basic fixture-credential\nstatus ready",
            "authorization: [REDACTED]\nstatus ready",
        ),
    ],
)
def test_status_redacts_generic_authorization_values(value: str, expected: str) -> None:
    assert redact_status(value) == expected


@pytest.mark.parametrize("token", recognizable_token_fixtures())
def test_status_redacts_recognizable_unkeyed_secret_shapes(token: str) -> None:
    assert redact_status(f"before {token} after") == "before [REDACTED] after"


@pytest.mark.parametrize("value", token_near_miss_fixtures())
def test_status_preserves_short_token_shape_near_misses(value: str) -> None:
    assert redact_status(value) == value


def test_status_preserves_publishable_key_shape() -> None:
    value = "pk_live_" + "A" * 24

    assert redact_status(value) == value


def test_status_preserves_namespaced_sensitive_key_near_misses_and_local_paths() -> None:
    value = (
        "APP_PASSWORDLESS=true VENDOR_TOKENIZER=ready TEAM_SECRETARY=assigned "
        r"working at C:\Users\Fixture User\private.txt"
    )

    assert redact_status(value) == value


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "//fixture-user:fixture-password@example.invalid/safe",
            "//[REDACTED]@example.invalid/safe",
        ),
        ("//fixture-user@example.invalid/safe", "//[REDACTED]@example.invalid/safe"),
        (
            "https://fixture-user@example.invalid/safe",
            "https://[REDACTED]@example.invalid/safe",
        ),
        (
            "http://fixture-user@example.invalid/safe",
            "http://[REDACTED]@example.invalid/safe",
        ),
        (
            "ftp://fixture-user@example.invalid/safe",
            "ftp://[REDACTED]@example.invalid/safe",
        ),
        (
            "https://fixture-user:fixture-pa@ss@example.invalid/safe",
            "https://[REDACTED]@example.invalid/safe",
        ),
        (
            "//fixture-user:fixture-pa@ss@example.invalid/safe",
            "//[REDACTED]@example.invalid/safe",
        ),
        (
            "https://:fixture-password@example.invalid/safe",
            "https://[REDACTED]@example.invalid/safe",
        ),
        (
            "https://fixture-user:@example.invalid/safe",
            "https://[REDACTED]@example.invalid/safe",
        ),
        (
            "//:fixture-password@example.invalid/safe",
            "//[REDACTED]@example.invalid/safe",
        ),
        (
            "//fixture-user:@example.invalid/safe",
            "//[REDACTED]@example.invalid/safe",
        ),
        (
            "https://fixture%3Auser:fixture%40password@example.invalid/safe",
            "https://[REDACTED]@example.invalid/safe",
        ),
        (
            "//fixture%3Auser:fixture%40password@example.invalid/safe",
            "//[REDACTED]@example.invalid/safe",
        ),
        (
            "prefix|//fixture-user:fixture-password@example.invalid/safe",
            "prefix|//[REDACTED]@example.invalid/safe",
        ),
        (
            "prefix`//fixture-user:fixture-password@example.invalid/safe",
            "prefix`//[REDACTED]@example.invalid/safe",
        ),
        (
            "prefix\u201d//fixture-user:fixture-password@example.invalid/safe",
            "prefix\u201d//[REDACTED]@example.invalid/safe",
        ),
        (
            "prefix)//fixture-user:fixture-password@example.invalid/safe",
            "prefix)//[REDACTED]@example.invalid/safe",
        ),
        (
            "prefix?//fixture-user:fixture-password@example.invalid/safe",
            "prefix?//[REDACTED]@example.invalid/safe",
        ),
        (
            "prefix#//fixture-user:fixture-password@example.invalid/safe",
            "prefix#//[REDACTED]@example.invalid/safe",
        ),
        (
            "prefix&//fixture-user:fixture-password@example.invalid/safe",
            "prefix&//[REDACTED]@example.invalid/safe",
        ),
    ],
)
def test_status_redacts_schemed_and_protocol_relative_url_userinfo(
    value: str,
    expected: str,
) -> None:
    assert redact_status(value) == expected


def test_status_url_userinfo_redaction_preserves_email_and_safe_protocol_relative_url() -> None:
    value = (
        "email fixture-user@example.invalid remote //example.invalid/safe "
        "encoded https://example.invalid/path%40name nested https://example.invalid/a//user@name"
        " twice-encoded https://example.invalid/a%252F%252Fuser%2540name"
    )

    assert redact_status(value) == value


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://fixture-user:fixture-pass@", "https://[REDACTED]@"),
        ("//fixture-token@", "//[REDACTED]@"),
    ],
)
def test_status_redacts_url_userinfo_even_when_the_host_is_missing(
    value: str,
    expected: str,
) -> None:
    assert redact_status(value) == expected


@pytest.mark.parametrize(
    ("nested", "depth", "location"),
    [
        ("https://fixture-user:fixture-pa@ss@inner.invalid/safe", 1, "query"),
        ("//:fixture-pass@inner.invalid/safe", 2, "fragment"),
    ],
)
def test_status_redacts_encoded_nested_url_userinfo(
    nested: str,
    depth: int,
    location: str,
) -> None:
    encoded = nested
    for _ in range(depth):
        encoded = quote(encoded, safe="")
    separator = "?next=" if location == "query" else "#next="
    value = f"https://outer.invalid/safe{separator}{encoded}"

    assert redact_status(value) == "[REDACTED]"


@pytest.mark.parametrize("nested", ["https://inner.invalid/safe", "//cdn.inner.invalid/safe"])
@pytest.mark.parametrize("depth", [1, 2])
def test_status_preserves_encoded_nested_urls_without_userinfo(nested: str, depth: int) -> None:
    encoded = nested
    for _ in range(depth):
        encoded = quote(encoded, safe="")
    value = f"https://outer.invalid/safe?next={encoded}"

    assert redact_status(value) == value


def test_status_encoded_nested_url_userinfo_fails_closed_beyond_decode_budget() -> None:
    encoded = "https://fixture-user:fixture-pass@inner.invalid/safe"
    for _ in range(3):
        encoded = quote(encoded, safe="")
    value = f"https://outer.invalid/safe?next={encoded}"

    assert redact_status(value) == "[REDACTED]"


@pytest.mark.parametrize(
    ("value", "depth"),
    [
        ("https://fixture-user:fixture-pa@ss@inner.invalid/safe", 1),
        ("//:fixture-pass@inner.invalid/safe", 2),
        ("https://fixture-user:fixture-pass@inner.invalid/safe", 3),
        ("https://fixture-user:fixture-pass@", 1),
    ],
)
def test_status_redacts_direct_encoded_url_userinfo(value: str, depth: int) -> None:
    encoded = value
    for _ in range(depth):
        encoded = quote(encoded, safe="")

    assert redact_status(encoded) == "[REDACTED]"


@pytest.mark.parametrize(
    "value",
    [
        "https://inner.invalid/a/b",
        "//cdn.inner.invalid/a/b",
        "https://inner.invalid/a//user@name",
    ],
)
@pytest.mark.parametrize("depth", [1, 2])
def test_status_preserves_direct_encoded_urls_without_userinfo(value: str, depth: int) -> None:
    encoded = value
    for _ in range(depth):
        encoded = quote(encoded, safe="")

    assert redact_status(encoded) == encoded


@pytest.mark.parametrize(
    "value",
    [
        "Authorization: [REDACTED]",
        "Authorization: Bearer [REDACTED]",
        "https://[REDACTED]@example.invalid/safe",
        "//[REDACTED]@example.invalid/safe",
    ],
)
def test_status_redaction_is_idempotent_for_authorization_and_url_markers(value: str) -> None:
    assert redact_status(value) == value


def test_status_is_unicode_safe_and_bounded_before_regex_work() -> None:
    rendered = redact_status("searching cards " + chr(0) + " " + "dragon" * 20_000, max_length=64)

    assert "\x00" not in rendered
    assert len(rendered) <= 64
    assert rendered == "[REDACTED: OVERSIZED INPUT]"


@pytest.mark.parametrize("quote", ['"', "'"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_status_redacts_complete_multiline_secret_through_closing_quote(
    quote: str,
    newline: str,
) -> None:
    value = f"password={quote}fixture first{newline}fixture second{quote} trailing"

    assert redact_status(value) == f"password={quote}[REDACTED]{quote} trailing"


@pytest.mark.parametrize("quote", ['"', "'"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_status_redacts_unterminated_multiline_secret_through_input_end(
    quote: str,
    newline: str,
) -> None:
    value = f"password={quote}fixture first{newline}fixture second{newline}status: ready"

    assert redact_status(value) == "password=[REDACTED]"


def test_status_preserves_safe_multiline_prose_and_public_material_blocks() -> None:
    public_body = "MII" + "A" * 60
    value = (
        "status: ready\n"
        f"-----BEGIN CERTIFICATE-----\n{public_body}\n"
        "-----END CERTIFICATE-----\n"
        f"-----BEGIN PUBLIC KEY-----\n{public_body}\n"
        "-----END PUBLIC KEY-----\n"
        f"-----BEGIN PGP PUBLIC KEY BLOCK-----\n{public_body}\n"
        "-----END PGP PUBLIC KEY BLOCK-----\n"
        "prose: BEGIN PRIVATE KEY rotation requires approval"
    )

    assert redact_status(value) == value


@pytest.mark.parametrize("label", ["CERTIFICATE", "PUBLIC KEY", "PGP PUBLIC KEY BLOCK"])
def test_status_public_material_blocks_do_not_hide_recognizable_secrets(label: str) -> None:
    token = "sk-" + "A" * 24
    value = f"-----BEGIN {label}-----\n{token}\n-----END {label}-----"

    cleaned = redact_status(value)

    assert cleaned == "[REDACTED]"
    assert token not in cleaned


def test_status_unterminated_public_material_marker_scanning_is_bounded() -> None:
    unit = "-----BEGIN PUBLIC KEY-----"

    def elapsed(size: int) -> float:
        value = (unit * ((size // len(unit)) + 1))[:size]
        started = perf_counter()
        cleaned = redact_status(value)
        duration = perf_counter() - started
        assert len(cleaned) == 2048
        return duration

    small = elapsed(16_384)
    large = elapsed(65_520)

    assert large <= (small * 8) + 0.02


@pytest.mark.parametrize("kind", ["", "RSA ", "EC ", "OPENSSH ", "DSA ", "ENCRYPTED "])
def test_status_redacts_complete_private_key_blocks(kind: str) -> None:
    begin = f"-----BEGIN {kind}PRIVATE KEY-----"
    end = f"-----END {kind}PRIVATE KEY-----"
    value = f"before\n{begin}\nfixture-private-body\n{end}\nafter"

    assert redact_status(value) == "before\n[REDACTED]\nafter"


@pytest.mark.parametrize("kind", ["", "RSA ", "EC ", "OPENSSH ", "DSA ", "ENCRYPTED "])
def test_status_unterminated_private_key_blocks_redact_through_input_end(kind: str) -> None:
    begin = f"-----BEGIN {kind}PRIVATE KEY-----"
    value = f"before\n{begin}\nfixture-private-body\nstatus: ready"

    assert redact_status(value) == "before\n[REDACTED]"


def test_status_redacts_complete_pgp_private_key_block() -> None:
    value = (
        "before\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nfixture-private-body\n"
        "-----END PGP PRIVATE KEY BLOCK-----\nafter"
    )

    assert redact_status(value) == "before\n[REDACTED]\nafter"


def test_status_unterminated_pgp_private_key_block_redacts_through_input_end() -> None:
    value = "before\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nfixture-private-body\nstatus: ready"

    assert redact_status(value) == "before\n[REDACTED]"


def identity() -> ProcessIdentity:
    return ProcessIdentity(
        boot_id="00000000-0000-0000-0000-000000000001",
        pid=4242,
        create_time=1234.5,
        executable="/synthetic/python",
        user="1000",
        user_hash="0" * 64,
    )


def lease_payload(*, heartbeat: datetime) -> dict[str, object]:
    return {
        "protocol_version": 1,
        "agent_id": "00000000-0000-4000-8000-000000000001",
        "registration_nonce": "nonce-0000000000000001",
        "identity": identity().as_dict(),
        "heartbeat_at": heartbeat.isoformat().replace("+00:00", "Z"),
        "heartbeat_timeout_seconds": 10.0,
        "provider": "custom",
        "project": "Synthetic Project",
        "role": "Test Agent",
        "status": "working",
        "detached": False,
        "expected_parent_pid": 4000,
        "expected_owner": "1000",
        "run_id": "00000000-0000-4000-8000-000000000002",
        "lifecycle": "running",
        "terminal_at": None,
        "resources": [],
        "counters": {"requests": 1, "runtime_seconds": 2.5},
    }


def test_process_identity_matches_engine_path_and_user_bounds() -> None:
    from pydantic import ValidationError

    from zombie_killer_engine.leases import LeaseEnvelope

    exact_executable = "/" + "x" * 32_767
    exact_user = "u" * 256
    exact = ProcessIdentity(
        boot_id="boot",
        pid=42,
        create_time=1.0,
        executable=exact_executable,
        user=exact_user,
    )
    candidate = lease_payload(heartbeat=datetime.now(UTC))
    candidate["identity"] = exact.as_dict()

    assert LeaseEnvelope.model_validate(candidate).identity.executable == exact_executable
    with pytest.raises(ValueError, match="executable"):
        ProcessIdentity(boot_id="boot", pid=42, create_time=1.0, executable="/" + "x" * 32_768)
    with pytest.raises(ValueError, match="user"):
        ProcessIdentity(boot_id="boot", pid=42, create_time=1.0, user="u" * 257)
    overbound = dict(candidate)
    overbound["identity"] = {**exact.as_dict(), "executable": "/" + "x" * 32_768}
    with pytest.raises(ValidationError):
        LeaseEnvelope.model_validate(overbound)


def test_resource_protocol_path_bound_matches_engine_parser() -> None:
    from pydantic import ValidationError

    from zombie_killer_engine.leases import LeaseEnvelope

    exact = "/" + "x" * 4095
    payload = lease_payload(heartbeat=datetime.now(UTC))
    payload["resources"] = [{"kind": "temporary", "path": exact}]

    assert require_protocol_path(exact, field="resource path") == exact
    assert LeaseEnvelope.model_validate(payload).resources[0].path == exact
    with pytest.raises(ValueError, match="resource path"):
        require_protocol_path("/" + "x" * 4096, field="resource path")
    payload["resources"] = [{"kind": "temporary", "path": "/" + "x" * 4096}]
    with pytest.raises(ValidationError):
        LeaseEnvelope.model_validate(payload)


def test_atomic_lease_is_bounded_and_engine_compatible(tmp_path: Path) -> None:
    from zombie_killer_engine.leases import discover_leases

    store = LeaseStore(tmp_path, strict=True)
    payload = lease_payload(heartbeat=datetime(2026, 8, 12, tzinfo=UTC))

    assert store.write_lease(str(payload["agent_id"]), payload)
    lease_path = store.lease_path(str(payload["agent_id"]))
    assert lease_path.stat().st_size <= 128 * 1024
    assert not tuple(store.leases_dir.glob("*.tmp"))
    discovery = discover_leases(store.leases_dir)
    assert discovery.malformed_count == 0
    assert len(discovery.leases) == 1
    assert discovery.leases[0].lease.registration_nonce == payload["registration_nonce"]


def test_verified_directory_replacement_fails_closed(tmp_path: Path) -> None:
    store = LeaseStore(tmp_path / "state")
    assert store.prepare()
    original = store.leases_dir
    displaced = tmp_path / "displaced-leases"
    original.rename(displaced)
    original.mkdir(mode=0o700)

    candidate = lease_payload(heartbeat=datetime.now(UTC))

    assert not store.write_lease(str(candidate["agent_id"]), candidate)
    assert not (original / f"{candidate['agent_id']}.json").exists()
    assert store.last_warning == "DIRECTORY_AUTHORITY_CHANGED"


def test_real_boot_identity_matches_engine() -> None:
    from zombie_killer_engine.scanner import current_boot_id as engine_boot_id

    assert current_boot_id() == engine_boot_id()


def test_default_runtime_path_matches_engine_platform_convention() -> None:
    from zombie_killer_engine.paths import AppPaths

    assert default_runtime_dir() == AppPaths.for_current_user().runtime_dir


def test_default_runtime_resolution_never_accesses_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from zombie_killer_engine.paths import AppPaths

    class EnvironmentDenied(dict[str, str]):
        def get(self, key: str, default: str | None = None) -> str | None:
            raise AssertionError(f"environment access denied: {key}")

        def __getitem__(self, key: str) -> str:
            raise AssertionError(f"environment access denied: {key}")

    assert "os.environ" not in inspect.getsource(default_runtime_dir)
    with monkeypatch.context() as environment_guard:
        environment_guard.setattr(os, "environ", EnvironmentDenied())
        sdk_path = default_runtime_dir()
        engine_path = AppPaths.for_current_user().runtime_dir

    assert sdk_path.is_absolute()
    assert engine_path == sdk_path


def test_linux_runtime_prefers_only_safe_owned_run_user_directory(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    run_user = tmp_path / "run" / "1000"
    run_user.mkdir(parents=True)
    run_user.chmod(0o700)

    assert (
        posix_runtime_dir(
            system="linux",
            uid=1000,
            home=home,
            run_user=run_user,
            owner_uid=1000,
            mode=0o700,
            direct=True,
        )
        == run_user / "Zombie Killer"
    )
    assert (
        posix_runtime_dir(
            system="linux",
            uid=1000,
            home=home,
            run_user=run_user,
            owner_uid=1001,
            mode=0o700,
            direct=True,
        )
        == home / ".local" / "state" / "Zombie Killer" / "runtime"
    )
    run_user.chmod(0o777)
    assert (
        posix_runtime_dir(
            system="linux",
            uid=1000,
            home=home,
            run_user=run_user,
            owner_uid=1000,
            mode=0o777,
            direct=True,
        )
        == home / ".local" / "state" / "Zombie Killer" / "runtime"
    )


def test_macos_runtime_uses_passwd_home_application_support(tmp_path: Path) -> None:
    assert (
        posix_runtime_dir(system="darwin", uid=1000, home=tmp_path, run_user=None, owner_uid=None)
        == tmp_path / "Library" / "Application Support" / "Zombie Killer" / "runtime"
    )


def test_oversized_lease_is_rejected_before_replace(tmp_path: Path) -> None:
    store = LeaseStore(tmp_path, strict=True)
    payload = lease_payload(heartbeat=datetime.now(UTC))
    payload["status"] = "x" * (128 * 1024)

    with pytest.raises(ValueError, match="128 KiB"):
        store.write_lease(str(payload["agent_id"]), payload)
    assert not store.lease_path(str(payload["agent_id"])).exists()


def cancellation_payload(
    *, nonce: str = "nonce-0000000000000001", request_id: str = "request-1"
) -> dict[str, object]:
    now = datetime(2026, 8, 12, 12, tzinfo=UTC)
    return {
        "protocol_version": 2,
        "agent_id": "00000000-0000-4000-8000-000000000001",
        "registration_nonce": nonce,
        "plan_id": "plan-1",
        "request_id": request_id,
        "target": cancellation_target(identity()),
        "requested_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=30)).isoformat().replace("+00:00", "Z"),
    }


def test_cancellation_accepts_exact_generation_and_acknowledges(tmp_path: Path) -> None:
    store = LeaseStore(tmp_path, strict=True)
    payload = cancellation_payload()
    store.write_cancellation_for_test(str(payload["agent_id"]), payload)

    accepted = store.poll_cancellation(
        str(payload["agent_id"]),
        registration_nonce=str(payload["registration_nonce"]),
        identity=identity(),
        now=datetime(2026, 8, 12, 12, 0, 1, tzinfo=UTC),
    )

    assert accepted is not None
    assert accepted["request_id"] == "request-1"
    acknowledgement = json.loads(store.ack_path(str(payload["agent_id"])).read_text())
    assert acknowledgement == {
        "protocol_version": 2,
        "agent_id": payload["agent_id"],
        "request_id": "request-1",
    }
    assert (
        store.poll_cancellation(
            str(payload["agent_id"]),
            registration_nonce=str(payload["registration_nonce"]),
            identity=identity(),
            now=datetime(2026, 8, 12, 12, 0, 2, tzinfo=UTC),
        )
        is None
    )


def test_cancellation_rejects_a_b_a_replay(tmp_path: Path) -> None:
    store = LeaseStore(tmp_path, strict=True)
    agent_id = "00000000-0000-4000-8000-000000000001"
    observed = datetime(2026, 8, 12, 12, 0, 1, tzinfo=UTC)

    for request_id in ("request-a", "request-b"):
        store.write_cancellation_for_test(agent_id, cancellation_payload(request_id=request_id))
        assert (
            store.poll_cancellation(
                agent_id,
                registration_nonce="nonce-0000000000000001",
                identity=identity(),
                now=observed,
            )
            is not None
        )

    store.write_cancellation_for_test(agent_id, cancellation_payload(request_id="request-a"))
    assert (
        store.poll_cancellation(
            agent_id,
            registration_nonce="nonce-0000000000000001",
            identity=identity(),
            now=observed,
        )
        is None
    )
    assert store.last_warning == "CANCELLATION_REUSED"


def test_engine_published_cancellation_is_consumed_by_sdk(tmp_path: Path) -> None:
    from zombie_killer_engine.leases import write_cancellation_request
    from zombie_killer_engine.models import ProcessIdentity as EngineIdentity

    store = LeaseStore(tmp_path, strict=True)
    assert store.prepare()
    own_identity = current_process_identity()
    now = datetime.now(UTC)
    write_cancellation_request(
        store.cancellations_dir,
        "00000000-0000-4000-8000-000000000001",
        target_identity=EngineIdentity(**own_identity.as_dict()),
        registration_nonce="nonce-0000000000000001",
        plan_id="plan-1",
        requested_at=now,
        expires_at=now + timedelta(seconds=30),
    )

    request = store.poll_cancellation(
        "00000000-0000-4000-8000-000000000001",
        registration_nonce="nonce-0000000000000001",
        identity=own_identity,
        now=now + timedelta(seconds=1),
    )

    assert request is not None
    if os.name != "nt":
        assert (
            request["target"]["user_hash"]
            == hashlib.sha256(str(os.geteuid()).encode("ascii")).hexdigest()
        )


@pytest.mark.parametrize("mutation", ["nonce", "expired", "identity", "legacy"])
def test_cancellation_rejects_unbound_or_expired_requests(tmp_path: Path, mutation: str) -> None:
    store = LeaseStore(tmp_path, strict=True)
    payload = cancellation_payload(
        nonce="wrong" if mutation == "nonce" else "nonce-0000000000000001"
    )
    if mutation == "expired":
        payload["expires_at"] = "2026-08-12T12:00:00Z"
    elif mutation == "identity":
        target = dict(payload["target"])
        target["pid"] = 4243
        payload["target"] = target
    elif mutation == "legacy":
        payload["protocol_version"] = 1
    store.write_cancellation_for_test(str(payload["agent_id"]), payload)

    assert (
        store.poll_cancellation(
            str(payload["agent_id"]),
            registration_nonce="nonce-0000000000000001",
            identity=identity(),
            now=datetime(2026, 8, 12, 12, 0, 1, tzinfo=UTC),
        )
        is None
    )
    assert not store.ack_path(str(payload["agent_id"])).exists()
    assert store.last_warning is not None


def test_temp_resource_requires_owned_direct_descendant(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "worker.tmp"
    target.write_text("synthetic", encoding="utf-8")

    resource = validate_temp_resource(target, root=root)

    assert resource["kind"] == "temporary"
    assert resource["path"] == str(target.resolve())
    assert resource["approved_root"] == str(root.resolve())
    assert resource["resource_type"] == "file"
    assert resource["cleanup_policy"] == "quarantine"
    fingerprint = resource["creation_fingerprint"]
    assert isinstance(fingerprint, dict)
    assert fingerprint["inode"] == target.stat().st_ino
    assert fingerprint["content_digest"] == hashlib.sha256(b"synthetic").hexdigest()
    with pytest.raises(ValueError):
        validate_temp_resource(root, root=root)
    with pytest.raises(ValueError):
        validate_temp_resource(Path("relative.tmp"), root=root)
    with pytest.raises(ValueError):
        validate_temp_resource(tmp_path / "outside.tmp", root=root)
    if os.name == "nt":
        with pytest.raises(ValueError):
            validate_temp_resource(Path(str(target) + ":stream"), root=root)


def test_directory_declaration_changes_when_nested_file_bytes_change(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    nested = root / "tree" / "nested"
    nested.mkdir(parents=True)
    target = nested / "artifact.bin"
    target.write_bytes(b"first bytes")
    first = validate_temp_resource(root / "tree", root=root)

    target.write_bytes(b"other bytes")
    second = validate_temp_resource(root / "tree", root=root)

    assert first["resource_type"] == "directory"
    assert first["creation_fingerprint"] != second["creation_fingerprint"]


def test_declared_file_mtime_may_differ_from_its_windows_creation_time(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "artifact.bin"
    target.write_bytes(b"owned declaration fixture")
    observed = target.stat()
    os.utime(target, ns=(observed.st_atime_ns, observed.st_mtime_ns + 1_000_000_000))

    resource = validate_temp_resource(target, root=root)

    assert resource["creation_fingerprint"]["mtime_ns"] == target.stat().st_mtime_ns
    assert resource["creation_fingerprint"]["ctime_ns"] == target.stat().st_ctime_ns
