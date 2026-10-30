from collections.abc import Callable
from time import perf_counter
from urllib.parse import quote

import pytest

from zombie_killer_engine.redaction import redact_display_text, redact_mapping, redact_text


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


def test_redacts_case_insensitive_bearer_authorization_and_preserves_context() -> None:
    value = "request=scan aUtHoRiZaTiOn: bEaReR synthetic-bearer-value status=ready"

    cleaned = redact_text(value)

    assert cleaned == "request=scan aUtHoRiZaTiOn: bEaReR [REDACTED] status=ready"
    assert "synthetic-bearer-value" not in cleaned


def test_redacts_bare_case_insensitive_bearer_value() -> None:
    value = "request=scan bEaReR synthetic-bare-bearer-value status=ready"

    cleaned = redact_text(value)

    assert cleaned == "request=scan bEaReR [REDACTED] status=ready"
    assert "synthetic-bare-bearer-value" not in cleaned


def test_redacts_long_jwt_like_values_without_redacting_dotted_versions() -> None:
    jwt_like = "syntheticHeaderSegment123.syntheticPayloadSegment456.syntheticSignatureSegment789"
    value = f"version=2.13.4 credential={jwt_like} state=ready"

    cleaned = redact_text(value)

    assert cleaned == "version=2.13.4 credential=[REDACTED] state=ready"
    assert jwt_like not in cleaned


@pytest.mark.parametrize(
    ("value", "secret", "expected"),
    [
        (
            "agent --api-key synthetic-api-key next",
            "synthetic-api-key",
            "agent --api-key [REDACTED] next",
        ),
        (
            "agent --token=synthetic-token next",
            "synthetic-token",
            "agent --token=[REDACTED] next",
        ),
        (
            "user=demo password=synthetic-password mode=local",
            "synthetic-password",
            "user=demo password=[REDACTED] mode=local",
        ),
    ],
)
def test_redacts_named_secret_values(value: str, secret: str, expected: str) -> None:
    cleaned = redact_text(value)

    assert cleaned == expected
    assert secret not in cleaned


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            'agent --password "two word secret" --mode local',
            'agent --password "[REDACTED]" --mode local',
        ),
        (
            "agent --api-key='two word secret' --mode local",
            "agent --api-key='[REDACTED]' --mode local",
        ),
        (
            'agent --token "two word secret" trailing-safe-text',
            'agent --token "[REDACTED]" trailing-safe-text',
        ),
    ],
)
def test_redacts_complete_quoted_named_secret_values(value: str, expected: str) -> None:
    cleaned = redact_text(value)

    assert cleaned == expected
    assert "two word secret" not in cleaned
    assert "word secret" not in cleaned


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            'json={"password": "synthetic json secret"} safe=true',
            'json={"password": "[REDACTED]"} safe=true',
        ),
        (
            "X-API-Key: fake-value\nstatus: ready",
            "X-API-Key: [REDACTED]\nstatus: ready",
        ),
        (
            "agent -token synthetic-single-dash-secret next",
            "agent -token [REDACTED] next",
        ),
        (
            "password: synthetic-colon-secret status=ready",
            "password: [REDACTED] status=ready",
        ),
    ],
)
def test_redacts_exact_sensitive_assignment_forms(value: str, expected: str) -> None:
    assert redact_text(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "tool --client-secret fake-client-value next",
            "tool --client-secret [REDACTED] next",
        ),
        (
            "access_token: fake-access-value status=ready",
            "access_token: [REDACTED] status=ready",
        ),
        (
            "Refresh-Token=fake-refresh-value status=ready",
            "Refresh-Token=[REDACTED] status=ready",
        ),
        (
            "secret: fake-generic-value status=ready",
            "secret: [REDACTED] status=ready",
        ),
        (
            "AWS_SECRET_ACCESS_KEY: fake-aws-value\nstatus: ready",
            "AWS_SECRET_ACCESS_KEY: [REDACTED]\nstatus: ready",
        ),
    ],
)
def test_redacts_canonical_secret_vocabulary_variants(
    value: str,
    expected: str,
) -> None:
    assert redact_text(value) == expected


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
def test_redacts_extended_sensitive_assignment_vocabulary(value: str, expected: str) -> None:
    assert redact_text(value) == expected


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
def test_redacts_bounded_unicode_sensitive_key_separators(
    separator: str,
    parts: tuple[str, ...],
) -> None:
    key = separator.join(parts)

    assert redact_text(f"{key}=fixture-alias-value") == f"{key}=[REDACTED]"


@pytest.mark.parametrize("separator", [" " * 5, "\t" * 5, "\ufeff" * 5, "\u0301"])
def test_sensitive_key_separator_budget_preserves_near_misses(separator: str) -> None:
    value = f"api{separator}key=fixture-alias-value"

    assert redact_text(value) == value


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
def test_redacts_generic_authorization_values(value: str, expected: str) -> None:
    assert redact_text(value) == expected


@pytest.mark.parametrize("token", recognizable_token_fixtures())
def test_redacts_recognizable_unkeyed_secret_shapes(token: str) -> None:
    assert redact_text(f"before {token} after") == "before [REDACTED] after"


@pytest.mark.parametrize("value", token_near_miss_fixtures())
def test_preserves_short_token_shape_near_misses(value: str) -> None:
    assert redact_text(value) == value


def test_preserves_publishable_key_shape() -> None:
    value = "pk_live_" + "A" * 24

    assert redact_text(value) == value


def test_does_not_redact_safe_sensitive_key_near_misses() -> None:
    value = (
        "tokenizer: enabled api-keyboard=compact passwordless=true "
        "client-secretary=present access-tokenizer=enabled"
    )

    assert redact_text(value) == value


def test_preserves_namespaced_sensitive_key_near_misses() -> None:
    value = "APP_PASSWORDLESS=true VENDOR_TOKENIZER=ready TEAM_SECRETARY=assigned"

    assert redact_text(value) == value


@pytest.mark.parametrize("quote", ['"', "'"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_complete_multiline_quoted_secret_redacts_through_closing_quote(
    quote: str,
    newline: str,
) -> None:
    value = f"agent --password {quote}fixture first{newline}fixture second{quote} trailing"

    cleaned = redact_text(value)

    assert cleaned == f"agent --password {quote}[REDACTED]{quote} trailing"
    assert "fixture first" not in cleaned
    assert "fixture second" not in cleaned


@pytest.mark.parametrize("quote", ['"', "'"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_unterminated_multiline_quoted_secret_redacts_through_input_end(
    quote: str,
    newline: str,
) -> None:
    value = f"agent --password {quote}fixture first{newline}fixture second{newline}status: ready"

    cleaned = redact_text(value)

    assert cleaned == "agent --password [REDACTED]"
    assert "fixture first" not in cleaned
    assert "fixture second" not in cleaned
    assert "status: ready" not in cleaned


def test_preserves_safe_multiline_prose_and_public_material_blocks() -> None:
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

    assert redact_text(value) == value


@pytest.mark.parametrize("label", ["CERTIFICATE", "PUBLIC KEY", "PGP PUBLIC KEY BLOCK"])
def test_public_material_blocks_do_not_hide_recognizable_secrets(label: str) -> None:
    token = "sk-" + "A" * 24
    value = f"-----BEGIN {label}-----\n{token}\n-----END {label}-----"

    cleaned = redact_text(value)

    assert cleaned == "[REDACTED]"
    assert token not in cleaned


def test_unterminated_public_material_marker_scanning_is_bounded() -> None:
    unit = "-----BEGIN PUBLIC KEY-----"

    def elapsed(size: int) -> float:
        value = (unit * ((size // len(unit)) + 1))[:size]
        started = perf_counter()
        assert redact_text(value, max_length=size) == value
        return perf_counter() - started

    small = elapsed(16_384)
    large = elapsed(65_520)

    assert large <= (small * 8) + 0.02


@pytest.mark.parametrize("kind", ["", "RSA ", "EC ", "OPENSSH ", "DSA ", "ENCRYPTED "])
def test_redacts_complete_private_key_blocks(kind: str) -> None:
    begin = f"-----BEGIN {kind}PRIVATE KEY-----"
    end = f"-----END {kind}PRIVATE KEY-----"
    value = f"before\n{begin}\nfixture-private-body\n{end}\nafter"

    assert redact_text(value) == "before\n[REDACTED]\nafter"


@pytest.mark.parametrize("kind", ["", "RSA ", "EC ", "OPENSSH ", "DSA ", "ENCRYPTED "])
def test_unterminated_private_key_blocks_redact_through_input_end(kind: str) -> None:
    begin = f"-----BEGIN {kind}PRIVATE KEY-----"
    value = f"before\n{begin}\nfixture-private-body\nstatus: ready"

    assert redact_text(value) == "before\n[REDACTED]"


def test_redacts_complete_pgp_private_key_block() -> None:
    value = (
        "before\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nfixture-private-body\n"
        "-----END PGP PRIVATE KEY BLOCK-----\nafter"
    )

    assert redact_text(value) == "before\n[REDACTED]\nafter"


def test_unterminated_pgp_private_key_block_redacts_through_input_end() -> None:
    value = "before\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nfixture-private-body\nstatus: ready"

    assert redact_text(value) == "before\n[REDACTED]"


def test_redacts_url_userinfo_credentials_and_preserves_url_context() -> None:
    value = "fetch https://synthetic-user:synthetic-password@example.invalid/private then continue"

    cleaned = redact_text(value)

    assert cleaned == "fetch https://[REDACTED]@example.invalid/private then continue"
    assert "synthetic-user" not in cleaned
    assert "synthetic-password" not in cleaned


@pytest.mark.parametrize("redactor", [redact_text, redact_display_text])
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
def test_redacts_schemed_and_protocol_relative_url_userinfo(
    redactor: Callable[[object | None], str],
    value: str,
    expected: str,
) -> None:
    assert redactor(value) == expected


@pytest.mark.parametrize("redactor", [redact_text, redact_display_text])
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://fixture-user:fixture-pass@", "https://[REDACTED]@"),
        ("//fixture-token@", "//[REDACTED]@"),
    ],
)
def test_redacts_url_userinfo_even_when_the_host_is_missing(
    redactor: Callable[[object | None], str],
    value: str,
    expected: str,
) -> None:
    assert redactor(value) == expected


@pytest.mark.parametrize("redactor", [redact_text, redact_display_text])
def test_url_userinfo_redaction_preserves_email_and_safe_protocol_relative_url(
    redactor: Callable[[object | None], str],
) -> None:
    value = (
        "email fixture-user@example.invalid remote //example.invalid/safe "
        "encoded https://example.invalid/path%40name nested https://example.invalid/a//user@name"
        " twice-encoded https://example.invalid/a%252F%252Fuser%2540name"
    )

    assert redactor(value) == value


@pytest.mark.parametrize("redactor", [redact_text, redact_display_text])
@pytest.mark.parametrize(
    ("nested", "depth", "location"),
    [
        ("https://fixture-user:fixture-pa@ss@inner.invalid/safe", 1, "query"),
        ("//:fixture-pass@inner.invalid/safe", 2, "fragment"),
    ],
)
def test_redacts_encoded_nested_url_userinfo(
    redactor: Callable[[object | None], str],
    nested: str,
    depth: int,
    location: str,
) -> None:
    encoded = nested
    for _ in range(depth):
        encoded = quote(encoded, safe="")
    separator = "?next=" if location == "query" else "#next="
    value = f"https://outer.invalid/safe{separator}{encoded}"

    assert redactor(value) == "[REDACTED]"


@pytest.mark.parametrize("redactor", [redact_text, redact_display_text])
@pytest.mark.parametrize("nested", ["https://inner.invalid/safe", "//cdn.inner.invalid/safe"])
@pytest.mark.parametrize("depth", [1, 2])
def test_preserves_encoded_nested_urls_without_userinfo(
    redactor: Callable[[object | None], str],
    nested: str,
    depth: int,
) -> None:
    encoded = nested
    for _ in range(depth):
        encoded = quote(encoded, safe="")
    value = f"https://outer.invalid/safe?next={encoded}"

    assert redactor(value) == value


@pytest.mark.parametrize("redactor", [redact_text, redact_display_text])
def test_encoded_nested_url_userinfo_fails_closed_beyond_decode_budget(
    redactor: Callable[[object | None], str],
) -> None:
    encoded = "https://fixture-user:fixture-pass@inner.invalid/safe"
    for _ in range(3):
        encoded = quote(encoded, safe="")
    value = f"https://outer.invalid/safe?next={encoded}"

    assert redactor(value) == "[REDACTED]"


@pytest.mark.parametrize("redactor", [redact_text, redact_display_text])
@pytest.mark.parametrize(
    ("value", "depth"),
    [
        ("https://fixture-user:fixture-pa@ss@inner.invalid/safe", 1),
        ("//:fixture-pass@inner.invalid/safe", 2),
        ("https://fixture-user:fixture-pass@inner.invalid/safe", 3),
        ("https://fixture-user:fixture-pass@", 1),
    ],
)
def test_redacts_direct_encoded_url_userinfo(
    redactor: Callable[[object | None], str],
    value: str,
    depth: int,
) -> None:
    encoded = value
    for _ in range(depth):
        encoded = quote(encoded, safe="")

    assert redactor(encoded) == "[REDACTED]"


@pytest.mark.parametrize("redactor", [redact_text, redact_display_text])
@pytest.mark.parametrize(
    "value",
    [
        "https://inner.invalid/a/b",
        "//cdn.inner.invalid/a/b",
        "https://inner.invalid/a//user@name",
    ],
)
@pytest.mark.parametrize("depth", [1, 2])
def test_preserves_direct_encoded_urls_without_userinfo(
    redactor: Callable[[object | None], str],
    value: str,
    depth: int,
) -> None:
    encoded = value
    for _ in range(depth):
        encoded = quote(encoded, safe="")

    assert redactor(encoded) == encoded


@pytest.mark.parametrize("redactor", [redact_text, redact_display_text])
@pytest.mark.parametrize(
    "value",
    [
        "Authorization: [REDACTED]",
        "Authorization: Bearer [REDACTED]",
        "https://[REDACTED]@example.invalid/safe",
        "//[REDACTED]@example.invalid/safe",
    ],
)
def test_redaction_is_idempotent_for_authorization_and_url_markers(
    redactor: Callable[[object | None], str],
    value: str,
) -> None:
    assert redactor(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "/opt/private/data.json",
        "/mnt/private volume/file",
        "/workspace",
        r"C:\Users\Fixture User\secret file.txt",
        r"\\server\private share\secret file.txt",
        r"\Users\Fixture User\secret file.txt",
        "//server/private share/secret.txt",
        "path=/workspace/cache safe suffix",
    ],
)
def test_display_redacts_entire_field_for_absolute_local_paths(value: str) -> None:
    assert redact_display_text(value) == "[LOCAL PATH]"


@pytest.mark.parametrize(
    "prefix",
    ["!", "@", "+", "\u2014", "\u20ac", "\U0001f6e1", "\U0001f6e1\ufe0f"],
)
def test_display_treats_unicode_punctuation_and_symbols_as_local_path_boundaries(
    prefix: str,
) -> None:
    assert redact_display_text(f"{prefix}/opt/private.txt") == "[LOCAL PATH]"
    assert redact_display_text(rf"{prefix}C:\private\fixture.txt") == "[LOCAL PATH]"
    assert redact_display_text(rf"{prefix}\Users\Fixture\private.txt") == "[LOCAL PATH]"


@pytest.mark.parametrize(
    "value",
    [
        "e\u0301/opt",
        "_/opt",
        "component/opt",
        "9/opt",
        "\u5b57/opt",
        "\u20achttps://example.invalid/a/b",
        "\u20ac//cdn.example.invalid/a/b",
    ],
)
def test_display_preserves_non_boundary_words_and_symbol_prefixed_remote_urls(value: str) -> None:
    assert redact_display_text(value) == value


@pytest.mark.parametrize(
    ("delimiter", "local_path"),
    [
        ("\u2014", "/private/x"),
        ("`", "/private/x"),
        ("\u201d", "/private/x"),
        ("]", "/private/x"),
        ("&", "/private/x"),
        ("\u2014", r"C:\private\fixture.txt"),
        ("]", r"\\server\private\fixture.txt"),
    ],
)
def test_display_detects_local_path_suffixes_adjacent_to_remote_urls(
    delimiter: str,
    local_path: str,
) -> None:
    value = f"https://example.invalid/safe{delimiter}{local_path}"

    assert redact_display_text(value) == "[LOCAL PATH]"


@pytest.mark.parametrize(
    "value",
    [
        r"https://example.invalid,C:\private\file.txt",
        "https://example.invalid,C:/private/file.txt",
        "ftp://example.invalid;C:/private/file.txt",
    ],
)
def test_display_detects_local_path_hidden_in_schemed_url_authority(value: str) -> None:
    assert redact_display_text(value) == "[LOCAL PATH]"


@pytest.mark.parametrize(
    "value",
    [
        "https://[::1]/safe/path",
        "https://example.invalid/a//user@name",
        "https://example.invalid/a-/b",
        "https://example.invalid/a,b",
        "https://example.invalid:443/private/file.txt",
        "https://example.invalid/safe?next=https://cdn.example.invalid/a/b&ratio=1/2",
        "//[::1]/safe/path?mode=read/write#version=v1.2.3/4.5.6",
        "//example.invalid./safe/path",
        "//localhost./safe/path",
        "//例子.测试/safe/path",
    ],
)
def test_display_remote_url_masking_preserves_ipv6_nested_urls_and_safe_queries(value: str) -> None:
    assert redact_display_text(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "https://example.invalid/safe?next=/workspace/private.txt",
        "https://example.invalid/safe?next=%2Fworkspace%2Fprivate.txt",
        "https://example.invalid/safe?next=%252Fworkspace%252Fprivate.txt",
        "https://example.invalid/safe?next=%25252Fworkspace%25252Fprivate.txt",
        "https://example.invalid/safe#next=/opt/private.txt",
        "https://example.invalid/safe#next=%2543%253A%255CFixture%255Cprivate.txt",
        "//cdn.example.invalid/safe?next=%2Fmnt%2Fprivate.txt",
        "//cdn.example.invalid/safe?next=/mnt/private.txt",
        "//cdn.example.invalid/safe#next=%2Fworkspace%2Fprivate.txt",
        "https://example.invalid/safe?next=C%3A%5CUsers%5CFixture%20User%5Cprivate.txt",
        "https://example.invalid/safe?next=%ZZ",
    ],
)
def test_display_redacts_local_paths_in_remote_url_query_or_fragment(value: str) -> None:
    assert redact_display_text(value) == "[LOCAL PATH]"


@pytest.mark.parametrize(
    ("value", "depth"),
    [
        ("/workspace/private.txt", 1),
        (r"C:\Fixture User\private.txt", 2),
        (r"\\server\private share\fixture.txt", 1),
        ("/opt/private.txt", 3),
    ],
)
def test_display_redacts_direct_encoded_absolute_local_paths(value: str, depth: int) -> None:
    encoded = value
    for _ in range(depth):
        encoded = quote(encoded, safe="")

    assert redact_display_text(encoded) == "[LOCAL PATH]"


@pytest.mark.parametrize(
    "value", ["https://inner.invalid/a/b", "//cdn.inner.invalid/a/b", "2026/08/12", "1/2"]
)
@pytest.mark.parametrize("depth", [1, 2])
def test_display_preserves_direct_encoded_remote_urls_dates_and_math(
    value: str,
    depth: int,
) -> None:
    encoded = value
    for _ in range(depth):
        encoded = quote(encoded, safe="")

    assert redact_display_text(encoded) == encoded


@pytest.mark.parametrize(
    "value",
    [
        "https://example.invalid/safe?date=2026%2F08%2F12",
        "https://example.invalid/safe?ratio=1%252F2",
        "https://example.invalid/safe?next=https%253A%252F%252Fcdn.example.invalid%252Fa%252Fb",
    ],
)
def test_display_preserves_safe_encoded_remote_query_values(value: str) -> None:
    assert redact_display_text(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "http://example.invalid/a/b",
        "https://example.invalid/a%2Fb",
        "ftp://files.example.invalid/pub/item",
        "//cdn.example.invalid/assets/app.js",
        "//localhost/assets/app.js",
        "//127.0.0.1/assets/app.js",
        "//[::1]/assets/app.js",
        "2026/08/12",
        "1/2",
        "10 / 2",
        "Progress 100% complete",
        "safe%20text and 100% done",
        "progress 100% complete code=%20",
        "hello%252520world",
        "read/write",
        "v1.2.3/4.5.6",
        "/",
        '{"ratio":"1/2"}',
    ],
)
def test_display_preserves_remote_urls_and_non_path_slash_expressions(value: str) -> None:
    assert redact_display_text(value) == value


def test_redacts_before_deterministic_bounded_truncation() -> None:
    secret = "synthetic-secret-that-must-never-be-partially-visible"
    value = f"before --token={secret} after " + ("safe " * 40)

    cleaned = redact_text(value, max_length=40)

    assert len(cleaned) == 40
    assert cleaned.endswith("…[TRUNCATED]")
    assert cleaned.startswith("before --token=[REDACTED]")
    assert secret not in cleaned
    assert "synthetic-secret" not in cleaned


@pytest.mark.parametrize(("value", "expected"), [(None, ""), (42, "42"), (False, "False")])
def test_tolerates_none_and_non_string_inputs(value: object, expected: str) -> None:
    assert redact_text(value) == expected


@pytest.mark.parametrize("max_length", [0, 1, 5, 12])
def test_respects_caps_at_or_below_the_truncation_marker(max_length: int) -> None:
    cleaned = redact_text("--token=synthetic-secret-value", max_length=max_length)

    assert len(cleaned) <= max_length
    assert "synthetic" not in cleaned


def test_rejects_negative_output_cap() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        redact_text("safe text", max_length=-1)


def test_recursively_redacts_sensitive_mapping_keys_without_mutation() -> None:
    value: dict[str, object] = {
        "project": "safe-project",
        "api_key": "synthetic-api-value",
        "AWS_SECRET_ACCESS_KEY": "fake-aws-value",
        "AWS_SESSION_TOKEN": "fake-session-value",
        "private_key": "fixture-private-value",
        "passphrase": "fixture-passphrase-value",
        "seed phrase": "fixture-seed-value",
        "credential": "fixture-credential-value",
        "command": "tool --client-secret fake-client-value next",
        "nested": {
            "token": "synthetic-token-value",
            "tokenizer": "safe-tokenizer",
        },
        "items": [{"password": "synthetic-password-value", "status": "ready"}],
    }

    cleaned = redact_mapping(value)

    assert cleaned == {
        "project": "safe-project",
        "api_key": "[REDACTED]",
        "AWS_SECRET_ACCESS_KEY": "[REDACTED]",
        "AWS_SESSION_TOKEN": "[REDACTED]",
        "private_key": "[REDACTED]",
        "passphrase": "[REDACTED]",
        "seed phrase": "[REDACTED]",
        "credential": "[REDACTED]",
        "command": "tool --client-secret [REDACTED] next",
        "nested": {"token": "[REDACTED]", "tokenizer": "safe-tokenizer"},
        "items": [{"password": "[REDACTED]", "status": "ready"}],
    }
    assert value["api_key"] == "synthetic-api-value"


def test_redact_mapping_sanitizes_secret_bearing_keys_without_collisions() -> None:
    value = {
        "api_key=fixture-key-in-name": "safe-one",
        "[REDACTED_KEY_1]": "safe-two",
        "nested": {"credential=fixture-nested-key": "safe-three"},
    }

    cleaned = redact_mapping(value)
    serialized = repr(cleaned)

    assert "fixture-key-in-name" not in serialized
    assert "fixture-nested-key" not in serialized
    assert sorted(str(item) for item in cleaned.values() if not isinstance(item, dict)) == [
        "safe-one",
        "safe-two",
    ]
    assert cleaned["nested"] != value["nested"]
    assert value["api_key=fixture-key-in-name"] == "safe-one"


@pytest.mark.parametrize(
    "key",
    [
        "SECRET_KEY",
        "SESSION_SECRET",
        "SESSION_TOKEN",
        "AUTH_TOKEN",
        "ID_TOKEN",
        "PRIVATE_TOKEN",
        "CREDENTIALS",
        "PWD",
        "VENDOR_API_KEY",
        "GITHUB_TOKEN",
        "SSH_PRIVATE_KEY",
        "SERVICE_PASSWORD",
        "APP_CLIENT_SECRET",
        "vendorApiKey",
    ],
)
def test_redact_mapping_recognizes_exact_and_namespaced_sensitive_keys(key: str) -> None:
    assert redact_mapping({key: "fixture-value"}) == {key: "[REDACTED]"}


def test_redact_mapping_sanitizes_embedded_secret_material_in_keys() -> None:
    token = "sk-" + "A" * 24
    encoded_token = token.replace("-", "%2D")
    overdepth_token = token.replace("-", "%25252D")
    encoded_url = quote(
        "https://fixture-user:fixture-pass@example.invalid/safe",
        safe="",
    )
    value = {
        f"prefix_{token}_suffix": "safe-token-value",
        "prefix_https://fixture-user:fixture-pass@example.invalid_suffix": "safe-url-value",
        f"prefix_{encoded_token}_suffix": "safe-encoded-token-value",
        f"prefix_{encoded_url}_suffix": "safe-encoded-url-value",
        f"prefix_{overdepth_token}_suffix": "safe-overdepth-token-value",
        "api%25255Fkey": "safe-overdepth-alias-value",
    }

    cleaned = redact_mapping(value)
    serialized = repr(cleaned)

    assert token not in serialized
    assert "fixture-user" not in serialized
    assert "%2D" not in serialized
    assert "%3A" not in serialized
    assert "%2525" not in serialized
    assert sorted(cleaned.values()) == [
        "safe-encoded-token-value",
        "safe-encoded-url-value",
        "safe-overdepth-alias-value",
        "safe-overdepth-token-value",
        "safe-token-value",
        "safe-url-value",
    ]


def test_redact_mapping_bounds_cyclic_sequence_work() -> None:
    cycle: list[object] = []
    cycle.extend((cycle, cycle))

    assert redact_mapping({"items": cycle}) == {"items": ["[REDACTED]", "[REDACTED]"]}


def test_redact_mapping_fails_closed_when_cumulative_node_budget_is_exceeded() -> None:
    value = {f"safe_{index}": "ready" for index in range(25_000)}

    started = perf_counter()
    cleaned = redact_mapping(value)
    elapsed = perf_counter() - started

    assert cleaned == {"[REDACTED]": "[REDACTED]"}
    assert elapsed < 1.0


def test_oversized_raw_input_returns_only_a_bounded_safe_marker() -> None:
    value = ("safe-prefix " * 6000) + "--token=synthetic-tail-secret"

    cleaned = redact_text(value)
    tightly_bounded = redact_text(value, max_length=10)

    assert cleaned == "[REDACTED: OVERSIZED INPUT]"
    assert tightly_bounded == "[REDACTED:"
    assert "safe-prefix" not in cleaned
    assert "synthetic-tail-secret" not in cleaned


def test_redact_mapping_validates_max_length_without_string_values() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        redact_mapping({"count": 3}, max_length=-1)
