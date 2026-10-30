"""Centralized secret redaction for display and persistence boundaries."""

from __future__ import annotations

import re
from collections.abc import Mapping
from unicodedata import category as unicode_category
from urllib.parse import unquote, urlsplit

_REDACTED = "[REDACTED]"
_TRUNCATION_MARKER = "…[TRUNCATED]"
_OVERSIZED_INPUT_MARKER = "[REDACTED: OVERSIZED INPUT]"
_MAX_RAW_INPUT_LENGTH = 65_536
_MAX_KEY_PART_SEPARATOR_LENGTH = 4
_FLEXIBLE_KEY_PART_SEPARATOR = (
    rf"(?:[-_.]|[\s\u200B\u200C\u200D\u2060\uFEFF]"
    rf"{{1,{_MAX_KEY_PART_SEPARATOR_LENGTH}}})?"
)
_BEARER_SENTINEL = "\ufdd0BEARER\ufdd1"
_BEARER_PATTERN = re.compile(
    r"(?i)(?P<prefix>\b(?:authorization[ \t]*:[ \t]*)?bearer[ \t]+)(?P<token>\S+)"
)
_QUOTED_SECRET_VALUE_PATTERN = (
    r'"(?:\\[\s\S]|[^"\\])*"(?:[^\s,}\]\);]+)?'
    r"|'(?:\\[\s\S]|[^'\\])*'(?:[^\s,}\]\);]+)?"
    r'|"(?:\\[\s\S]|[^"\\])*\Z'
    r"|'(?:\\[\s\S]|[^'\\])*\Z"
)
_SECRET_VALUE_PATTERN = _QUOTED_SECRET_VALUE_PATTERN + r"|\S+"
_AUTHORIZATION_ASSIGNMENT_VALUE_PATTERN = _QUOTED_SECRET_VALUE_PATTERN + r"|[^\r\n]+"
_AUTHORIZATION_KEY = r"(?:proxy[-_.]?)?authorization"
_FLEXIBLE_AUTHORIZATION_KEY = rf"(?:proxy{_FLEXIBLE_KEY_PART_SEPARATOR})?authorization"
_FOLDED_AUTHORIZATION_PATTERN = re.compile(
    rf"(?im)(?P<prefix>(?<![\w-])(?:--?)?{_FLEXIBLE_AUTHORIZATION_KEY}[ \t]*:[ \t]*)"
    r"(?:>[ \t]*)?(?:\r?\n[ \t]+[^\r\n]*)+"
)
_QUOTED_AUTHORIZATION_PATTERN = re.compile(
    rf"(?im)(?P<prefix>(?<![\w-])"
    rf"(?:\"{_FLEXIBLE_AUTHORIZATION_KEY}\"|'{_FLEXIBLE_AUTHORIZATION_KEY}')"
    rf"[ \t]*[:=][ \t]*)(?P<value>{_SECRET_VALUE_PATTERN})"
)
_AUTHORIZATION_HEADER_PATTERN = re.compile(
    rf"(?im)(?P<prefix>(?<![\w-])(?:--?)?{_FLEXIBLE_AUTHORIZATION_KEY}"
    rf"[ \t]*:[ \t]*)"
    r"(?P<value>[^\r\n]+)"
)
_AUTHORIZATION_ASSIGNMENT_PATTERN = re.compile(
    rf"(?im)(?P<prefix>(?<![\w-])(?:--?)?"
    rf"(?:{_AUTHORIZATION_KEY}(?:[ \t]*=[ \t]*|[ \t]+)"
    rf"|{_FLEXIBLE_AUTHORIZATION_KEY}[ \t]*=[ \t]*))"
    rf"(?P<value>{_AUTHORIZATION_ASSIGNMENT_VALUE_PATTERN})"
)
_JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"(?![A-Za-z0-9_-])"
)
_SENSITIVE_KEY_PARTS = (
    ("access", "token"),
    ("api", "key"),
    ("auth", "token"),
    ("authorization",),
    ("aws", "secret", "access", "key"),
    ("aws", "session", "token"),
    ("client", "secret"),
    ("credential",),
    ("credentials",),
    ("id", "token"),
    ("passphrase",),
    ("password",),
    ("passwd",),
    ("private", "key"),
    ("private", "token"),
    ("proxy", "authorization"),
    ("refresh", "token"),
    ("secret",),
    ("secret", "key"),
    ("seed", "phrase"),
    ("session", "secret"),
    ("session", "token"),
    ("token",),
    ("pwd",),
    ("x", "api", "key"),
)
_TEXTUAL_ASSIGNMENT_KEY_PARTS = tuple(
    parts
    for parts in _SENSITIVE_KEY_PARTS
    if parts not in {("authorization",), ("proxy", "authorization")}
)
_SENSITIVE_KEY_PATTERN = (
    "(?:"
    + "|".join(
        r"[-_.]?".join(parts)
        for parts in sorted(_TEXTUAL_ASSIGNMENT_KEY_PARTS, key=lambda item: (-len(item), item))
    )
    + ")"
)
_SPACED_SENSITIVE_KEY_PATTERN = (
    "(?:"
    + "|".join(
        _FLEXIBLE_KEY_PART_SEPARATOR.join(parts)
        for parts in sorted(_TEXTUAL_ASSIGNMENT_KEY_PARTS, key=lambda item: (-len(item), item))
    )
    + ")"
)
_SENSITIVE_KEY_TOKEN = (
    rf'(?:"{_SENSITIVE_KEY_PATTERN}"|\'{_SENSITIVE_KEY_PATTERN}\'|'
    rf"{_SENSITIVE_KEY_PATTERN})"
)
_SPACED_SENSITIVE_KEY_TOKEN = (
    rf'(?:"{_SPACED_SENSITIVE_KEY_PATTERN}"|\'{_SPACED_SENSITIVE_KEY_PATTERN}\'|'
    rf"{_SPACED_SENSITIVE_KEY_PATTERN})"
)
_NAMED_SECRET_PATTERN = re.compile(
    rf"(?im)(?P<prefix>(?<![\w-])(?:--?)?"
    rf"(?:{_SENSITIVE_KEY_TOKEN}(?:[ \t]*[:=][ \t]*|[ \t]+)"
    rf"|{_SPACED_SENSITIVE_KEY_TOKEN}[ \t]*[:=][ \t]*))"
    rf"(?P<value>{_SECRET_VALUE_PATTERN})"
)
_GENERIC_ASSIGNMENT_KEY_SEPARATOR = (
    rf"(?:[-_.]|[\s\u200B\u200C\u200D\u2060\uFEFF]"
    rf"{{1,{_MAX_KEY_PART_SEPARATOR_LENGTH}}})"
)
_GENERIC_ASSIGNMENT_KEY = (
    rf"[A-Za-z][A-Za-z0-9]*(?:{_GENERIC_ASSIGNMENT_KEY_SEPARATOR}[A-Za-z0-9]+){{0,8}}"
)
_NAMESPACED_SECRET_ASSIGNMENT_PATTERN = re.compile(
    rf"(?im)(?P<prefix>(?<![\w-])(?:--?)?"
    rf"(?P<quote>[\"']?)(?P<key>{_GENERIC_ASSIGNMENT_KEY})(?P=quote)"
    rf"[ \t]*[:=][ \t]*)(?P<value>{_SECRET_VALUE_PATTERN})"
)
_PRIVATE_KEY_BLOCK_PATTERN = re.compile(
    r"-----BEGIN (?P<private_key_label>(?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----[\s\S]*?"
    r"(?:-----END (?P=private_key_label)-----|\Z)"
)
_PUBLIC_MATERIAL_BEGIN_PATTERN = re.compile(
    r"-----BEGIN (?P<public_material_label>(?:PGP )?PUBLIC KEY(?: BLOCK)?|CERTIFICATE)-----"
)
_URL_AUTHORITY_PATTERN = re.compile(
    r"(?i)(?P<prefix>\b[a-z][a-z0-9+.-]*://|(?<![\w:/])//)"
    r"(?P<authority>[^\s/?#\"'<>`|\u2018\u2019\u201c\u201d]+)"
)
_EMBEDDED_URL_AUTHORITY_PATTERN = re.compile(
    r"(?i)(?P<prefix>[a-z][a-z0-9+.-]*://|//)"
    r"(?P<authority>[^\s/?#\"'<>`|\u2018\u2019\u201c\u201d]+)"
)
_ENCODED_ESCAPE_PREFIX = r"%(?:25)*"
_RESIDUAL_ENCODED_URL_START_PATTERN = re.compile(
    rf"(?i)(?:\b[a-z][a-z0-9+.-]*{_ENCODED_ESCAPE_PREFIX}3a"
    rf"(?:{_ENCODED_ESCAPE_PREFIX}2f|/)(?:{_ENCODED_ESCAPE_PREFIX}2f|/)"
    rf"|(?<![\w:/])(?:{_ENCODED_ESCAPE_PREFIX}2f(?:{_ENCODED_ESCAPE_PREFIX}2f|/)"
    rf"|/{_ENCODED_ESCAPE_PREFIX}2f))"
)
_RESIDUAL_ENCODED_AUTHORITY_END_PATTERN = re.compile(
    rf"(?i){_ENCODED_ESCAPE_PREFIX}(?:2f|3f|23)|[/?#&\s]"
)
_RESIDUAL_ENCODED_AT_PATTERN = re.compile(rf"(?i)(?:{_ENCODED_ESCAPE_PREFIX}40|@)")
_RECOGNIZABLE_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(
        r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)"
        r"[A-Z0-9]{16}\b"
    ),
    re.compile(r"\b(?:xox[baprs]|xapp)-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\b1//[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bya29\.[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bMII[A-Za-z0-9+/=]{40,}\b"),
)
_EMBEDDED_RECOGNIZABLE_SECRET_PATTERNS = tuple(
    re.compile(pattern.pattern.removeprefix(r"\b").removesuffix(r"\b"))
    for pattern in _RECOGNIZABLE_SECRET_PATTERNS
)
_PUBLIC_MATERIAL_SECRET_PATTERNS = _RECOGNIZABLE_SECRET_PATTERNS[:-1]
_EMBEDDED_JWT_PATTERN = re.compile(r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_REMOTE_URL_PATTERN = re.compile(
    r"(?i)\b(?:https?|ftp)://[^\s\uFEFF\"'<>`|\u2018\u2019\u201c\u201d]*"
    r"|(?<![\w:/])//(?!/)[^\s\uFEFF\"'<>`|\u2018\u2019\u201c\u201d]*"
)
_EMPTY_PATH_FOLLOWERS = frozenset("\"'`)]},;|\u2018\u2019\u201c\u201d")
_VALID_PERCENT_ESCAPE_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")
_INVALID_PERCENT_ESCAPE_PATTERN = re.compile(r"%(?![0-9A-Fa-f]{2})")
_AUTHORITY_DRIVE_SUFFIX_PATTERN = re.compile(r"(?i)(?<![A-Za-z0-9_])[A-Z]:\Z")
_MAX_PERCENT_DECODE_PASSES = 2
_MAX_BOUNDARY_MARK_LOOKBACK = 16
_SENSITIVE_MAPPING_KEYS = frozenset("".join(parts) for parts in _SENSITIVE_KEY_PARTS)
_MAX_MAPPING_DEPTH = 32
_MAX_MAPPING_NODES = 10_000
_CAMEL_ACRONYM_BOUNDARY_PATTERN = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_WORD_BOUNDARY_PATTERN = re.compile(r"([a-z0-9])([A-Z])")


class _RedactionBudgetExceeded(Exception):
    """Signal that fail-closed structured redaction exhausted its work budget."""


def _consume_redaction_budget(remaining: list[int]) -> None:
    if remaining[0] <= 0:
        raise _RedactionBudgetExceeded
    remaining[0] -= 1


def _redact_named_secret(match: re.Match[str]) -> str:
    value = match.group("value")
    quote = value[0] if value[:1] in {'"', "'"} and value[-1:] == value[:1] else ""
    return f"{match.group('prefix')}{quote}{_REDACTED}{quote}"


def _redact_namespaced_secret(match: re.Match[str]) -> str:
    key = match.group("key")
    if _normalized_key(key) in {"authorization", "proxyauthorization"} or not is_sensitive_key(key):
        return match.group(0)
    return _redact_named_secret(match)


def _redact_bearer(match: re.Match[str]) -> str:
    if match.group("token") == _REDACTED:
        return match.group(0)
    return f"{match.group('prefix')}{_BEARER_SENTINEL}"


def _redact_folded_authorization(match: re.Match[str]) -> str:
    prefix = match.group("prefix")
    separator = "" if prefix[-1:].isspace() else " "
    return f"{prefix}{separator}{_REDACTED}"


def _redact_authorization(match: re.Match[str]) -> str:
    prefix = match.group("prefix")
    value = match.group("value")
    if re.match(
        rf"(?i)bearer[ \t]+{re.escape(_BEARER_SENTINEL)}(?:[ \t]|\Z)",
        value,
    ):
        return f"{prefix}{value.replace(_BEARER_SENTINEL, _REDACTED, 1)}"
    if re.fullmatch(r"(?i)bearer[ \t]+\[REDACTED\]", value):
        return f"{prefix}{value}"
    quote = value[0] if value[:1] in {'"', "'"} and value[-1:] == value[:1] else ""
    return f"{prefix}{quote}{_REDACTED}{quote}"


def _redact_url_userinfo(match: re.Match[str]) -> str:
    authority = match.group("authority")
    separator = authority.rfind("@")
    if separator <= 0:
        return match.group(0)
    return f"{match.group('prefix')}{_REDACTED}@{authority[separator + 1 :]}"


def _text_contains_unredacted_url_userinfo(value: str) -> bool:
    for match in _URL_AUTHORITY_PATTERN.finditer(value):
        authority = match.group("authority")
        separator = authority.rfind("@")
        if separator > 0 and authority[:separator] != _REDACTED:
            return True
    return False


def _contains_residual_encoded_url_userinfo(value: str) -> bool:
    for match in _RESIDUAL_ENCODED_URL_START_PATTERN.finditer(value):
        remainder = value[match.end() :]
        authority_end = _RESIDUAL_ENCODED_AUTHORITY_END_PATTERN.search(remainder)
        authority = remainder[: authority_end.start()] if authority_end else remainder
        separators = tuple(_RESIDUAL_ENCODED_AT_PATTERN.finditer(authority))
        if not separators:
            continue
        separator = separators[-1]
        if separator.start() > 0:
            return True
    return False


def _encoded_component_contains_url_userinfo(component: str) -> bool:
    current = component
    if _text_contains_unredacted_url_userinfo(current):
        return True
    for _ in range(_MAX_PERCENT_DECODE_PASSES):
        try:
            decoded = unquote(current, encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            return True
        if decoded == current:
            return False
        current = decoded
        if _text_contains_unredacted_url_userinfo(current):
            return True
    return _contains_residual_encoded_url_userinfo(current)


def _contains_encoded_nested_url_userinfo(value: str) -> bool:
    if _encoded_component_contains_url_userinfo(value):
        return True
    for match in _REMOTE_URL_PATTERN.finditer(value):
        candidate = match.group(0)
        protocol_relative = candidate.startswith("//")
        parse_candidate = candidate.replace(f"{_REDACTED}@", "redacted@")
        try:
            parsed = urlsplit(f"https:{parse_candidate}" if protocol_relative else parse_candidate)
            if parsed.scheme not in {"http", "https", "ftp"} or not _remote_host(
                parsed.hostname,
                protocol_relative=protocol_relative,
            ):
                continue
        except ValueError:
            continue
        if any(
            _encoded_component_contains_url_userinfo(component)
            for component in (parsed.query, parsed.fragment)
            if component
        ):
            return True
    return False


def _redact_unprotected_secret_shapes(segment: str) -> str:
    for pattern in _RECOGNIZABLE_SECRET_PATTERNS:
        segment = pattern.sub(_REDACTED, segment)
    return segment


def _redact_recognizable_secret_shapes(value: str) -> str:
    pieces: list[str] = []
    cursor = 0
    while public_begin := _PUBLIC_MATERIAL_BEGIN_PATTERN.search(value, cursor):
        label = public_begin.group("public_material_label")
        end_marker = f"-----END {label}-----"
        end_start = value.find(end_marker, public_begin.end())
        if end_start < 0:
            break
        pieces.append(_redact_unprotected_secret_shapes(value[cursor : public_begin.start()]))
        block_end = end_start + len(end_marker)
        block = value[public_begin.start() : block_end]
        pieces.append(
            _REDACTED
            if any(pattern.search(block) for pattern in _PUBLIC_MATERIAL_SECRET_PATTERNS)
            else block
        )
        cursor = block_end
    pieces.append(_redact_unprotected_secret_shapes(value[cursor:]))
    return "".join(pieces)


def redact_text(value: object | None, max_length: int = 2048) -> str:
    """Return text with recognizable secret values replaced."""
    if max_length < 0:
        raise ValueError("max_length must be non-negative")
    text = "" if value is None else str(value)
    if len(text) > _MAX_RAW_INPUT_LENGTH:
        return _OVERSIZED_INPUT_MARKER[:max_length]
    cleaned = _BEARER_PATTERN.sub(_redact_bearer, text.replace(_BEARER_SENTINEL, _REDACTED))
    cleaned = _FOLDED_AUTHORIZATION_PATTERN.sub(_redact_folded_authorization, cleaned)
    cleaned = _QUOTED_AUTHORIZATION_PATTERN.sub(_redact_authorization, cleaned)
    cleaned = _AUTHORIZATION_HEADER_PATTERN.sub(_redact_authorization, cleaned)
    cleaned = _AUTHORIZATION_ASSIGNMENT_PATTERN.sub(_redact_authorization, cleaned)
    cleaned = cleaned.replace(_BEARER_SENTINEL, _REDACTED)
    cleaned = _PRIVATE_KEY_BLOCK_PATTERN.sub(_REDACTED, cleaned)
    cleaned = _JWT_PATTERN.sub(_REDACTED, cleaned)
    cleaned = _NAMED_SECRET_PATTERN.sub(_redact_named_secret, cleaned)
    cleaned = _NAMESPACED_SECRET_ASSIGNMENT_PATTERN.sub(_redact_namespaced_secret, cleaned)
    cleaned = _URL_AUTHORITY_PATTERN.sub(_redact_url_userinfo, cleaned)
    if _contains_encoded_nested_url_userinfo(cleaned):
        return _REDACTED[:max_length]
    cleaned = _redact_recognizable_secret_shapes(cleaned)
    if len(cleaned) <= max_length:
        return cleaned
    if max_length <= len(_TRUNCATION_MARKER):
        return _TRUNCATION_MARKER[:max_length]
    return cleaned[: max_length - len(_TRUNCATION_MARKER)] + _TRUNCATION_MARKER


def _is_local_boundary(value: str, offset: int) -> bool:
    if offset == 0:
        return True
    cursor = offset - 1
    for _ in range(_MAX_BOUNDARY_MARK_LOOKBACK):
        previous_category = unicode_category(value[cursor])
        if previous_category[0] != "M":
            return previous_category[0] not in {"L", "N"} and previous_category != "Pc"
        cursor -= 1
        if cursor < 0:
            return True
    return True


def _remote_host(parsed_hostname: str | None, *, protocol_relative: bool) -> bool:
    if not parsed_hostname:
        return False
    if not protocol_relative:
        return True
    hostname = parsed_hostname.casefold().removesuffix(".")
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    return (
        ascii_hostname == "localhost"
        or ":" in ascii_hostname
        or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ascii_hostname) is not None
        or re.search(r"\.[a-z0-9-]{2,}\Z", ascii_hostname, re.IGNORECASE) is not None
    )


def _contains_unmasked_local_path(
    value: str,
    *,
    structural_root_offset: int | None = None,
) -> bool:
    for offset, character in enumerate(value):
        if structural_root_offset == offset and character == "/":
            continue
        if character in {"/", "\\"} and offset > 0 and value[offset - 1] == character:
            continue
        if not _is_local_boundary(value, offset):
            continue
        if (
            character.isascii()
            and character.isalpha()
            and offset + 2 < len(value)
            and value[offset + 1] == ":"
            and value[offset + 2] in {"/", "\\"}
        ):
            return True
        if character == "\\":
            if offset + 1 < len(value):
                following = value[offset + 1]
                if not following.isspace() and following not in _EMPTY_PATH_FOLLOWERS:
                    return True
            continue
        if character != "/":
            continue
        if structural_root_offset is not None and offset > 0 and value[offset - 1] == "-":
            continue
        cursor = offset
        while cursor < len(value) and value[cursor] == "/":
            cursor += 1
        if cursor >= len(value):
            continue
        following = value[cursor]
        if not following.isspace() and following not in _EMPTY_PATH_FOLLOWERS:
            return True
    return False


def _encoded_component_contains_local_path(
    component: str,
    *,
    depth: int,
    strict_percent: bool = True,
) -> bool:
    current = component
    for _ in range(_MAX_PERCENT_DECODE_PASSES):
        if strict_percent and _INVALID_PERCENT_ESCAPE_PATTERN.search(current):
            return True
        try:
            decoded = unquote(current, encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            return True
        if decoded == current:
            return False
        if _contains_local_path(decoded, depth=depth + 1):
            return True
        current = decoded
    if strict_percent and _INVALID_PERCENT_ESCAPE_PATTERN.search(current):
        return True
    try:
        decoded = unquote(current, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return True
    return decoded != current and _contains_local_path(decoded, depth=depth + 1)


def _contains_local_path(value: str, *, depth: int = 0) -> bool:
    if depth > 4:
        return True
    if (
        depth == 0
        and _VALID_PERCENT_ESCAPE_PATTERN.search(value)
        and _encoded_component_contains_local_path(
            value,
            depth=depth,
            strict_percent=False,
        )
    ):
        return True
    masked = list(value)
    for match in _REMOTE_URL_PATTERN.finditer(value):
        candidate = match.group(0)
        protocol_relative = candidate.startswith("//")
        parse_candidate = candidate.replace(f"{_REDACTED}@", "redacted@")
        try:
            parsed = urlsplit(f"https:{parse_candidate}" if protocol_relative else parse_candidate)
            redacted_missing_host = candidate.endswith(f"{_REDACTED}@")
            if parsed.scheme not in {"http", "https", "ftp"} or not (
                redacted_missing_host
                or _remote_host(
                    parsed.hostname,
                    protocol_relative=protocol_relative,
                )
            ):
                continue
        except ValueError:
            continue
        if _contains_unmasked_local_path(parsed.netloc):
            return True
        if parsed.path.startswith("/") and _AUTHORITY_DRIVE_SUFFIX_PATTERN.search(parsed.netloc):
            return True
        if _contains_unmasked_local_path(
            parsed.path,
            structural_root_offset=0 if parsed.path.startswith("/") else None,
        ):
            return True
        for component in (parsed.query, parsed.fragment):
            if not component:
                continue
            if _contains_local_path(
                component,
                depth=depth + 1,
            ) or _encoded_component_contains_local_path(component, depth=depth):
                return True
        masked[match.start() : match.end()] = " " * (match.end() - match.start())
    return _contains_unmasked_local_path("".join(masked))


def redact_display_text(value: object | None, max_length: int = 2048) -> str:
    """Redact secrets and fail closed on absolute local paths in display text."""
    cleaned = redact_text(value, max_length=max_length)
    if _contains_local_path(cleaned):
        return "[LOCAL PATH]"[:max_length]
    return cleaned


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _key_parts(value: str) -> tuple[str, ...]:
    split_acronyms = _CAMEL_ACRONYM_BOUNDARY_PATTERN.sub(r"\1 \2", value)
    split_words = _CAMEL_WORD_BOUNDARY_PATTERN.sub(r"\1 \2", split_acronyms)
    return tuple(re.findall(r"[a-z0-9]+", split_words.casefold()))


def is_sensitive_key(value: str) -> bool:
    """Return whether a standalone key/switch expects a sensitive value."""
    parts = _key_parts(value)
    return _normalized_key(value) in _SENSITIVE_MAPPING_KEYS or any(
        len(parts) >= len(suffix) and parts[-len(suffix) :] == suffix
        for suffix in _SENSITIVE_KEY_PARTS
    )


def _contains_raw_sensitive_key_material(value: str) -> bool:
    if is_sensitive_key(value) or redact_text(value, max_length=len(value)) != value:
        return True
    for match in _EMBEDDED_URL_AUTHORITY_PATTERN.finditer(value):
        authority = match.group("authority")
        separator = authority.rfind("@")
        if separator > 0 and authority[:separator] != _REDACTED:
            return True
    return _EMBEDDED_JWT_PATTERN.search(value) is not None or any(
        pattern.search(value) is not None for pattern in _EMBEDDED_RECOGNIZABLE_SECRET_PATTERNS
    )


def contains_sensitive_key_material(value: str) -> bool:
    """Return whether a dynamic field name embeds raw or percent-encoded secret material."""
    if len(value) > _MAX_RAW_INPUT_LENGTH:
        return True
    current = value
    for decode_pass in range(_MAX_PERCENT_DECODE_PASSES + 1):
        if _contains_raw_sensitive_key_material(current):
            return True
        if "%" not in current:
            return False
        if decode_pass == _MAX_PERCENT_DECODE_PASSES:
            return _VALID_PERCENT_ESCAPE_PATTERN.search(current) is not None
        try:
            decoded = unquote(current, encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            return True
        if decoded == current:
            return False
        current = decoded
    return False


def _redact_value(
    value: object,
    *,
    max_length: int,
    depth: int,
    seen: set[int],
    remaining: list[int],
) -> object:
    if depth > _MAX_MAPPING_DEPTH:
        return _REDACTED
    _consume_redaction_budget(remaining)
    if isinstance(value, Mapping):
        if len(value) > remaining[0]:
            raise _RedactionBudgetExceeded
        identity = id(value)
        if identity in seen:
            return _REDACTED
        seen.add(identity)
        try:
            reserved = {str(key) for key in value}
            cleaned_mapping: dict[str, object] = {}
            for index, (key, item) in enumerate(value.items(), start=1):
                _consume_redaction_budget(remaining)
                raw_key = str(key)
                if is_sensitive_key(raw_key):
                    cleaned_mapping[raw_key] = _REDACTED
                    continue
                cleaned_key = redact_text(raw_key, max_length=max_length)
                if cleaned_key != raw_key or contains_sensitive_key_material(raw_key):
                    base = f"[REDACTED_KEY_{index}]"
                    cleaned_key = base
                    suffix = 1
                    while cleaned_key in reserved or cleaned_key in cleaned_mapping:
                        cleaned_key = f"{base[:-1]}_{suffix}]"
                        suffix += 1
                cleaned_mapping[cleaned_key] = _redact_value(
                    item,
                    max_length=max_length,
                    depth=depth + 1,
                    seen=seen,
                    remaining=remaining,
                )
            return cleaned_mapping
        finally:
            seen.remove(identity)
    if isinstance(value, list):
        if len(value) > remaining[0]:
            raise _RedactionBudgetExceeded
        identity = id(value)
        if identity in seen:
            return _REDACTED
        seen.add(identity)
        try:
            return [
                _redact_value(
                    item,
                    max_length=max_length,
                    depth=depth + 1,
                    seen=seen,
                    remaining=remaining,
                )
                for item in value
            ]
        finally:
            seen.remove(identity)
    if isinstance(value, tuple):
        if len(value) > remaining[0]:
            raise _RedactionBudgetExceeded
        identity = id(value)
        if identity in seen:
            return _REDACTED
        seen.add(identity)
        try:
            return tuple(
                _redact_value(
                    item,
                    max_length=max_length,
                    depth=depth + 1,
                    seen=seen,
                    remaining=remaining,
                )
                for item in value
            )
        finally:
            seen.remove(identity)
    if isinstance(value, str):
        return redact_text(value, max_length=max_length)
    return value


def redact_mapping(value: Mapping[str, object], max_length: int = 2048) -> dict[str, object]:
    """Return a recursively redacted copy of a structured mapping."""
    if max_length < 0:
        raise ValueError("max_length must be non-negative")
    try:
        cleaned = _redact_value(
            value,
            max_length=max_length,
            depth=0,
            seen=set(),
            remaining=[_MAX_MAPPING_NODES],
        )
    except _RedactionBudgetExceeded:
        return {_REDACTED: _REDACTED}
    if not isinstance(cleaned, dict):
        raise TypeError("redact_mapping requires a mapping")
    return cleaned
