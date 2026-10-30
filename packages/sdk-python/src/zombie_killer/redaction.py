"""Bounded status redaction for the public broadcaster SDK."""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

_REDACTED = "[REDACTED]"
_TRUNCATION = "…"
_OVERSIZED = "[REDACTED: OVERSIZED INPUT]"
_MAX_RAW = 65_536
_MAX_KEY_PART_SEPARATOR_LENGTH = 4
_FLEXIBLE_KEY_PART_SEPARATOR = (
    rf"(?:[-_.]|[\s\u200B\u200C\u200D\u2060\uFEFF]"
    rf"{{1,{_MAX_KEY_PART_SEPARATOR_LENGTH}}})?"
)
_BEARER_SENTINEL = "\ufdd0BEARER\ufdd1"
_BEARER = re.compile(r"(?i)(?P<prefix>\b(?:authorization[ \t]*:[ \t]*)?bearer[ \t]+)(?P<token>\S+)")
_QUOTED_SECRET_VALUE = (
    r'"(?:\\[\s\S]|[^"\\])*"(?:[^\s,}\]\);]+)?'
    r"|'(?:\\[\s\S]|[^'\\])*'(?:[^\s,}\]\);]+)?"
    r'|"(?:\\[\s\S]|[^"\\])*\Z'
    r"|'(?:\\[\s\S]|[^'\\])*\Z"
)
_SECRET_VALUE = _QUOTED_SECRET_VALUE + r"|\S+"
_AUTHORIZATION_ASSIGNMENT_VALUE = _QUOTED_SECRET_VALUE + r"|[^\r\n]+"
_AUTHORIZATION_KEY = r"(?:proxy[-_.]?)?authorization"
_FLEXIBLE_AUTHORIZATION_KEY = rf"(?:proxy{_FLEXIBLE_KEY_PART_SEPARATOR})?authorization"
_FOLDED_AUTHORIZATION = re.compile(
    rf"(?im)(?P<prefix>(?<![\w-])(?:--?)?{_FLEXIBLE_AUTHORIZATION_KEY}[ \t]*:[ \t]*)"
    r"(?:>[ \t]*)?(?:\r?\n[ \t]+[^\r\n]*)+"
)
_QUOTED_AUTHORIZATION = re.compile(
    rf"(?im)(?P<prefix>(?<![\w-])"
    rf"(?:\"{_FLEXIBLE_AUTHORIZATION_KEY}\"|'{_FLEXIBLE_AUTHORIZATION_KEY}')"
    rf"[ \t]*[:=][ \t]*)(?P<value>{_SECRET_VALUE})"
)
_AUTHORIZATION_HEADER = re.compile(
    rf"(?im)(?P<prefix>(?<![\w-])(?:--?)?{_FLEXIBLE_AUTHORIZATION_KEY}"
    rf"[ \t]*:[ \t]*)"
    r"(?P<value>[^\r\n]+)"
)
_AUTHORIZATION_ASSIGNMENT = re.compile(
    rf"(?im)(?P<prefix>(?<![\w-])(?:--?)?"
    rf"(?:{_AUTHORIZATION_KEY}(?:[ \t]*=[ \t]*|[ \t]+)"
    rf"|{_FLEXIBLE_AUTHORIZATION_KEY}[ \t]*=[ \t]*))"
    rf"(?P<value>{_AUTHORIZATION_ASSIGNMENT_VALUE})"
)
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
    r"[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])"
)
_SENSITIVE_KEY_PARTS = (
    ("access", "token"),
    ("api", "key"),
    ("auth", "token"),
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
_KEY = (
    "(?:"
    + "|".join(
        r"[-_.]?".join(parts)
        for parts in sorted(_SENSITIVE_KEY_PARTS, key=lambda item: (-len(item), item))
    )
    + ")"
)
_SPACED_KEY = (
    "(?:"
    + "|".join(
        _FLEXIBLE_KEY_PART_SEPARATOR.join(parts)
        for parts in sorted(_SENSITIVE_KEY_PARTS, key=lambda item: (-len(item), item))
    )
    + ")"
)
_KEY_TOKEN = rf'(?:"{_KEY}"|\'{_KEY}\'|{_KEY})'
_SPACED_KEY_TOKEN = rf'(?:"{_SPACED_KEY}"|\'{_SPACED_KEY}\'|{_SPACED_KEY})'
_ASSIGNMENT = re.compile(
    rf"(?im)(?P<prefix>(?<![\w-])(?:--?)?(?:"
    rf"{_KEY_TOKEN}(?:[ \t]*[:=][ \t]*|[ \t]+)"
    rf"|{_SPACED_KEY_TOKEN}[ \t]*[:=][ \t]*))"
    rf"(?P<value>{_SECRET_VALUE})"
)
_GENERIC_ASSIGNMENT_KEY_SEPARATOR = (
    rf"(?:[-_.]|[\s\u200B\u200C\u200D\u2060\uFEFF]"
    rf"{{1,{_MAX_KEY_PART_SEPARATOR_LENGTH}}})"
)
_GENERIC_ASSIGNMENT_KEY = (
    rf"[A-Za-z][A-Za-z0-9]*(?:{_GENERIC_ASSIGNMENT_KEY_SEPARATOR}[A-Za-z0-9]+){{0,8}}"
)
_NAMESPACED_ASSIGNMENT = re.compile(
    rf"(?im)(?P<prefix>(?<![\w-])(?:--?)?"
    rf"(?P<quote>[\"']?)(?P<key>{_GENERIC_ASSIGNMENT_KEY})(?P=quote)"
    rf"[ \t]*[:=][ \t]*)(?P<value>{_SECRET_VALUE})"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?P<private_key_label>(?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----[\s\S]*?"
    r"(?:-----END (?P=private_key_label)-----|\Z)"
)
_PUBLIC_MATERIAL_BEGIN = re.compile(
    r"-----BEGIN (?P<public_material_label>(?:PGP )?PUBLIC KEY(?: BLOCK)?|CERTIFICATE)-----"
)
_URL_AUTHORITY = re.compile(
    r"(?i)(?P<prefix>\b[a-z][a-z0-9+.-]*://|(?<![\w:/])//)"
    r"(?P<authority>[^\s/?#\"'<>`|\u2018\u2019\u201c\u201d]+)"
)
_REMOTE_URL = re.compile(
    r"(?i)\b(?:https?|ftp)://[^\s\uFEFF\"'<>`|\u2018\u2019\u201c\u201d]*"
    r"|(?<![\w:/])//(?!/)[^\s\uFEFF\"'<>`|\u2018\u2019\u201c\u201d]*"
)
_MAX_PERCENT_DECODE_PASSES = 2
_ENCODED_ESCAPE_PREFIX = r"%(?:25)*"
_RESIDUAL_ENCODED_URL_START = re.compile(
    rf"(?i)(?:\b[a-z][a-z0-9+.-]*{_ENCODED_ESCAPE_PREFIX}3a"
    rf"(?:{_ENCODED_ESCAPE_PREFIX}2f|/)(?:{_ENCODED_ESCAPE_PREFIX}2f|/)"
    rf"|(?<![\w:/])(?:{_ENCODED_ESCAPE_PREFIX}2f(?:{_ENCODED_ESCAPE_PREFIX}2f|/)"
    rf"|/{_ENCODED_ESCAPE_PREFIX}2f))"
)
_RESIDUAL_ENCODED_AUTHORITY_END = re.compile(rf"(?i){_ENCODED_ESCAPE_PREFIX}(?:2f|3f|23)|[/?#&\s]")
_RESIDUAL_ENCODED_AT = re.compile(rf"(?i)(?:{_ENCODED_ESCAPE_PREFIX}40|@)")
_RECOGNIZABLE_SECRETS = (
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
_SENSITIVE_KEYS = frozenset("".join(parts) for parts in _SENSITIVE_KEY_PARTS)
_PUBLIC_MATERIAL_SECRET_PATTERNS = _RECOGNIZABLE_SECRETS[:-1]
_CAMEL_ACRONYM_BOUNDARY = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_WORD_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")


def _replace_assignment(match: re.Match[str]) -> str:
    value = match.group("value")
    quote = value[0] if value[:1] in {"'", '"'} and value[-1:] == value[:1] else ""
    return f"{match.group('prefix')}{quote}{_REDACTED}{quote}"


def _key_parts(value: str) -> tuple[str, ...]:
    split_acronyms = _CAMEL_ACRONYM_BOUNDARY.sub(r"\1 \2", value)
    split_words = _CAMEL_WORD_BOUNDARY.sub(r"\1 \2", split_acronyms)
    return tuple(re.findall(r"[a-z0-9]+", split_words.casefold()))


def _is_sensitive_key(value: str) -> bool:
    parts = _key_parts(value)
    normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
    return normalized in _SENSITIVE_KEYS or any(
        len(parts) >= len(suffix) and parts[-len(suffix) :] == suffix
        for suffix in _SENSITIVE_KEY_PARTS
    )


def _replace_namespaced_assignment(match: re.Match[str]) -> str:
    if not _is_sensitive_key(match.group("key")):
        return match.group(0)
    return _replace_assignment(match)


def _replace_bearer(match: re.Match[str]) -> str:
    if match.group("token") == _REDACTED:
        return match.group(0)
    return f"{match.group('prefix')}{_BEARER_SENTINEL}"


def _replace_folded_authorization(match: re.Match[str]) -> str:
    prefix = match.group("prefix")
    separator = "" if prefix[-1:].isspace() else " "
    return f"{prefix}{separator}{_REDACTED}"


def _replace_authorization(match: re.Match[str]) -> str:
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


def _replace_url_userinfo(match: re.Match[str]) -> str:
    authority = match.group("authority")
    separator = authority.rfind("@")
    if separator <= 0:
        return match.group(0)
    return f"{match.group('prefix')}{_REDACTED}@{authority[separator + 1 :]}"


def _text_contains_unredacted_url_userinfo(value: str) -> bool:
    for match in _URL_AUTHORITY.finditer(value):
        authority = match.group("authority")
        separator = authority.rfind("@")
        if separator > 0 and authority[:separator] != _REDACTED:
            return True
    return False


def _contains_residual_encoded_url_userinfo(value: str) -> bool:
    for match in _RESIDUAL_ENCODED_URL_START.finditer(value):
        remainder = value[match.end() :]
        authority_end = _RESIDUAL_ENCODED_AUTHORITY_END.search(remainder)
        authority = remainder[: authority_end.start()] if authority_end else remainder
        separators = tuple(_RESIDUAL_ENCODED_AT.finditer(authority))
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


def _contains_encoded_nested_url_userinfo(value: str) -> bool:
    if _encoded_component_contains_url_userinfo(value):
        return True
    for match in _REMOTE_URL.finditer(value):
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
    for pattern in _RECOGNIZABLE_SECRETS:
        segment = pattern.sub(_REDACTED, segment)
    return segment


def _redact_recognizable_secret_shapes(value: str) -> str:
    pieces: list[str] = []
    cursor = 0
    while public_begin := _PUBLIC_MATERIAL_BEGIN.search(value, cursor):
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


def redact_status(value: object | None, *, max_length: int = 2048) -> str:
    """Return one secret-redacted, control-safe, length-bounded status string."""
    if not 0 <= max_length <= 2048:
        raise ValueError("max_length must be between zero and 2048")
    text = "" if value is None else str(value)
    if len(text) > _MAX_RAW:
        return _OVERSIZED[:max_length]
    text = "".join(
        character if character >= " " or character in "\t\n" else " " for character in text
    )
    cleaned = _BEARER.sub(_replace_bearer, text.replace(_BEARER_SENTINEL, _REDACTED))
    cleaned = _FOLDED_AUTHORIZATION.sub(_replace_folded_authorization, cleaned)
    cleaned = _QUOTED_AUTHORIZATION.sub(_replace_authorization, cleaned)
    cleaned = _AUTHORIZATION_HEADER.sub(_replace_authorization, cleaned)
    cleaned = _AUTHORIZATION_ASSIGNMENT.sub(_replace_authorization, cleaned)
    cleaned = cleaned.replace(_BEARER_SENTINEL, _REDACTED)
    cleaned = _PRIVATE_KEY_BLOCK.sub(_REDACTED, cleaned)
    cleaned = _JWT.sub(_REDACTED, cleaned)
    cleaned = _ASSIGNMENT.sub(_replace_assignment, cleaned)
    cleaned = _NAMESPACED_ASSIGNMENT.sub(_replace_namespaced_assignment, cleaned)
    cleaned = _URL_AUTHORITY.sub(_replace_url_userinfo, cleaned)
    if _contains_encoded_nested_url_userinfo(cleaned):
        return _REDACTED[:max_length]
    cleaned = _redact_recognizable_secret_shapes(cleaned)
    if len(cleaned) <= max_length:
        return cleaned
    if max_length <= len(_TRUNCATION):
        return _TRUNCATION[:max_length]
    return cleaned[: max_length - len(_TRUNCATION)] + _TRUNCATION


__all__ = ["redact_status"]
