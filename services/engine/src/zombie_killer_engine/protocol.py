"""Bounded NDJSON protocol transport for the local engine sidecar."""

from __future__ import annotations

import json
import math
import sys
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from typing import BinaryIO
from uuid import UUID, uuid4

from pydantic import ValidationError

from zombie_killer_engine.service import (
    Capability,
    ClientKind,
    EngineService,
    ErrorBody,
    ErrorCode,
    Method,
    RequestContext,
    RequestEnvelope,
    ResponseEnvelope,
)

MAX_INPUT_FRAME_BYTES = 1024 * 1024
MAX_OUTPUT_FRAME_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_COLLECTION = 10_000
MAX_JSON_STRING = 65_536
_OUTPUT_DELIMITER_BYTES = 1


class _FrameError(ValueError):
    pass


def _reject_constant(_value: str) -> None:
    raise _FrameError("non-finite JSON numbers are not supported")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _FrameError("duplicate JSON object key")
        result[key] = value
    return result


def _validate_tree(value: object, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise _FrameError("JSON nesting limit exceeded")
    if isinstance(value, str):
        if len(value) > MAX_JSON_STRING:
            raise _FrameError("JSON string limit exceeded")
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise _FrameError("non-finite JSON number")
    if value is None or isinstance(value, bool | int | float):
        return
    if isinstance(value, Mapping):
        if len(value) > MAX_JSON_COLLECTION:
            raise _FrameError("JSON collection limit exceeded")
        for key, item in value.items():
            if len(str(key)) > 128:
                raise _FrameError("JSON field name limit exceeded")
            _validate_tree(item, depth=depth + 1)
        return
    if isinstance(value, list):
        if len(value) > MAX_JSON_COLLECTION:
            raise _FrameError("JSON collection limit exceeded")
        for item in value:
            _validate_tree(item, depth=depth + 1)
        return
    raise _FrameError("unsupported JSON value")


def _error_response(
    *,
    request_id: UUID | None = None,
    method: Method | None = None,
    code: ErrorCode = ErrorCode.INVALID_REQUEST,
    message: str = "The protocol frame is invalid.",
    details: dict[str, str | int | bool | None] | None = None,
) -> ResponseEnvelope:
    return ResponseEnvelope(
        request_id=request_id or uuid4(),
        method=method,
        ok=False,
        result=None,
        error=ErrorBody(code=code, message=message, details=details or {}),
    )


def _request_id_from(value: object) -> UUID | None:
    if not isinstance(value, Mapping):
        return None
    raw = value.get("request_id")
    if not isinstance(raw, str):
        return None
    try:
        return UUID(raw)
    except ValueError:
        return None


def _method_from(value: object) -> Method | None:
    if not isinstance(value, Mapping):
        return None
    raw = value.get("method")
    if not isinstance(raw, str):
        return None
    try:
        return Method(raw)
    except ValueError:
        return None


def _encode(response: ResponseEnvelope) -> bytes:
    try:
        encoded = json.dumps(
            response.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        encoded = b""
    if encoded and len(encoded) + _OUTPUT_DELIMITER_BYTES <= MAX_OUTPUT_FRAME_BYTES:
        return encoded
    fallback = _error_response(
        request_id=response.request_id,
        method=response.method,
        code=ErrorCode.PARTIAL,
        message="The response exceeded the supported output limit.",
    )
    encoded = json.dumps(
        fallback.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if (
        len(encoded) + _OUTPUT_DELIMITER_BYTES > MAX_OUTPUT_FRAME_BYTES
    ):  # pragma: no cover - constant-size invariant
        raise RuntimeError("bounded protocol error exceeded output cap")
    return encoded


_READ_CONTEXT = RequestContext(
    client=ClientKind.CONTROLLER,
    capability=Capability.READ,
    local_control=False,
)


class ProtocolRunner:
    """Bind protocol parsing to launcher-supplied authority, never JSON authority."""

    def __init__(
        self,
        service: EngineService,
        *,
        context: RequestContext,
        replay_cache: RequestReplayCache | None = None,
    ) -> None:
        self._service = service
        self._context = context
        self._replay_cache = replay_cache if replay_cache is not None else RequestReplayCache()

    def handle_frame(self, frame: bytes) -> bytes:
        return handle_frame(
            frame,
            self._service,
            context=self._context,
            replay_cache=self._replay_cache,
        )


class RequestReplayCache:
    """Bounded per-session LRU/TTL set of request IDs."""

    def __init__(
        self,
        *,
        max_entries: int = 4_096,
        ttl_seconds: float = 300,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 1 <= max_entries <= 100_000:
            raise ValueError("max_entries is outside the supported bound")
        if not 1 <= ttl_seconds <= 86_400 or not math.isfinite(ttl_seconds):
            raise ValueError("ttl_seconds is outside the supported bound")
        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._entries: OrderedDict[UUID, float] = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    def register(self, request_id: UUID) -> bool:
        now = self._clock()
        while self._entries:
            _oldest_id, oldest_at = next(iter(self._entries.items()))
            if now - oldest_at <= self._ttl_seconds:
                break
            self._entries.popitem(last=False)
        if request_id in self._entries:
            self._entries.move_to_end(request_id)
            self._entries[request_id] = now
            return False
        self._entries[request_id] = now
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)
        return True


def handle_frame(
    frame: bytes,
    service: EngineService,
    *,
    context: RequestContext = _READ_CONTEXT,
    replay_cache: RequestReplayCache | None = None,
) -> bytes:
    """Parse and dispatch one frame without accepting embedded line boundaries."""
    request_id: UUID | None = None
    method: Method | None = None
    try:
        if not frame or len(frame) > MAX_INPUT_FRAME_BYTES:
            raise _FrameError("frame size is invalid")
        if b"\n" in frame or b"\r" in frame:
            raise _FrameError("embedded line boundary")
        try:
            text = frame.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise _FrameError("invalid UTF-8") from error
        decoder = json.JSONDecoder(
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        try:
            value, end = decoder.raw_decode(text)
        except (json.JSONDecodeError, RecursionError, _FrameError) as error:
            raise _FrameError("invalid JSON") from error
        if end != len(text):
            raise _FrameError("trailing JSON data")
        request_id = _request_id_from(value)
        method = _method_from(value)
        _validate_tree(value)
        if not isinstance(value, dict):
            raise _FrameError("request envelope must be an object")
        try:
            # Pydantic's strict JSON mode still accepts JSON strings for UUIDs and
            # enums while rejecting Python-side coercions such as bool-to-int.
            envelope = RequestEnvelope.model_validate_json(
                json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            )
        except ValidationError as error:
            raise _FrameError("request envelope validation failed") from error
        if replay_cache is not None and not replay_cache.register(envelope.request_id):
            return _encode(
                _error_response(
                    request_id=envelope.request_id,
                    method=method,
                    code=ErrorCode.CONFLICT,
                    message="The request ID was already used in this protocol session.",
                    details={"reason": "request_id_replay"},
                )
            )
        response = service.dispatch(envelope, context=context)
        if not response.ok and response.method is None and method is not None:
            response = response.model_copy(update={"method": method})
        return _encode(response)
    except _FrameError:
        return _encode(_error_response(request_id=request_id, method=method))
    except Exception:
        return _encode(
            _error_response(
                request_id=request_id,
                method=method,
                code=ErrorCode.INTERNAL,
                message="An internal protocol error occurred.",
                details={"correlation_id": str(uuid4())},
            )
        )


def _write_response(stdout: BinaryIO, response: bytes) -> bool:
    try:
        stdout.write(response + b"\n")
        stdout.flush()
        return True
    except (BrokenPipeError, OSError):
        return False


def _drain_line(stdin: BinaryIO) -> None:
    while True:
        chunk = stdin.readline(MAX_INPUT_FRAME_BYTES + 2)
        if not chunk or chunk.endswith(b"\n"):
            return


def stdio(
    service: EngineService,
    *,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    context: RequestContext = _READ_CONTEXT,
    replay_cache: RequestReplayCache | None = None,
) -> int:
    """Serve persistent NDJSON, producing exactly one response for each input line."""
    source = stdin or sys.stdin.buffer
    sink = stdout or sys.stdout.buffer
    active_replay_cache = replay_cache if replay_cache is not None else RequestReplayCache()
    try:
        while True:
            line = source.readline(MAX_INPUT_FRAME_BYTES + 2)
            if not line:
                return 0
            complete = line.endswith(b"\n")
            terminator_bytes = 2 if line.endswith(b"\r\n") else 1 if complete else 0
            oversized = len(line) - terminator_bytes > MAX_INPUT_FRAME_BYTES or not complete
            if oversized:
                if not complete:
                    _drain_line(source)
                response = _encode(_error_response(message="The input frame is too large."))
            else:
                frame = line[:-terminator_bytes]
                response = handle_frame(
                    frame,
                    service,
                    context=context,
                    replay_cache=active_replay_cache,
                )
            if not _write_response(sink, response):
                return 0
    except KeyboardInterrupt:
        return 130
    finally:
        service.close()


def protocol_once(
    service: EngineService,
    *,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    context: RequestContext = _READ_CONTEXT,
) -> int:
    """Read one request through EOF; reject additional lines or trailing data."""
    source = stdin or sys.stdin.buffer
    sink = stdout or sys.stdout.buffer
    try:
        try:
            data = source.read(MAX_INPUT_FRAME_BYTES + 3)
        except KeyboardInterrupt:
            return 130
        if data.endswith(b"\r\n"):
            frame = data[:-2]
        elif data.endswith(b"\n"):
            frame = data[:-1]
        else:
            frame = data
        valid_size = 0 < len(frame) <= MAX_INPUT_FRAME_BYTES
        single_line = b"\n" not in frame and b"\r" not in frame
        if not valid_size or not single_line:
            response = _encode(
                _error_response(message="Expected exactly one bounded request frame.")
            )
            exit_code = 2
        else:
            response = handle_frame(frame, service, context=context)
            exit_code = 0 if json.loads(response)["ok"] else 2
        _write_response(sink, response)
        return exit_code
    finally:
        service.close()


__all__ = [
    "MAX_INPUT_FRAME_BYTES",
    "MAX_OUTPUT_FRAME_BYTES",
    "ProtocolRunner",
    "RequestReplayCache",
    "handle_frame",
    "protocol_once",
    "stdio",
]
