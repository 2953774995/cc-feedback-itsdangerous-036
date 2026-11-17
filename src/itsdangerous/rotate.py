from __future__ import annotations

import time
import typing as t
from dataclasses import dataclass
from dataclasses import field

from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import BadData
from .exc import BadSignature
from .signer import Signer


class UnknownKeyError(BadData):
    """Raised if a token names a key id that is not in the key ring.

    This is not a subclass of :class:`BadSignature`: the signature was
    never checked because no key could be selected.
    """


class RetiredKeyError(BadData):
    """Raised if a token was signed with a key generation that has been
    retired from the ring.

    This is not a subclass of :class:`BadSignature`: the key is known,
    it is simply no longer accepted.
    """


@dataclass
class VerifyItem:
    """The outcome of verifying a single token in a batch."""

    index: int
    ok: bool
    reason: str
    key_id: str | None = None
    payload: str | bytes | None = None


@dataclass
class BatchResult:
    """The result of :meth:`KeyRing.verify_many`."""

    items: list[VerifyItem] = field(default_factory=list)
    stats: dict[str, t.Any] = field(default_factory=dict)


def _check_key_id(key_id: str) -> None:
    if not key_id or "." in key_id:
        raise ValueError("key_id must be non-empty and must not contain '.'")


class KeyRing:
    """A ring of named key generations for signed tokens.

    The last generation added is the *current* one and is the only one
    used for signing. All non-retired generations can still verify, so
    old links keep working after a rotation.

    Token format (dot separated, URL safe)::

        key_id.timestamp.nonce_b64.payload_b64.signature

    The signature is produced by the existing :class:`Signer` HMAC
    logic over ``key_id.timestamp.nonce_b64.payload_b64``, keyed with
    the secret of the generation named by ``key_id``.

    :param keys: An iterable of ``(key_id, secret)`` pairs, oldest to
        newest. Must not be empty.
    """

    def __init__(self, keys: t.Iterable[tuple[str, str | bytes]]):
        self.keys: dict[str, bytes] = {}
        self._retired: set[str] = set()
        self._signers: dict[tuple[str, bytes], Signer] = {}

        for key_id, secret in keys:
            _check_key_id(key_id)
            self.keys[key_id] = want_bytes(secret)

        if not self.keys:
            raise ValueError("KeyRing requires at least one key")

    @property
    def current(self) -> tuple[str, bytes]:
        """The ``(key_id, secret)`` pair used for signing."""
        key_id = next(reversed(self.keys))
        return key_id, self.keys[key_id]

    def promote(self, secret: str | bytes, key_id: str) -> None:
        """Add a new generation and make it the current signing key."""
        _check_key_id(key_id)

        if key_id in self.keys:
            raise ValueError(f"key id {key_id!r} already exists in the ring")

        self.keys[key_id] = want_bytes(secret)
        self._retired.discard(key_id)

    def retire(self, key_id: str) -> None:
        """Mark a generation as retired. Its tokens stop verifying."""
        if key_id not in self.keys:
            raise ValueError(f"unknown key id {key_id!r}")

        self._retired.add(key_id)

    def _signer_for(self, key_id: str, salt: str | bytes) -> Signer:
        salt_b = want_bytes(salt)
        cache_key = (key_id, salt_b)
        signer = self._signers.get(cache_key)

        if signer is None:
            signer = Signer(self.keys[key_id], salt=salt_b)
            self._signers[cache_key] = signer

        return signer

    def sign(
        self, value: str | bytes, salt: str | bytes, nonce: str | None = None
    ) -> str:
        """Sign ``value`` with the current generation. The key id, a
        timestamp, and an optional nonce are embedded in the token.
        """
        key_id, _ = self.current
        ts = str(int(time.time()))
        nonce_b64 = base64_encode(nonce).decode("ascii") if nonce else ""
        payload_b64 = base64_encode(want_bytes(value)).decode("ascii")
        inner = f"{key_id}.{ts}.{nonce_b64}.{payload_b64}"
        return self._signer_for(key_id, salt).sign(inner).decode("ascii")

    def _parse(self, token: str) -> tuple[str, str, str, str]:
        """Split a token into ``(key_id, ts, nonce, payload)`` without
        checking the signature. Raises :class:`BadSignature` if the
        structure is not exactly five dot-separated fields.
        """
        parts = token.split(".")

        if len(parts) != 5 or not all(parts[:2]) or not parts[4]:
            raise BadSignature("Malformed token: expected 5 segments")

        key_id, ts, nonce_b64, payload_b64, _sig = parts

        try:
            nonce = base64_decode(nonce_b64).decode("utf-8") if nonce_b64 else ""
            payload = base64_decode(payload_b64).decode("utf-8")
        except (BadData, UnicodeDecodeError) as e:
            raise BadSignature("Malformed token: bad base64 segment") from e

        return key_id, ts, nonce, payload

    def verify(self, value: str | bytes, salt: str | bytes) -> tuple[str, str]:
        """Verify a token and return ``(payload, key_id)``.

        :raises BadSignature: the token is malformed or the signature
            does not match.
        :raises UnknownKeyError: the token names an unknown key id.
        :raises RetiredKeyError: the token names a retired key id.
        """
        if not isinstance(value, (str, bytes)) or not value:
            raise BadSignature("Malformed token")

        token = want_bytes(value).decode("ascii", "ignore")
        key_id, _ts, _nonce, payload = self._parse(token)

        if key_id not in self.keys:
            raise UnknownKeyError(f"Unknown key id {key_id!r}")

        if key_id in self._retired:
            raise RetiredKeyError(f"Key id {key_id!r} has been retired")

        # unsign re-checks the structure and verifies the HMAC with the
        # selected generation's secret.
        self._signer_for(key_id, salt).unsign(token)

        return payload, key_id

    def verify_many(
        self,
        values: t.Iterable[t.Any],
        salt: str | bytes,
        max_age: int | float | None = None,
        nonce_store: t.Any = None,
    ) -> BatchResult:
        """Verify a batch of tokens. A bad entry never aborts the batch.

        Each item records ``index``, ``ok``, ``reason`` and ``key_id``.
        ``reason`` is one of ``ok``, ``bad_signature``, ``expired``,
        ``unknown_key``, ``retired_key``, ``replay`` or ``malformed``.
        """
        result = BatchResult()
        by_reason: dict[str, int] = {}
        by_key_id: dict[str, int] = {}
        ok_count = 0
        now = time.time() if max_age is not None else 0.0

        for index, value in enumerate(values):
            item = self._verify_one(value, salt, max_age, now, nonce_store, index)
            result.items.append(item)
            by_reason[item.reason] = by_reason.get(item.reason, 0) + 1

            if item.ok:
                ok_count += 1

                if item.key_id is not None:
                    by_key_id[item.key_id] = by_key_id.get(item.key_id, 0) + 1

        result.stats = {
            "ok": ok_count,
            "bad": len(result.items) - ok_count,
            "by_reason": by_reason,
            "by_key_id": by_key_id,
        }
        return result

    def _verify_one(
        self,
        value: t.Any,
        salt: str | bytes,
        max_age: int | float | None,
        now: float,
        nonce_store: t.Any,
        index: int,
    ) -> VerifyItem:
        if not isinstance(value, (str, bytes)) or not value:
            return VerifyItem(index, False, "malformed")

        try:
            token = want_bytes(value).decode("ascii")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return VerifyItem(index, False, "malformed")

        try:
            key_id, ts, nonce, payload = self._parse(token)
        except BadSignature:
            return VerifyItem(index, False, "malformed")

        if key_id not in self.keys:
            return VerifyItem(index, False, "unknown_key", key_id=key_id)

        if key_id in self._retired:
            return VerifyItem(index, False, "retired_key", key_id=key_id)

        try:
            self._signer_for(key_id, salt).unsign(token)
        except BadSignature:
            return VerifyItem(index, False, "bad_signature", key_id=key_id)

        if max_age is not None:
            try:
                age = now - float(ts)
            except ValueError:
                return VerifyItem(index, False, "malformed", key_id=key_id)

            if age > max_age:
                return VerifyItem(index, False, "expired", key_id=key_id)

        if nonce_store is not None and nonce:
            if nonce_store.seen(nonce):
                return VerifyItem(index, False, "replay", key_id=key_id)

            nonce_store.mark(nonce)

        return VerifyItem(index, True, "ok", key_id=key_id, payload=payload)


def verify_many(
    values: t.Iterable[t.Any],
    salt: str | bytes,
    ring: KeyRing | None = None,
    max_age: int | float | None = None,
    nonce_store: t.Any = None,
) -> BatchResult:
    """Module-level convenience wrapper around
    :meth:`KeyRing.verify_many`.
    """
    if ring is None:
        raise ValueError("a KeyRing instance is required")

    return ring.verify_many(values, salt, max_age=max_age, nonce_store=nonce_store)
