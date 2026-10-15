"""Encryption of saved server credentials (AES-256-GCM).

* The key comes from ``ENCRYPTION_KEY`` (any string of 16+ characters, stretched with HKDF-SHA256). If it is
  not set, ``SECRET_KEY`` is used as a fallback - but only when it was provided explicitly: a random
  per-start key would make saved passwords unreadable after a restart.
* Every ciphertext is bound to what it protects (``aad``, e.g. ``server:<id>:password``), so a value copied
  into another profile does not decrypt.
* ``ENCRYPTION_KEY_PREVIOUS`` lets you rotate: new values use the current key, old ones still decrypt and
  are re-encrypted automatically at startup.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import Settings
from .errors import AppError

_PREFIX = "v1"
_MIN_KEY_CHARS = 16


class SecretsUnavailable(AppError):
    def __init__(self) -> None:
        super().__init__(
            "Saved server passwords need an encryption key. Set ENCRYPTION_KEY (or SECRET_KEY) in the server "
            "settings so they can be stored safely and survive restarts.",
            409,
        )


def _derive(material: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"pgaccesscontrol/v1", info=b"server-credentials").derive(material.encode())


@dataclass
class DecryptResult:
    plaintext: str
    current_key: bool  # False: decrypted with a previous key and should be re-encrypted


class SecretBox:
    def __init__(self, keys: list[bytes], *, from_secret_key: bool = False) -> None:
        if not keys:
            raise ValueError("at least one key is required")
        self._keys = keys
        self.from_secret_key = from_secret_key  # True when falling back to SECRET_KEY

    @classmethod
    def from_settings(cls, s: Settings) -> "SecretBox | None":
        material, fallback = s.encryption_key, False
        if not material and not s.secret_key_generated:
            material, fallback = s.secret_key, True
        if not material:
            return None
        if len(material) < _MIN_KEY_CHARS:
            raise ValueError(f"ENCRYPTION_KEY must be at least {_MIN_KEY_CHARS} characters")
        keys = [_derive(material)]
        if s.encryption_key_previous:
            keys.append(_derive(s.encryption_key_previous))
        return cls(keys, from_secret_key=fallback)

    def encrypt(self, plaintext: str, aad: str) -> str:
        nonce = os.urandom(12)
        ct = AESGCM(self._keys[0]).encrypt(nonce, plaintext.encode(), aad.encode())
        return f"{_PREFIX}:{base64.urlsafe_b64encode(nonce + ct).decode()}"

    def decrypt(self, token: str, aad: str) -> DecryptResult:
        try:
            prefix, body = token.split(":", 1)
            raw = base64.urlsafe_b64decode(body)
        except Exception as exc:  # noqa: BLE001
            raise AppError("A saved credential is corrupted.", 500) from exc
        if prefix != _PREFIX:
            raise AppError("A saved credential uses an unknown format.", 500)
        nonce, ct = raw[:12], raw[12:]
        for i, key in enumerate(self._keys):
            try:
                return DecryptResult(AESGCM(key).decrypt(nonce, ct, aad.encode()).decode(), current_key=(i == 0))
            except InvalidTag:
                continue
        raise AppError(
            "A saved server password cannot be decrypted with the current ENCRYPTION_KEY. "
            "Restore the previous key (ENCRYPTION_KEY_PREVIOUS) or re-enter the password.",
            500,
        )
