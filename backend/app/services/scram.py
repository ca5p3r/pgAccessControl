"""Client-side SCRAM-SHA-256 verifier generation.

Sending a pre-computed verifier in ``CREATE/ALTER ROLE ... PASSWORD`` keeps the plaintext password
out of the server log (log_statement = 'ddl'), pg_stat_activity and any pooler in between.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

_ITERATIONS = 4096


def scram_sha256_verifier(password: str) -> str | None:
    """Return a verifier string, or None when the password needs server-side SASLprep handling."""
    if not password.isascii():
        return None  # let the server normalise (SASLprep) and hash it
    salt = os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return f"SCRAM-SHA-256${_ITERATIONS}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"
