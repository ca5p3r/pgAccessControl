"""CSV helpers shared by the audit and permission exports."""

from __future__ import annotations

import csv
import io
from typing import Any, Iterable, Iterator

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: Any) -> Any:
    """Neutralise spreadsheet formula injection: role and object names are user-controlled text."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def to_csv(header: list[str], rows: Iterable[list[Any]]) -> Iterator[str]:
    """Yield CSV text in chunks (header first)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    for i, row in enumerate(rows, 1):
        writer.writerow([safe_cell(c) for c in row])
        if i % 500 == 0:
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()
    yield buf.getvalue()
