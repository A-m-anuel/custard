"""CSV helpers with protection against spreadsheet formula injection (CWE-1236)."""

from __future__ import annotations

import csv
import io

_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value) -> str:
    text = "" if value is None else str(value)
    if text.startswith(_DANGEROUS_PREFIXES):
        return "'" + text
    return text


def rows_to_csv(header: list[str], rows) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    for row in rows:
        writer.writerow([safe_cell(v) for v in row])
    return buffer.getvalue()
