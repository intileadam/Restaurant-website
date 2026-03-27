"""Lightweight checks for customer CSV template and column contract (no DB)."""

from __future__ import annotations

import csv
import io
import pathlib
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE = REPO_ROOT / "apps" / "campaign_console" / "static" / "customers_import_template.csv"

EXPECTED_HEADERS = [
    "email",
    "firstname",
    "lastname",
    "company",
    "phone",
    "comments",
    "is_subscribed",
    "tags",
]


class TestCustomerCsvTemplate(unittest.TestCase):
    def test_template_exists_and_has_expected_columns(self) -> None:
        self.assertTrue(TEMPLATE.is_file(), msg=f"Expected template at {TEMPLATE}")
        raw = TEMPLATE.read_text(encoding="utf-8-sig")
        first_line = raw.strip().splitlines()[0]
        reader = csv.reader(io.StringIO(first_line))
        header = next(reader)
        normalized = [h.strip().lower() for h in header]
        self.assertEqual(normalized, EXPECTED_HEADERS)


if __name__ == "__main__":
    unittest.main()
