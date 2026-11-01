import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app import AppHandler, clamp_int, parse_content_disposition, parse_multipart
from state import STATE


class APITests(unittest.TestCase):
    def setUp(self):
        STATE.reset()

    def test_clamp_int(self):
        self.assertEqual(clamp_int("10", 5, 0, 20), 10)
        self.assertEqual(clamp_int("-5", 5, 0, 20), 0)
        self.assertEqual(clamp_int("100", 5, 0, 20), 20)
        self.assertEqual(clamp_int("invalid", 5, 0, 20), 5)
        self.assertEqual(clamp_int(None, 5, 0, 20), 5)

    def test_parse_content_disposition(self):
        header = 'form-data; name="file"; filename="document.pdf"'
        parsed = parse_content_disposition(header)
        self.assertEqual(parsed.get("name"), "file")
        self.assertEqual(parsed.get("filename"), "document.pdf")

    def test_parse_multipart(self):
        boundary = "---------------------------123456789"
        content_type = f"multipart/form-data; boundary={boundary}"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="window_size"\r\n\r\n'
            "8\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
            "Content-Type: text/plain\r\n\r\n"
            "Hello World\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")

        fields, files = parse_multipart(content_type, body)
        self.assertEqual(fields.get("window_size"), "8")
        self.assertIn("file", files)
        self.assertEqual(files["file"].filename, "test.txt")
        self.assertEqual(files["file"].data, b"Hello World")


if __name__ == "__main__":
    unittest.main()

