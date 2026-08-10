import unittest

import access_log_abuse as ala


def entry(ip, method="GET", path="/", status=200, ua="Mozilla/5.0"):
    return {"ip": ip, "method": method, "path": path, "status": status, "ua": ua}


class ParseTests(unittest.TestCase):
    def test_parses_combined_format(self):
        line = ('203.0.113.10 - - [10/Aug/2026:00:00:01 +0000] '
                '"POST /login HTTP/1.1" 401 512 "-" "sqlmap/1.7"')
        e = ala.parse_line(line)
        self.assertEqual(e["ip"], "203.0.113.10")
        self.assertEqual(e["method"], "POST")
        self.assertEqual(e["path"], "/login")
        self.assertEqual(e["status"], 401)
        self.assertEqual(e["ua"], "sqlmap/1.7")

    def test_bad_line_returns_none(self):
        self.assertIsNone(ala.parse_line("garbage line"))


class DetectTests(unittest.TestCase):
    def test_credential_stuffing(self):
        entries = [entry("1.1.1.1", "POST", "/api/login", 401) for _ in range(12)]
        findings = ala.detect(entries)
        self.assertTrue(any(f["type"] == "credential_stuffing" for f in findings))

    def test_below_threshold_no_stuffing(self):
        entries = [entry("1.1.1.1", "POST", "/login", 401) for _ in range(5)]
        self.assertFalse(any(f["type"] == "credential_stuffing" for f in ala.detect(entries)))

    def test_enumeration(self):
        entries = [entry("2.2.2.2", "GET", "/admin/%d" % i, 404) for i in range(25)]
        findings = ala.detect(entries)
        self.assertTrue(any(f["type"] == "enumeration" for f in findings))

    def test_scanner_ua(self):
        entries = [entry("3.3.3.3", ua="Nikto/2.5")]
        findings = ala.detect(entries)
        self.assertTrue(any(f["type"] == "scanner" for f in findings))

    def test_blocklist_high_only(self):
        entries = ([entry("1.1.1.1", "POST", "/login", 401) for _ in range(12)]
                   + [entry("2.2.2.2", "GET", "/x/%d" % i, 404) for i in range(25)])
        findings = ala.detect(entries)
        block = ala.blocklist(findings)  # default high+
        self.assertIn("1.1.1.1", block)       # credential stuffing = high
        self.assertNotIn("2.2.2.2", block)    # enumeration = medium


if __name__ == "__main__":
    unittest.main()
