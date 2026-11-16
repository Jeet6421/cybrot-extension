"""Static checks for the CYBROT extension's permission and passive-mode rules.

Run from the extension folder:  python3 -m unittest tests/test_static.py
These read the files only. They do not run the browser or the engine.
"""
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def read(name):
    return (ROOT / name).read_text(encoding="utf-8")


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(read("manifest.json"))

    def test_uses_activetab_not_tabs(self):
        # "tabs" triggers the "Read your browsing history" warning in Chrome.
        self.assertIn("activeTab", self.manifest["permissions"])
        self.assertNotIn("tabs", self.manifest["permissions"])

    def test_no_broad_host_access(self):
        for pattern in self.manifest.get("host_permissions", []):
            self.assertIn("127.0.0.1", pattern, f"unexpected host permission: {pattern}")
        self.assertFalse(
            any("<all_urls>" in p or p.startswith("*") for p in self.manifest.get("host_permissions", []))
        )

    def test_only_expected_permissions(self):
        self.assertEqual(sorted(self.manifest["permissions"]), ["activeTab", "storage"])

    def test_explicit_csp_blocks_remote_scripts(self):
        csp = self.manifest["content_security_policy"]["extension_pages"]
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("http", csp)
        self.assertNotIn("unsafe-eval", csp)


class PopupTests(unittest.TestCase):
    def test_passive_is_forced_and_not_user_selectable(self):
        js = read("popup.js")
        self.assertIn("const PASSIVE_ONLY = true;", js)
        self.assertIn("passive_only: PASSIVE_ONLY", js)
        self.assertNotIn('$("passive-only")', js)
        self.assertNotIn("passive_only: false", js)

    def test_html_has_no_passive_checkbox(self):
        html = read("popup.html")
        self.assertNotIn('id="passive-only"', html)
        self.assertNotRegex(html, r'type="checkbox"[^>]*passive')

    def test_requests_have_timeouts(self):
        js = read("popup.js")
        self.assertIn("AbortController", js)
        self.assertIn("REQUEST_TIMEOUT_MS", js)
        self.assertIn("signal: controller.signal", js)

    def test_no_innerhtml_from_engine_data(self):
        js = read("popup.js")
        self.assertIsNone(re.search(r"\.innerHTML\s*=", js), "innerHTML assigned; engine text must use textContent")
        self.assertNotIn("insertAdjacentHTML", js)

    def test_save_replaces_record_instead_of_merging(self):
        js = read("popup.js")
        match = re.search(r"async function saveLastScan\(record\)\s*\{(.*?)\n  \}", js, re.S)
        self.assertIsNotNone(match, "saveLastScan not found")
        body = match.group(1)
        self.assertNotIn("loadLastScan", body)
        self.assertNotIn("...previous", body)

    def test_no_inline_scripts_in_html(self):
        html = read("popup.html")
        self.assertIsNone(re.search(r"<script(?![^>]*\bsrc=)", html), "inline script found in popup.html")
        self.assertIsNone(re.search(r"\bon[a-z]+\s*=", html), "inline event handler found in popup.html")


class ReportDownloadTests(unittest.TestCase):
    def setUp(self):
        self.html = read("popup.html")
        self.js = read("popup.js")

    def test_three_report_buttons_in_results_view(self):
        results = self.html.split('id="view-results"', 1)[1]
        for fmt in ("html", "csv", "json"):
            self.assertIn(f'data-format="{fmt}"', results, f"missing {fmt} report button")

    def test_report_buttons_use_engine_report_endpoints(self):
        self.assertIn("/api/scans/", self.js)
        self.assertRegex(self.js, r"report\.\$\{format\}")

    def test_report_download_uses_scan_id_and_timeout(self):
        self.assertIn("encodeURIComponent(data.scan_id)", self.js)
        self.assertIn("REQUEST_TIMEOUT_MS", self.js.split("async function downloadReport", 1)[1])

    def test_export_json_removed(self):
        self.assertNotIn("export-json", self.html)
        self.assertNotIn("export-json", self.js)
        self.assertNotIn("exportJson", self.js)

    def test_report_status_is_announced(self):
        self.assertIn('aria-live="polite"', self.html)


if __name__ == "__main__":
    unittest.main()
