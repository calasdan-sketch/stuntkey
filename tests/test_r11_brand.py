"""Round 11: Calas brand layer (brand.py, local page, docs/site)."""
import io
import os
import re
import unittest
from unittest import mock

from stuntkey import brand

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, "stuntkey", "web", "index.html")
SITE = os.path.join(ROOT, "docs", "site")


def _read(p):
    with open(p, encoding="utf8") as f:
        return f.read()


def _lum(h):
    h = h.lstrip("#")
    out = []
    for i in (0, 2, 4):
        c = int(h[i:i + 2], 16) / 255
        out.append(c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4)
    return 0.2126 * out[0] + 0.7152 * out[1] + 0.0722 * out[2]


def ratio(a, b):
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


class FakeTTY(io.StringIO):
    def __init__(self, tty, encoding="utf-8"):
        super().__init__()
        self._tty = tty
        self._enc = encoding

    @property
    def encoding(self):
        return self._enc

    def isatty(self):
        return self._tty


CLEAN = {k: v for k, v in os.environ.items()
         if k not in ("NO_COLOR", "FORCE_COLOR", "CLICOLOR_FORCE", "COLORTERM", "WT_SESSION", "TERM")}


class BrandPy(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(brand.COLORS["blue"], "#155F87")
        self.assertEqual(brand.COLORS["gold"], "#F0C171")

    def test_no_color_env(self):
        with mock.patch.dict(os.environ, dict(CLEAN, NO_COLOR="1"), clear=True):
            s = FakeTTY(True)
            self.assertNotIn("\x1b", brand.banner(s))
            self.assertNotIn("\x1b", brand.ok("x", s))

    def test_non_tty_has_no_escapes(self):
        with mock.patch.dict(os.environ, CLEAN, clear=True):
            s = FakeTTY(False)
            for text in (brand.banner(s), brand.step(1, 3, "a", s), brand.warn("w", s),
                         brand.fail("f", s), brand.plain_box("T", ["one", "two"], s)):
                self.assertNotIn("\x1b", text)

    def test_banner_words(self):
        with mock.patch.dict(os.environ, CLEAN, clear=True):
            b = brand.banner(FakeTTY(False))
        self.assertIn("STUNTKEY", b)
        self.assertIn("BY CALAS AUTOMATIONS", b)

    def test_ascii_only_on_cp1252_and_ascii_streams(self):
        with mock.patch.dict(os.environ, CLEAN, clear=True):
            for enc in ("ascii", "cp1252"):
                s = FakeTTY(False, encoding=enc)
                text = "\n".join([brand.banner(s), brand.ok("a", s), brand.warn("b", s),
                                  brand.fail("c", s), brand.step(2, 4, "d", s),
                                  brand.plain_box("Title", ["line"], s)])
                text.encode("ascii")          # must not raise

    def test_color_on_when_forced_tty(self):
        env = dict(CLEAN, FORCE_COLOR="1", COLORTERM="truecolor")
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(brand, "_enable_windows_vt", return_value=True):
            b = brand.banner(FakeTTY(True))
        self.assertIn("\x1b[", b)
        self.assertIn("38;2;21;95;135", b)        # #155F87

    def test_legacy_windows_console_stays_plain(self):
        env = dict(CLEAN, FORCE_COLOR="1")
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(brand, "_enable_windows_vt", return_value=False):
            self.assertNotIn("\x1b", brand.ok("x", FakeTTY(True)))

    def test_helpers_write_when_given_a_stream(self):
        with mock.patch.dict(os.environ, CLEAN, clear=True):
            s = FakeTTY(False)
            brand.step(1, 2, "go", s)
            self.assertIn("Step 1 of 2: go", s.getvalue())

    def test_plain_box_lines_same_width(self):
        with mock.patch.dict(os.environ, CLEAN, clear=True):
            box = brand.plain_box("Hello", ["short", "a much longer line " * 6], FakeTTY(False))
        widths = {len(x) for x in box.splitlines()}
        self.assertEqual(len(widths), 1)


class Pages(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile(WEB):
            self.skipTest("web page not present")

    def test_local_page_branding(self):
        h = _read(WEB)
        self.assertIn("BY CALAS AUTOMATIONS", h)
        self.assertIn("StuntKey", h)
        self.assertIn("-webkit-mask:var(--crest-img)", h)
        self.assertIn("data:image/png;base64,iVBORw0KGgo", h)
        self.assertIn("rotateY(360deg)", h)
        self.assertIn("6s linear infinite", h)
        self.assertNotIn("perspective", h)
        self.assertNotIn("preserve-3d", h)
        self.assertIn("prefers-reduced-motion", h)
        self.assertIn("prefers-color-scheme:dark", h)
        self.assertIn("{{status_json}}", h)
        self.assertIn("{{version}}", h)

    def test_local_page_makes_no_external_requests(self):
        h = _read(WEB)
        self.assertNotRegex(h, r"<script[^>]+src=")
        self.assertNotRegex(h, r"<link[^>]+href=\"https?:")
        self.assertNotRegex(h, r"(?:src|href)=\"https?://")

    def test_site_pages(self):
        for name in ("index.html", "how-it-works.html", "add-your-first-key.html"):
            h = _read(os.path.join(SITE, name))
            self.assertIn("BY CALAS AUTOMATIONS", h, name)
            self.assertNotRegex(h, r"<script[^>]+src=", name)
            for m in re.findall(r"<link(?![^>]*canonical)[^>]+href=\"(https?://[^\"]+)\"", h):
                self.assertTrue(m.startswith("https://fonts.g"), (name, m))
        css = _read(os.path.join(SITE, "styles.css"))
        self.assertIn("-webkit-mask:var(--crest-img)", css)
        self.assertIn("base64,iVBORw0KGgo", css)

    def test_no_hand_drawn_crest(self):
        for p in [WEB] + [os.path.join(SITE, n) for n in os.listdir(SITE) if n.endswith((".html", ".css"))]:
            t = _read(p)
            self.assertNotRegex(t, r"<svg", p)
            self.assertNotRegex(t, r"<path\b", p)

    def test_crest_is_the_real_logo(self):
        import base64
        css = _read(os.path.join(SITE, "styles.css"))
        b64 = re.search(r"base64,([A-Za-z0-9+/=]+)\)", css).group(1)
        raw = base64.b64decode(b64)
        self.assertEqual(raw[:8], b"\x89PNG\r\n\x1a\n")
        with open(os.path.join(SITE, "favicon.png"), "rb") as f:
            self.assertEqual(raw, f.read())

    def test_page_text_has_no_unreplaced_build_tokens(self):
        self.assertNotIn("@@", _read(WEB))
        self.assertNotIn("@@", _read(os.path.join(SITE, "styles.css")))


class Contrast(unittest.TestCase):
    def setUp(self):
        p = os.path.join(SITE, "styles.css")
        if not os.path.isfile(p):
            self.skipTest("docs not present")
        self.css = _read(p)

    def tokens(self, dark):
        blocks = re.findall(r"(:root[^{]*)\{([^}]*)\}", self.css)
        tok = {}
        for sel, body in blocks:
            is_dark = "dark" in sel or ("prefers" in sel)
            if is_dark and not dark:
                continue
            for k, v in re.findall(r"--([a-z0-9-]+):(#[0-9A-Fa-f]{6})", body):
                tok[k] = v
        # the media-query block: its selector is captured differently
        if dark:
            m = re.search(r"prefers-color-scheme:dark\)\{:root:not\(\[data-theme=\"light\"\]\)\{([^}]*)\}", self.css)
            for k, v in re.findall(r"--([a-z0-9-]+):(#[0-9A-Fa-f]{6})", m.group(1)):
                tok[k] = v
        return tok

    def test_wcag_aa_both_themes(self):
        for dark in (False, True):
            t = self.tokens(dark)
            pairs = [("ink", "paper"), ("ink-2", "paper"), ("ink-2", "sunk"), ("ink", "sunk"),
                     ("accent", "paper"), ("accent", "sunk"), ("btn-ink", "btn-bg"),
                     ("gold-text", "paper"), ("ok", "paper"), ("warn", "paper"),
                     ("code-ink", "code-bg"), ("focus", "paper")]
            for a, b in pairs:
                r = ratio(t[a], t[b])
                need = 3.0 if a == "focus" else 4.5
                self.assertGreaterEqual(r, need, (("dark" if dark else "light"), a, b, round(r, 2)))

    def test_hero_band(self):
        navy = "#0B2E45"
        for fg in ("#FFFFFF", "#D3E3EE", "#7FBFE3", "#F0C171"):
            self.assertGreaterEqual(ratio(fg, navy), 4.5, fg)
        self.assertGreaterEqual(ratio("#0B2E45", "#F0C171"), 4.5)   # gold button text


if __name__ == "__main__":
    unittest.main()
