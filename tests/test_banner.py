"""UI.banner() geometry / colour / ASCII + the CLI suppression matrix
(tty, --quiet, --json, non-tty stderr, --no-color, piped stdout, --ascii).
The banner is the first thing an operator sees and the first thing that
breaks a JSON pipeline if it leaks."""
import os
import re
import shutil
import tempfile
import unittest

from tests._helpers import SGR, run_cli
from core.ui import UI, C

SECRET_ROW2 = r" / ___|  ___  ___ _ __ __| |_  "
HOUND_ROW3 = r"| |_| |/ _ \| | | | '_ \ / _` |"
HOUND_ART = r"(    @\___"


class BannerRenderTests(unittest.TestCase):
    # 1
    def test_banner_geometry(self):
        b = UI(use_color=False).banner("2.0")
        lines = b.split("\n")
        self.assertEqual(len(lines), 16)
        self.assertLessEqual(max(len(l) for l in lines), 80)        # observed 71
        self.assertEqual(lines[0], lines[-1])                         # top/bottom frame identical
        self.assertEqual(lines[6], "")                                # blank between hound and wordmark
        colour = UI(use_color=True).banner("2.0")
        self.assertEqual([SGR.sub("", l) for l in colour.split("\n")], lines)   # colour never changes geometry

    # 2
    def test_banner_wordmark_and_text(self):
        b = UI(use_color=False).banner("2.0")
        for frag in (SECRET_ROW2, HOUND_ROW3, HOUND_ART,
                     "H U N T  ●  C O L L E C T  ●  O R G A N I Z E",
                     "v2.0", "Red Team Loot Intelligence", "═", "─"):
            self.assertIn(frag, b)
        b2 = UI(use_color=False).banner("9.9", subtitle="X")
        self.assertIn("v9.9", b2)
        self.assertIn("X", b2)

    # 3
    def test_banner_colour_codes(self):
        b = UI(use_color=True).banner()
        for k in ("red", "white", "dred", "reset"):
            self.assertIn(C[k], b)
        self.assertNotIn("\033", SGR.sub("", b))
        self.assertNotIn("\033", UI(use_color=False).banner())

    # 4
    def test_banner_ascii_mode(self):
        b = UI(use_color=False, ascii_only=True).banner()
        lines = b.split("\n")
        self.assertTrue(all(ord(ch) < 128 for ch in b))
        self.assertIn("H U N T  *  C O L L E C T  *  O R G A N I Z E", b)
        self.assertEqual(lines[0].strip(), "=" * 69)
        self.assertIn("-" * 69, b)
        self.assertIn(SECRET_ROW2, b)                                 # wordmark unchanged in ASCII mode
        self.assertEqual(len(lines), 16)

    # 5
    def test_no_color_env_wins(self):
        os.environ["NO_COLOR"] = "1"
        try:
            u = UI(use_color=True)
            self.assertIs(u.color, False)
            self.assertNotIn("\033", u.banner())
        finally:
            os.environ.pop("NO_COLOR", None)

    # 6
    def test_non_utf8_locale_forces_ascii(self):
        saved = {k: os.environ.get(k) for k in ("LANG", "LC_ALL", "LC_CTYPE")}
        os.environ["LANG"] = "C"
        os.environ.pop("LC_ALL", None)
        os.environ.pop("LC_CTYPE", None)
        try:
            u = UI(use_color=False)
            self.assertIs(u.ascii, True)
            self.assertTrue(all(ord(ch) < 128 for ch in u.banner()))
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            os.environ["LANG"] = "C.UTF-8"


class BannerCliMatrixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sh-banner-")
        self.out = tempfile.mkdtemp(prefix="sh-banner-out-")
        with open(os.path.join(self.tmp, "notes.txt"), "w") as fh:
            fh.write("creds: jdoe:Summer2024!\n")
        self.args = [self.tmp, "--no-inventory", "--no-pot",
                     "--users-out", os.path.join(self.out, "users.txt")]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        shutil.rmtree(self.out, ignore_errors=True)

    # 7
    def test_cli_banner_on_tty_goes_to_stderr_only(self):
        rc, so, se = run_cli(self.args, stdout_tty=True, stderr_tty=True)
        self.assertEqual(rc, 0)
        self.assertIn("H U N T", se)
        self.assertIn(SECRET_ROW2, se)
        self.assertNotIn("H U N T", so)
        self.assertTrue(SGR.search(so))
        self.assertTrue(SGR.search(se))
        self.assertIn("scanning", se)

    # 8
    def test_cli_quiet_suppresses_all_stderr(self):
        rc, so, se = run_cli(self.args + ["-q"], stdout_tty=True, stderr_tty=True)
        self.assertEqual(rc, 0)
        self.assertEqual(se, "")
        self.assertIn("CRED PAIRS", so)                               # results still printed

    # 9
    def test_cli_json_suppresses_banner_but_keeps_status(self):
        j = os.path.join(self.out, "f.json")
        rc, so, se = run_cli(self.args + ["--json", j], stdout_tty=True, stderr_tty=True)
        self.assertEqual(rc, 0)
        self.assertNotIn("H U N T", se)
        self.assertIn("scanning", se)
        self.assertGreater(os.path.getsize(j), 0)

    # 10
    def test_cli_stderr_not_tty_suppresses_banner(self):
        rc, so, se = run_cli(self.args, stdout_tty=True, stderr_tty=False)
        self.assertEqual(rc, 0)
        self.assertNotIn("H U N T", se)
        self.assertIn("scanning", se)
        self.assertNotIn("\033[K", se)                                # progress bar off when stderr is not a tty

    # 11
    def test_cli_no_color_and_piped_stdout_have_no_sgr(self):
        rc, so, se = run_cli(self.args + ["--no-color"], stdout_tty=True, stderr_tty=True)
        self.assertEqual(rc, 0)
        self.assertIsNone(SGR.search(so))
        self.assertIsNone(SGR.search(se))
        self.assertIn("H U N T", se)                                  # banner still shown, uncoloured
        # NB: "\033[K" (progress erase) MAY appear in se - never assert on "\033" directly.
        rc, so, se = run_cli(self.args, stdout_tty=False, stderr_tty=True)
        self.assertEqual(rc, 0)
        self.assertIsNone(SGR.search(so))                             # colour keyed off stdout tty
        self.assertIsNone(SGR.search(se))
        self.assertIn("H U N T", se)                                  # banner keyed off stderr tty

    # 12
    def test_cli_ascii_has_no_non_ascii_bytes(self):
        rc, so, se = run_cli(self.args + ["--ascii"], stdout_tty=True, stderr_tty=True)
        self.assertEqual(rc, 0)
        bad = sorted({ch for ch in so + se if ord(ch) >= 128})
        self.assertEqual(bad, [], f"non-ASCII glyphs leaked under --ascii: {bad!r}")
        # the bullets are colour-accented on a tty, so compare the plain text
        self.assertIn("H U N T  *  C O L L E C T", SGR.sub("", se))
        self.assertTrue("->" in so or ">" in so)                      # arrow glyphs transliterated


if __name__ == "__main__":
    unittest.main()
