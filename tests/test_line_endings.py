"""iter-311: Windows captures arrive as CRLF (and sometimes UTF-16LE).

filters.read_text() used to keep the '\\r', so every multi-line detector
anchored on `[ \\t]*$` silently missed CRLF captures. These tests pin the
fix: the same capture in LF, CRLF and UTF-16LE must produce the same
findings on the same line numbers.
"""
import os
import tempfile
import unittest

from tests._helpers import StubReport
from analyzers import filters, keyword
from analyzers.ingest.evidence import Store as StubStore

try:
    from analyzers import privesc
    HAVE_PRIVESC = True
except Exception:  # pragma: no cover
    HAVE_PRIVESC = False


GNL = ("PS C:\\> Get-NetLoggedOn -ComputerName WEB01\n"
       "UserName      UserDomain  LogonServer  ComputerName\n"
       "--------      ----------  -----------  ------------\n"
       "alice         CORP        DC01         WEB01\n"
       "Administrator CORP        DC01         WEB01\n")

WHOAMI = ("PRIVILEGES INFORMATION\n"
          "----------------------\n"
          "\n"
          "Privilege Name                Description                               State\n"
          "============================= ========================================= ========\n"
          "SeImpersonatePrivilege        Impersonate a client after authentication Enabled\n"
          "SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled\n")


def _write(raw_bytes, suffix=".txt"):
    fd, p = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw_bytes)
    return p


def _encodings(text):
    return {
        "lf": text.encode("utf-8"),
        "crlf": text.replace("\n", "\r\n").encode("utf-8"),
        "utf16le-bom-crlf": b"\xff\xfe" + text.replace("\n", "\r\n").encode("utf-16-le"),
    }


def _run(module, raw):
    p = _write(raw)
    try:
        r, s = StubReport(), StubStore()
        module.analyze(p, r, s)
        return r.findings
    finally:
        os.unlink(p)


class ReadTextEOL(unittest.TestCase):
    def test_crlf_normalised(self):
        p = _write(b"a\r\nb\r\nc")
        try:
            self.assertEqual(filters.read_text(p), "a\nb\nc")
        finally:
            os.unlink(p)

    def test_lone_cr_normalised_like_universal_newlines(self):
        p = _write(b"a\rb\nc")
        try:
            self.assertEqual(filters.read_text(p), "a\nb\nc")
            with open(p, "r") as fh:   # universal-newline mode
                self.assertEqual(fh.read(), "a\nb\nc")
        finally:
            os.unlink(p)

    def test_utf16_bom_crlf(self):
        p = _write(b"\xff\xfe" + "x\r\ny".encode("utf-16-le"))
        try:
            self.assertEqual(filters.read_text(p), "x\ny")
        finally:
            os.unlink(p)


class MultilineDetectorsOnCRLF(unittest.TestCase):
    def _sig(self, findings, needle):
        return sorted((f["line"], f["severity"]) for f in findings if needle in f["detail"])

    def test_get_netloggedon_rows_fire_on_crlf(self):
        enc = _encodings(GNL)
        lf = self._sig(_run(keyword, enc["lf"]), "Logged-on session")
        crlf = self._sig(_run(keyword, enc["crlf"]), "Logged-on session")
        self.assertEqual(len(lf), 2, lf)
        self.assertEqual(crlf, lf, "CRLF capture must match LF findings + line numbers")

    @unittest.skipUnless(HAVE_PRIVESC, "analyzers/privesc.py missing")
    def test_whoami_priv_fires_on_crlf_and_utf16(self):
        enc = _encodings(WHOAMI)
        base = self._sig(_run(privesc, enc["lf"]), "SeImpersonatePrivilege")
        self.assertEqual(len(base), 1, base)
        self.assertEqual(base[0][1], "CRITICAL")
        for name in ("crlf", "utf16le-bom-crlf"):
            got = self._sig(_run(privesc, enc[name]), "SeImpersonatePrivilege")
            self.assertEqual(got, base, f"{name}: {got} != {base}")

    @unittest.skipUnless(HAVE_PRIVESC, "analyzers/privesc.py missing")
    def test_whoami_table_row_not_double_reported(self):
        # privesc.py owns the table; keyword.py's per-line marker must stand
        # down on the row (it still fires on bare tool-name mentions).
        raw = WHOAMI.replace("\n", "\r\n").encode("utf-8")
        kw = [f for f in _run(keyword, raw) if "SeImpersonate" in f["detail"]]
        pv = [f for f in _run(privesc, raw) if "SeImpersonate" in f["detail"]]
        self.assertEqual(kw, [], kw)
        self.assertEqual(len(pv), 1, pv)


if __name__ == "__main__":
    unittest.main()


class Utf16LootParity(unittest.TestCase):
    """iter-313: Windows PowerShell 5.1 `cmd > out.txt` writes UTF-16LE+BOM.
    Every single-line analyzer used a UTF-8 open(), so such captures lost
    their hashes, creds and chains. The full CLI must now report the same
    findings for UTF-8, UTF-16LE+BOM and UTF-16BE+BOM copies of one file."""

    CAPTURE = ("PS C:\\> type C:\\inetpub\\wwwroot\\web.config\r\n"
               "<add name=\"db\" connectionString=\"Server=sql01;User ID=sa;"
               "Password=Sup3rS3cret!\" />\r\n"
               "Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
               "e19ccf75ee54e06b06a5907af13cef42:::\r\n")

    def _cli_findings(self, raw):
        from tests._helpers import run_cli
        import shutil
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, "loot.txt"), "wb") as fh:
                fh.write(raw)
            out = run_cli([d, "--no-color", "--quiet", "--no-inventory", "--no-pot"])
            text = out[1] if isinstance(out, tuple) else str(out)
            return sorted({ln.split("  ", 1)[-1].strip()[:60]
                           for ln in text.splitlines()
                           if "loot.txt:" in ln and ln.strip().startswith("[")})
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_open_text_contract(self):
        p = _write(b"\xff\xfe" + "a\r\nb\r\n".encode("utf-16-le"))
        try:
            with filters.open_text(p) as fh:
                self.assertEqual(list(fh), ["a\n", "b\n"])
            with self.assertRaises(OSError):
                filters.open_text(p + ".missing")
        finally:
            os.unlink(p)

    def test_utf16_capture_same_findings_as_utf8(self):
        base = self._cli_findings(self.CAPTURE.encode("utf-8"))
        self.assertTrue(any("e19ccf75ee54e06b06a5907af13cef42" in b or "Administrator" in b
                            or "Sup3rS3cret" in b for b in base), base)
        for name, raw in (("utf16le", b"\xff\xfe" + self.CAPTURE.encode("utf-16-le")),
                          ("utf16be", b"\xfe\xff" + self.CAPTURE.encode("utf-16-be"))):
            self.assertEqual(self._cli_findings(raw), base, name)
