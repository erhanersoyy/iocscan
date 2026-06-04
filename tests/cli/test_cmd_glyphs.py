from __future__ import annotations


def test_glyphs_subcommand_renders_reference(tmp_home, capsys):
    """`iocscan glyphs` prints the symbol reference table and exits 0."""
    from iocscan.cli import main

    rc = main(["glyphs"])
    out = capsys.readouterr().out
    assert rc == 0
    for word in ("malicious", "inconclusive", "whitelist"):
        assert word in out, word
