import os
import stat
import unittest.mock
import pytest

from iocscan.core.config import Config, load_config


def test_config_returns_none_when_no_key(tmp_home):
    cfg = load_config()
    assert cfg.key_for("virustotal") is None


def test_env_var_takes_precedence_over_file(tmp_home, monkeypatch):
    cfg_path = tmp_home / ".iocscan" / "config.toml"
    cfg_path.parent.mkdir()
    cfg_path.write_text('[providers]\nvirustotal = "from_file"\n')
    monkeypatch.setenv("IOCSCAN_VT_KEY", "from_env")
    cfg = load_config()
    assert cfg.key_for("virustotal") == "from_env"


def test_cli_overrides_env_and_file(tmp_home, monkeypatch):
    monkeypatch.setenv("IOCSCAN_VT_KEY", "from_env")
    cfg = load_config(cli_keys={"virustotal": "from_cli"})
    assert cfg.key_for("virustotal") == "from_cli"


def test_load_config_reads_settings(tmp_home):
    cfg_path = tmp_home / ".iocscan" / "config.toml"
    cfg_path.parent.mkdir()
    cfg_path.write_text(
        "[settings]\ncache_ttl_hours = 12\ntimeout_seconds = 5\nmin_coverage = 4\n"
    )
    cfg = load_config()
    assert cfg.cache_ttl_hours == 12
    assert cfg.timeout_seconds == 5
    assert cfg.min_coverage == 4


def test_config_set_writes_file_with_0600(tmp_home):
    cfg = load_config()
    cfg.set_key("virustotal", "ABC123")
    path = tmp_home / ".iocscan" / "config.toml"
    assert path.exists()
    mode = oct(path.stat().st_mode)[-3:]
    assert mode == "600"
    # re-read
    again = load_config()
    assert again.key_for("virustotal") == "ABC123"


def test_malformed_toml_raises_clearly(tmp_home):
    cfg_path = tmp_home / ".iocscan" / "config.toml"
    cfg_path.parent.mkdir()
    cfg_path.write_text("this is not toml = [[[")
    with pytest.raises(ValueError, match="config.toml"):
        load_config()


def test_iocscan_cache_ttl_env_overrides_file(tmp_home, monkeypatch):
    cfg_path = tmp_home / ".iocscan" / "config.toml"
    cfg_path.parent.mkdir()
    cfg_path.write_text("[settings]\ncache_ttl_hours = 24\n")
    monkeypatch.setenv("IOCSCAN_CACHE_TTL", "6")
    cfg = load_config()
    assert cfg.cache_ttl_hours == 6


def test_iocscan_cache_ttl_malformed_warns(tmp_home, monkeypatch, capsys):
    monkeypatch.setenv("IOCSCAN_CACHE_TTL", "24h")
    cfg = load_config()
    assert cfg.cache_ttl_hours == 24  # default unchanged
    err = capsys.readouterr().err
    assert "IOCSCAN_CACHE_TTL" in err
    assert "24h" in err


def test_set_key_directory_mode_is_0700(tmp_home):
    """Config directory must be created/fixed to 0o700 (owner-only access)."""
    cfg = load_config()
    cfg.set_key("virustotal", "ABC123")
    parent = tmp_home / ".iocscan"
    dir_mode = stat.S_IMODE(parent.stat().st_mode)
    assert dir_mode == 0o700, (
        f"Expected config dir mode 0o700, got {oct(dir_mode)}"
    )


def test_set_key_tmp_file_never_world_readable(tmp_home):
    """os.open must be used so the tmp file is born 0o600, not chmod'd after."""
    opened_modes: list[int] = []
    real_os_open = os.open

    def recording_open(path, flags, mode=0o777, **kwargs):
        opened_modes.append(mode)
        return real_os_open(path, flags, mode, **kwargs)

    with unittest.mock.patch("os.open", side_effect=recording_open):
        cfg = load_config()
        cfg.set_key("virustotal", "ABC123")

    # At least one os.open call should have been made with mode 0o600
    assert any(m == 0o600 for m in opened_modes), (
        f"Expected os.open called with mode=0o600, got modes: {[oct(m) for m in opened_modes]}"
    )
