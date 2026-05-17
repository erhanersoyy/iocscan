import os
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
