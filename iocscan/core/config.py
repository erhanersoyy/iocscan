from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import tomli_w

CONFIG_DIR = ".iocscan"
CONFIG_FILE = "config.toml"

ENV_VARS = {
    "abusech":    "IOCSCAN_ABUSECH_KEY",
    "virustotal": "IOCSCAN_VT_KEY",
    "abuseipdb":  "IOCSCAN_ABUSEIPDB_KEY",
    "otx":        "IOCSCAN_OTX_KEY",
    "greynoise":  "IOCSCAN_GREYNOISE_KEY",
    "urlscan":    "IOCSCAN_URLSCAN_KEY",
}


@dataclass
class Config:
    keys: dict[str, str] = field(default_factory=dict)
    cache_ttl_hours: int = 24
    timeout_seconds: int = 20
    min_coverage: int = 3
    path: Path | None = None

    def key_for(self, provider: str) -> str | None:
        return self.keys.get(provider)

    def set_key(self, provider: str, value: str) -> None:
        self.keys[provider] = value
        target = self.path or _default_path()
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(target.parent, 0o700)
        payload = {
            "providers": dict(self.keys),
            "settings": {
                "cache_ttl_hours": self.cache_ttl_hours,
                "timeout_seconds": self.timeout_seconds,
                "min_coverage": self.min_coverage,
            },
        }
        # with_suffix would strip ".toml"; append instead so an orphaned tmp
        # from a crashed write is recognisably "<target>.tmp".
        tmp = target.parent / (target.name + ".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(tomli_w.dumps(payload).encode("utf-8"))
        os.chmod(tmp, 0o600)
        tmp.replace(target)
        os.chmod(target, 0o600)
        self.path = target


def _default_path() -> Path:
    return Path(os.path.expanduser("~")) / CONFIG_DIR / CONFIG_FILE


def load_config(cli_keys: dict[str, str] | None = None) -> Config:
    path = _default_path()
    file_keys: dict[str, str] = {}
    settings: dict = {}
    if path.exists():
        try:
            data = tomllib.loads(path.read_text())
        except tomllib.TOMLDecodeError as e:
            raise ValueError(f"malformed config.toml at {path}: {e}") from e
        file_keys = {k: str(v) for k, v in data.get("providers", {}).items()}
        settings = data.get("settings", {})

    merged: dict[str, str] = dict(file_keys)
    for provider, env_name in ENV_VARS.items():
        val = os.environ.get(env_name)
        if val:
            merged[provider] = val
    if cli_keys:
        merged.update({k: v for k, v in cli_keys.items() if v})

    ttl_env = os.environ.get("IOCSCAN_CACHE_TTL")
    if ttl_env:
        try:
            settings = dict(settings)
            settings["cache_ttl_hours"] = int(ttl_env)
        except ValueError:
            import sys
            print(
                f"warning: IOCSCAN_CACHE_TTL='{ttl_env}' is not an integer; ignoring",
                file=sys.stderr,
            )

    return Config(
        keys=merged,
        cache_ttl_hours=int(settings.get("cache_ttl_hours", 24)),
        timeout_seconds=int(settings.get("timeout_seconds", 20)),
        min_coverage=int(settings.get("min_coverage", 3)),
        path=path,
    )
