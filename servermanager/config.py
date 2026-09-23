"""Static configuration loaded from a TOML file.

Runtime settings that can be changed in the web interface live in the
database (see ``settings.py``). This file only holds what is needed to
boot the application: paths, database URL and the update source.
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = "/etc/servermanager/servermanager.conf"


@dataclass
class Config:
    config_path: str = DEFAULT_CONFIG_PATH
    base_url: str = "http://localhost:8000"
    listen: str = "127.0.0.1:8000"
    trusted_proxies: int = 1
    secure_cookies: bool = True
    data_dir: str = "/var/lib/servermanager"
    secret_key_file: str = "/etc/servermanager/secret.key"
    database_url: str = ""
    repo_dir: str = "/opt/servermanager"
    branch: str = "main"
    helper: str = "/opt/servermanager/bin/sm-helper"
    use_sudo: bool = True
    tls_cert_file: str = ""
    extra: dict = field(default_factory=dict)

    # ---- derived paths -------------------------------------------------
    @property
    def data_path(self) -> Path:
        return Path(self.data_dir)

    @property
    def jobs_dir(self) -> Path:
        return self.data_path / "jobs"

    @property
    def backups_dir(self) -> Path:
        return self.data_path / "backups"

    @property
    def system_backups_dir(self) -> Path:
        return self.data_path / "system-backups"

    @property
    def ssh_dir(self) -> Path:
        return self.data_path / "ssh"

    @property
    def wireguard_dir(self) -> Path:
        return self.data_path / "wireguard"

    @property
    def staging_dir(self) -> Path:
        return self.data_path / "restore-staging"

    @property
    def ssh_key_path(self) -> Path:
        return self.ssh_dir / "id_ed25519"

    def ensure_dirs(self) -> None:
        for p in (self.data_path, self.jobs_dir, self.backups_dir, self.system_backups_dir,
                  self.ssh_dir, self.wireguard_dir):
            p.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(p, 0o700)
            except PermissionError:
                pass


def load_config(path: str | None = None) -> Config:
    path = path or os.environ.get("SM_CONFIG", DEFAULT_CONFIG_PATH)
    cfg = Config(config_path=path)
    data: dict = {}
    if os.path.exists(path):
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    else:
        # Development fallback: keep everything inside ./dev-data
        dev = Path(os.environ.get("SM_DEV_DATA", "dev-data")).absolute()
        cfg.data_dir = str(dev)
        cfg.secret_key_file = str(dev / "secret.key")
        cfg.secure_cookies = False
        cfg.use_sudo = False
        cfg.repo_dir = str(Path(__file__).resolve().parent.parent)
        cfg.helper = str(Path(cfg.repo_dir) / "bin" / "sm-helper")

    server = data.get("server", {})
    paths = data.get("paths", {})
    database = data.get("database", {})
    update = data.get("update", {})

    cfg.base_url = server.get("base_url", cfg.base_url).rstrip("/")
    cfg.listen = server.get("listen", cfg.listen)
    cfg.trusted_proxies = int(server.get("trusted_proxies", cfg.trusted_proxies))
    cfg.secure_cookies = bool(server.get("secure_cookies", cfg.secure_cookies))
    cfg.tls_cert_file = server.get("tls_cert_file", cfg.tls_cert_file)
    cfg.data_dir = paths.get("data_dir", cfg.data_dir)
    cfg.secret_key_file = paths.get("secret_key_file", cfg.secret_key_file)
    cfg.database_url = database.get("url", "") or f"sqlite:///{Path(cfg.data_dir) / 'servermanager.db'}"
    cfg.repo_dir = update.get("repo_dir", cfg.repo_dir)
    cfg.branch = update.get("branch", cfg.branch)
    cfg.helper = update.get("helper", cfg.helper)
    cfg.use_sudo = bool(update.get("use_sudo", cfg.use_sudo))
    cfg.extra = data

    # Environment overrides (useful for tests and containers)
    if os.environ.get("SM_DATA_DIR"):
        cfg.data_dir = os.environ["SM_DATA_DIR"]
        cfg.database_url = f"sqlite:///{Path(cfg.data_dir) / 'servermanager.db'}"
        cfg.secret_key_file = str(Path(cfg.data_dir) / "secret.key")
    if os.environ.get("SM_DATABASE_URL"):
        cfg.database_url = os.environ["SM_DATABASE_URL"]
    if os.environ.get("SM_BASE_URL"):
        cfg.base_url = os.environ["SM_BASE_URL"].rstrip("/")
    return cfg


_config: Config | None = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = load_config()
    return _config


def set_config(cfg: Config) -> None:
    global _config
    _config = cfg
