"""Panel configuration, read from the environment (12-factor, Docker-friendly)."""

from __future__ import annotations

import os
import secrets


class Settings:
    def __init__(self) -> None:
        # Signing/encryption. MUST be set & stable in production (compose .env).
        self.secret_key: str = os.environ.get("PANEL_SECRET_KEY", "")
        if not self.secret_key:
            # Dev fallback so the app still boots; sessions/secrets won't survive
            # a restart and this is logged loudly at startup.
            self.secret_key = secrets.token_urlsafe(32)
            self.secret_key_ephemeral = True
        else:
            self.secret_key_ephemeral = False

        self.database_url: str = os.environ.get("DATABASE_URL", "sqlite:///./data/panel.db")

        # First-run admin bootstrap.
        self.admin_username: str = os.environ.get("ADMIN_USERNAME", "admin")
        self.admin_password: str = os.environ.get("ADMIN_PASSWORD", "")

        # Temporary password assigned to admin-created users; they must change it
        # on first login.
        self.default_user_password: str = os.environ.get("DEFAULT_USER_PASSWORD", "change-me-123")

        # 3x-ui installer used for provisioning a fresh node (mainline MHSanaei).
        self.xui_install_cmd: str = os.environ.get(
            "XUI_INSTALL_CMD",
            "curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh -o /tmp/3xui-install.sh "
            "&& bash /tmp/3xui-install.sh",
        )
        self.xui_folder: str = os.environ.get("XUI_FOLDER", "/usr/local/x-ui")

        # The latest Xray bundled by the installer doesn't work on all clients;
        # pin every freshly provisioned node to this known-good version.
        self.xray_version: str = os.environ.get("XRAY_VERSION", "v26.6.27")

        # AmneziaWG auto-deploy. The panel now stands the AWG server up itself,
        # as a container from the official amneziavpn/amneziawg-go image (the
        # same engine the AmneziaVPN app runs), mounting its config dir at the
        # app's /opt/amnezia/awg path so awg.py reads it unchanged.
        self.awg_image: str = os.environ.get("AWG_IMAGE", "amneziavpn/amneziawg-go:latest")
        self.awg_container: str = os.environ.get("AWG_CONTAINER", "vespn-awg")
        self.awg_conf_dir: str = os.environ.get("AWG_CONF_DIR", "/opt/vespn-awg")

        # Cookie/session
        self.session_cookie: str = os.environ.get("SESSION_COOKIE", "vpnpanel_session")
        self.session_https_only: bool = os.environ.get("SESSION_HTTPS_ONLY", "false").lower() == "true"

        # Telegram bot (optional): daily backup+stats, hourly monitoring + alerts,
        # and on-demand /check /backup /status commands. The bot runs as a
        # background thread inside the panel process and stays dormant until a
        # token is set. TG_ADMIN_CHAT is a comma-separated list of chat ids that
        # receive messages and may issue commands.
        self.tg_bot_token: str = os.environ.get("TG_BOT_TOKEN", "")
        self.tg_admin_chat: str = os.environ.get("TG_ADMIN_CHAT", "")
        # Telegram's API is blocked from RU, where the Hub lives. Point the bot at
        # a reachable proxy that forwards to api.telegram.org (e.g. a Cloudflare
        # Worker — Cloudflare is reachable from RU). Default = direct.
        self.tg_api_base: str = os.environ.get("TG_API_BASE", "https://api.telegram.org")
        self.tg_backup_hour: int = int(os.environ.get("TG_BACKUP_HOUR", "6"))  # UTC hour for the daily backup
        self.tg_monitor_minutes: int = int(os.environ.get("TG_MONITOR_MINUTES", "60"))  # monitoring cadence

    @property
    def tg_admin_chats(self) -> list[str]:
        return [c.strip() for c in self.tg_admin_chat.split(",") if c.strip()]

    @property
    def tg_enabled(self) -> bool:
        return bool(self.tg_bot_token and self.tg_admin_chats)


settings = Settings()
