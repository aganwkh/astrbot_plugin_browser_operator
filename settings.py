from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_DATA_DIR = Path("/opt/AstrBot/data")


@dataclass(frozen=True)
class BrowserRuntimeConfig:
    chrome_path: str
    headless: bool
    data_dir: Path
    temp_dir: Path
    profile_base_dir: Path
    profile_dir: Path
    profile_scope: str
    profile_key: str
    use_proxy: bool
    proxy_server: str
    viewport_width: int
    viewport_height: int
    default_timeout_ms: int
    allow_private_network: bool
    allowed_users: list[str]
    allowed_sessions: list[str]
    allowed_domains: list[str]
    blocked_domains: list[str]
    max_pages: int
    max_download_size_mb: int
    block_screenshots_in_sensitive_mode: bool


def parse_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def safe_id(value: str, limit: int = 80) -> str:
    text = str(value or "unknown")
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in text)
    return safe[:limit] or "unknown"


def _cfg(config: Any, key: str, default=None):
    try:
        return config.get(key, default)
    except Exception:
        return default


def _event_value(event: Any, method_name: str, default: str) -> str:
    try:
        method = getattr(event, method_name)
        return str(method())
    except Exception:
        return default


def _bool_cfg(config: Any, key: str, default: bool) -> bool:
    value = _cfg(config, key, default)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _int_cfg(config: Any, key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(_cfg(config, key, default))
    except Exception:
        value = default
    return max(minimum, min(value, maximum))


def _profile_dir_for_scope(base_dir: Path, scope: str, event: Any) -> tuple[str, Path]:
    sender_id = safe_id(_event_value(event, "get_sender_id", "unknown_user"))
    session_id = safe_id(_event_value(event, "get_session_id", "unknown_session"))
    platform = safe_id(_event_value(event, "get_platform_name", "unknown_platform"))

    if scope == "global":
        return "global", base_dir / "global"
    if scope == "user":
        return f"user:{sender_id}", base_dir / "users" / sender_id
    if scope == "platform_session":
        return f"platform_session:{platform}:{session_id}", base_dir / "platform_sessions" / platform / session_id
    return f"session:{session_id}", base_dir / "sessions" / session_id


def build_runtime_config(config: Any, event: Any) -> BrowserRuntimeConfig:
    data_dir = Path(str(_cfg(config, "data_dir", str(DEFAULT_DATA_DIR)) or str(DEFAULT_DATA_DIR))).expanduser()
    temp_dir = Path(str(_cfg(config, "temp_dir", "") or data_dir / "temp")).expanduser()
    profile_base_dir = Path(
        str(_cfg(config, "user_data_dir", "") or data_dir / "browser_profiles")
    ).expanduser()
    profile_scope = str(_cfg(config, "profile_scope", "session") or "session").strip().lower()
    if profile_scope not in {"global", "session", "user", "platform_session"}:
        profile_scope = "session"
    profile_key, profile_dir = _profile_dir_for_scope(profile_base_dir, profile_scope, event)

    return BrowserRuntimeConfig(
        chrome_path=str(_cfg(config, "chrome_path", "") or "").strip(),
        headless=_bool_cfg(config, "headless", True),
        data_dir=data_dir,
        temp_dir=temp_dir,
        profile_base_dir=profile_base_dir,
        profile_dir=profile_dir,
        profile_scope=profile_scope,
        profile_key=profile_key,
        use_proxy=_bool_cfg(config, "use_proxy", False),
        proxy_server=str(_cfg(config, "proxy_server", "") or "").strip(),
        viewport_width=_int_cfg(config, "viewport_width", 1280, 240, 3840),
        viewport_height=_int_cfg(config, "viewport_height", 800, 240, 5000),
        default_timeout_ms=_int_cfg(config, "default_timeout_ms", 15000, 1000, 120000),
        allow_private_network=_bool_cfg(config, "allow_private_network", False),
        allowed_users=parse_list(_cfg(config, "allowed_users", [])),
        allowed_sessions=parse_list(_cfg(config, "allowed_sessions", [])),
        allowed_domains=parse_list(_cfg(config, "allowed_domains", [])),
        blocked_domains=parse_list(_cfg(config, "blocked_domains", [])),
        max_pages=_int_cfg(config, "max_pages", 5, 1, 20),
        max_download_size_mb=_int_cfg(config, "max_download_size_mb", 50, 1, 1024),
        block_screenshots_in_sensitive_mode=_bool_cfg(config, "block_screenshots_in_sensitive_mode", True),
    )
