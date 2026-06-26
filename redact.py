import re
from typing import Any


SENSITIVE_RE = re.compile(
    r"(?i)(access[_-]?token|refresh[_-]?token|id[_-]?token|authorization|cookie|password|passwd|secret|api[_-]?key|session)[\s:=\"']+([^\s\"'&;,}]+)"
)

SENSITIVE_KEYWORDS = [
    "password",
    "passwd",
    "pwd",
    "token",
    "cookie",
    "secret",
    "apikey",
    "api_key",
    "authorization",
    "auth",
    "bearer",
    "验证码",
    "密码",
    "令牌",
    "密钥",
]


def mask_sensitive(value: Any, limit: int = 4000) -> str:
    if value is None:
        return ""
    text = str(value)
    text = SENSITIVE_RE.sub(lambda m: f"{m.group(1)}=<masked>", text)
    if len(text) > limit:
        text = text[:limit] + f"\n\n... 已截断（原长度 {len(text)}）"
    return text


def looks_sensitive(text: str) -> bool:
    normalized = (text or "").lower()
    return any(keyword.lower() in normalized for keyword in SENSITIVE_KEYWORDS)


def is_sensitive_metadata(metadata: dict[str, Any]) -> bool:
    input_type = str(metadata.get("type") or "").lower()
    if input_type == "password":
        return True

    parts = [
        metadata.get("name"),
        metadata.get("id"),
        metadata.get("placeholder"),
        metadata.get("aria"),
        metadata.get("aria-label"),
        metadata.get("label"),
        metadata.get("autocomplete"),
    ]
    return looks_sensitive(" ".join(str(part or "") for part in parts))


def safe_element_name(metadata: dict[str, Any], limit: int = 160) -> str:
    tag = str(metadata.get("tag") or "").lower()
    if tag in {"input", "textarea"} and is_sensitive_metadata(metadata):
        return "<sensitive input masked>"

    for key in ("innerText", "text", "placeholder", "aria", "aria-label", "name", "label"):
        value = str(metadata.get(key) or "").strip()
        if value:
            return mask_sensitive(value, limit)[:limit]

    # Avoid exposing typed form values in element lists. Values are not labels.
    return ""


def sanitize_filename(name: str, default: str = "download.bin") -> str:
    safe = PathLikeName.clean(name or default)
    return safe[:120] or default


class PathLikeName:
    @staticmethod
    def clean(name: str) -> str:
        return re.sub(r'[\\/:*?"<>|]+', "_", str(name)).strip().strip(".")
