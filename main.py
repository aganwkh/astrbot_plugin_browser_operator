import asyncio
import base64
import json
import mimetypes
import re
import time
from pathlib import Path
from datetime import datetime
from typing import Any, Optional

try:
    from astrbot.api import AstrBotConfig
except Exception:
    AstrBotConfig = Any

from astrbot.api.star import Context, Star, register
from astrbot.api.event import filter, AstrMessageEvent
import astrbot.api.message_components as Comp

try:
    from .redact import is_sensitive_metadata, mask_sensitive, sanitize_filename
    from .security import validate_url
    from .settings import BrowserRuntimeConfig, build_runtime_config
except Exception:
    from redact import is_sensitive_metadata, mask_sensitive, sanitize_filename
    from security import validate_url
    from settings import BrowserRuntimeConfig, build_runtime_config

# 默认路径仅作为配置缺省值；运行时可由 _conf_schema.json 覆盖。
DATA_DIR = Path("/opt/AstrBot/data")
TEMP_DIR = DATA_DIR / "temp"


def _mask_sensitive(value: Any, limit: int = 4000) -> str:
    return mask_sensitive(value, limit)


def _safe_json(obj: Any, limit: int = 8000) -> str:
    return _mask_sensitive(json.dumps(obj, ensure_ascii=False, indent=2), limit=limit)


def _now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]


def _is_path_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except Exception:
        return False


class BrowserController:
    """持久化浏览器控制器。默认复用同一个 context/page，多步操作不会自动刷新页面。"""

    def __init__(self):
        self.playwright = None
        self.context = None
        self.page = None
        self.active_profile_key: Optional[str] = None
        self.active_profile_dir: Optional[Path] = None
        self.active_runtime: Optional[BrowserRuntimeConfig] = None
        self._init_lock = asyncio.Lock()
        self._op_lock = asyncio.Lock()
        self.dialog_behavior = "dismiss"  # dismiss / accept / ignore
        self.console_messages: list[str] = []
        self.request_failures: list[str] = []

    async def ensure_page(self, runtime: BrowserRuntimeConfig):
        async with self._init_lock:
            if self.playwright is None:
                from playwright.async_api import async_playwright
                self.playwright = await async_playwright().start()

            if self.context is not None and self.active_profile_key != runtime.profile_key:
                await self._close_context()

            runtime.temp_dir.mkdir(parents=True, exist_ok=True)
            runtime.profile_dir.mkdir(parents=True, exist_ok=True)

            if self.context is None:
                launch_kwargs = dict(
                    user_data_dir=str(runtime.profile_dir),
                    headless=runtime.headless,
                    args=["--no-sandbox"],
                    viewport={"width": runtime.viewport_width, "height": runtime.viewport_height},
                    accept_downloads=True,
                )
                if runtime.chrome_path:
                    launch_kwargs["executable_path"] = runtime.chrome_path
                if runtime.use_proxy and runtime.proxy_server:
                    launch_kwargs["proxy"] = {"server": runtime.proxy_server}

                self.context = await self.playwright.chromium.launch_persistent_context(**launch_kwargs)
                self.context.on("page", lambda p: asyncio.create_task(self._prepare_page(p, runtime)))
                self.active_profile_key = runtime.profile_key
                self.active_profile_dir = runtime.profile_dir
                self.active_runtime = runtime

            if self.page is not None:
                try:
                    if self.page.is_closed():
                        self.page = None
                except Exception:
                    self.page = None

            if self.page is None:
                try:
                    pages = [p for p in self.context.pages if not p.is_closed()]
                except Exception:
                    pages = []
                self.page = pages[0] if pages else await self.context.new_page()
                await self._prepare_page(self.page, runtime)

            return self.page

    async def _prepare_page(self, page, runtime: BrowserRuntimeConfig):
        try:
            page.set_default_timeout(runtime.default_timeout_ms)
            page.on("dialog", lambda dialog: asyncio.create_task(self._handle_dialog(dialog)))
            page.on("console", lambda msg: self._append_console(msg))
            page.on("requestfailed", lambda req: self._append_request_failed(req))
        except Exception:
            pass

    def _append_console(self, msg):
        try:
            self.console_messages.append(f"{msg.type}: {_mask_sensitive(msg.text, 300)}")
            self.console_messages = self.console_messages[-50:]
        except Exception:
            pass

    def _append_request_failed(self, req):
        try:
            self.request_failures.append(f"{req.method} {_mask_sensitive(req.url, 300)}")
            self.request_failures = self.request_failures[-50:]
        except Exception:
            pass

    async def _handle_dialog(self, dialog):
        try:
            if self.dialog_behavior == "accept":
                await dialog.accept()
            elif self.dialog_behavior == "ignore":
                return
            else:
                await dialog.dismiss()
        except Exception:
            pass

    def pages(self):
        try:
            return [p for p in self.context.pages if not p.is_closed()] if self.context else []
        except Exception:
            return []

    def set_page(self, page):
        self.page = page

    async def error_screenshot(self, page, prefix: str = "browser_error", temp_dir: Optional[Path] = None) -> Optional[Path]:
        try:
            temp_dir = temp_dir or TEMP_DIR
            temp_dir.mkdir(parents=True, exist_ok=True)
            path = temp_dir / f"{prefix}_{_now_stamp()}.png"
            await page.screenshot(path=str(path), full_page=True)
            return path
        except Exception:
            return None

    async def _close_context(self):
        if self.context:
            try:
                await self.context.close()
            except Exception:
                pass
        self.context = None
        self.page = None
        self.active_profile_key = None
        self.active_profile_dir = None
        self.active_runtime = None
        self.console_messages = []
        self.request_failures = []

    async def close(self):
        async with self._init_lock:
            await self._close_context()
            if self.playwright:
                try:
                    await self.playwright.stop()
                except Exception:
                    pass
                self.playwright = None


_browser_controller = BrowserController()

BROWSER_BYPASS_PATTERNS = [
    r"\bfrom\s+playwright\b",
    r"\bimport\s+playwright\b",
    r"\basync_playwright\s*\(",
    r"\bsync_playwright\s*\(",
    r"\.chromium\.launch\s*\(",
    r"launch_persistent_context\s*\(",
    r"playwright\s+install\s+chromium",
    r"/root/\.cache/ms-playwright",
    r"\bfrom\s+selenium\b",
    r"webdriver\.Chrome\s*\(",
    r"chromium-browser.*--no-sandbox",
]

BROWSER_BYPASS_BLOCK_MESSAGE = (
    "检测到本次回复正在直接编写 Playwright / Chromium / Selenium 浏览器自动化代码，"
    "已由 browser-operator 插件拦截。\n\n"
    "正确做法：调用已注册的 browser_* 工具完成网页操作。不要在回复中手写 "
    "p.chromium.launch / sync_playwright / async_playwright / Selenium 代码。"
)


def _component_to_text(comp) -> str:
    for attr in ("text", "content", "message"):
        val = getattr(comp, attr, None)
        if isinstance(val, str):
            return val
    return ""


def _contains_browser_bypass(text: str) -> bool:
    if not text:
        return False
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in BROWSER_BYPASS_PATTERNS)


async def _click_like(page, selector: str) -> str:
    errors = []
    attempts = [
        ("role-button", lambda: page.get_by_role("button", name=selector).click(timeout=5000)),
        ("role-link", lambda: page.get_by_role("link", name=selector).click(timeout=5000)),
        ("text-exact", lambda: page.get_by_text(selector, exact=True).click(timeout=5000)),
        ("text-fuzzy", lambda: page.get_by_text(selector).first.click(timeout=5000)),
        ("css", lambda: page.locator(selector).first.click(timeout=5000)),
    ]
    for name, action in attempts:
        try:
            await action()
            return name
        except Exception as e:
            errors.append(f"{name}: {str(e)[:120]}")
    raise Exception("; ".join(errors))


async def _locator_sensitive(locator) -> bool:
    try:
        metadata = {
            "type": await locator.get_attribute("type"),
            "name": await locator.get_attribute("name"),
            "id": await locator.get_attribute("id"),
            "placeholder": await locator.get_attribute("placeholder"),
            "aria": await locator.get_attribute("aria-label"),
            "autocomplete": await locator.get_attribute("autocomplete"),
        }
        return is_sensitive_metadata(metadata)
    except Exception:
        # If we cannot inspect a field, prefer not to screenshot after typing.
        return True


async def _fill_like(page, selector: str, text: str, clear: bool = True) -> tuple[str, bool]:
    errors = []
    locators = [
        ("placeholder", lambda: page.get_by_placeholder(selector).first),
        ("label", lambda: page.get_by_label(selector).first),
        ("css", lambda: page.locator(selector).first),
    ]
    for name, factory in locators:
        try:
            loc = factory()
            sensitive = await _locator_sensitive(loc)
            if clear:
                await loc.fill(text, timeout=5000)
            else:
                await loc.type(text, timeout=5000)
            return name, sensitive
        except Exception as e:
            errors.append(f"{name}: {str(e)[:120]}")
    raise Exception("; ".join(errors))


@register("astrbot_plugin_browser_operator", "虾仁 & 爱音", "Browser Operator 插件", "0.3.0")
class BrowserOperatorPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig = None):
        super().__init__(context)
        self.config = config or {}
        self.last_screenshot_path: Optional[str] = None
        self.last_observation: str = ""
        self.last_observe_at: float = 0.0
        self.sensitive_profiles: set[str] = set()

    def _cfg(self, key: str, default=None):
        try:
            return self.config.get(key, default)
        except Exception:
            return default

    def _runtime(self, event: AstrMessageEvent) -> BrowserRuntimeConfig:
        return build_runtime_config(self.config, event)

    def _permission_error(self, event: AstrMessageEvent, runtime: Optional[BrowserRuntimeConfig] = None) -> str:
        runtime = runtime or self._runtime(event)
        try:
            sender_id = str(event.get_sender_id())
        except Exception:
            sender_id = ""
        try:
            session_id = str(event.get_session_id())
        except Exception:
            session_id = ""

        if runtime.allowed_users and sender_id not in runtime.allowed_users:
            return "错误：当前用户无权限使用浏览器工具"
        if runtime.allowed_sessions and session_id not in runtime.allowed_sessions:
            return "错误：当前会话无权限使用浏览器工具"
        return ""

    async def _ensure_page(self, event: AstrMessageEvent):
        runtime = self._runtime(event)
        permission_error = self._permission_error(event, runtime)
        if permission_error:
            raise PermissionError(permission_error)
        return await _browser_controller.ensure_page(runtime)

    def _temp_dir(self, event: AstrMessageEvent) -> Path:
        temp_dir = self._runtime(event).temp_dir
        temp_dir.mkdir(parents=True, exist_ok=True)
        return temp_dir

    def _profile_key(self, event: AstrMessageEvent) -> str:
        return self._runtime(event).profile_key

    def _mark_sensitive(self, event: AstrMessageEvent) -> None:
        self.sensitive_profiles.add(self._profile_key(event))

    def _clear_sensitive(self, event: AstrMessageEvent) -> None:
        self.sensitive_profiles.discard(self._profile_key(event))

    def _sensitive_block_message(self, event: AstrMessageEvent) -> str:
        runtime = self._runtime(event)
        if runtime.block_screenshots_in_sensitive_mode and runtime.profile_key in self.sensitive_profiles:
            return "当前会话处于敏感输入保护模式，已跳过截图/视觉观察。打开新页面或刷新后会自动解除。"
        return ""

    async def _safe_error_screenshot(self, event: AstrMessageEvent, prefix: str) -> Optional[Path]:
        try:
            return await _browser_controller.error_screenshot(
                await self._ensure_page(event),
                prefix,
                self._temp_dir(event),
            )
        except Exception:
            return None

    def _vision_actions(self) -> set[str]:
        raw = self._cfg(
            "vision_trigger_actions",
            "open,click,press,select,check,reload,back,forward,hover,scroll,scroll_to,click_at,download,upload,new_page,switch_page,frame_click,viewport",
        )
        if isinstance(raw, list):
            return {str(x).strip() for x in raw if str(x).strip()}
        return {x.strip() for x in str(raw).split(",") if x.strip()}

    def _vision_enabled_for_action(self, action: str) -> bool:
        if not bool(self._cfg("vision_enabled", True)):
            return False
        if not bool(self._cfg("vision_auto_observe", True)):
            return False
        return action in self._vision_actions()

    async def _capture_view(
        self,
        page,
        prefix: str = "browser_observe",
        full_page: Optional[bool] = None,
        temp_dir: Optional[Path] = None,
    ) -> Optional[Path]:
        try:
            temp_dir = temp_dir or TEMP_DIR
            temp_dir.mkdir(parents=True, exist_ok=True)
            if full_page is None:
                full_page = bool(self._cfg("vision_full_page", False))
            path = temp_dir / f"{prefix}_{_now_stamp()}.png"
            try:
                await page.screenshot(path=str(path), full_page=bool(full_page))
            except Exception:
                path = temp_dir / f"{prefix}_viewport_{_now_stamp()}.png"
                await page.screenshot(path=str(path), full_page=False)
            self.last_screenshot_path = str(path)
            return path
        except Exception:
            return None

    async def _page_text_preview(self, page, limit: int = 800) -> str:
        if not bool(self._cfg("vision_include_visible_text", True)):
            return ""
        try:
            return _mask_sensitive((await page.inner_text("body"))[:limit], limit)
        except Exception:
            return ""

    async def _call_vision_provider(self, event: AstrMessageEvent, image_path: Path, prompt: str) -> str:
        provider_id = str(self._cfg("vision_provider", "") or "").strip()
        if not provider_id:
            return ""
        try:
            from astrbot.core.agent.message import TextPart, ImageURLPart, UserMessageSegment

            mime = mimetypes.guess_type(str(image_path))[0] or "image/png"
            data_uri = f"data:{mime};base64," + base64.b64encode(image_path.read_bytes()).decode("ascii")
            content = [
                TextPart(text=prompt),
                ImageURLPart(image_url=ImageURLPart.ImageURL(url=data_uri, id=f"browser_observe_{_now_stamp()}")),
            ]
            resp = await self.context.llm_generate(
                chat_provider_id=provider_id,
                contexts=[UserMessageSegment(content=content)],
            )
            text = getattr(resp, "completion_text", None) or str(resp)
            text = _mask_sensitive(text, int(self._cfg("vision_max_chars", 1500) or 1500))
            self.last_observation = text
            return text
        except Exception as e:
            return f"视觉模型调用失败：{_mask_sensitive(str(e), 800)}"

    async def _observe_after_action(self, event: AstrMessageEvent, action: str, page=None) -> str:
        if not self._vision_enabled_for_action(action):
            return ""
        sensitive_block = self._sensitive_block_message(event)
        if sensitive_block:
            return "\n\n[浏览器观察已跳过]\n" + sensitive_block
        try:
            min_interval = float(self._cfg("vision_min_interval_seconds", 0.5) or 0)
        except Exception:
            min_interval = 0.5
        now = time.time()
        if min_interval > 0 and now - self.last_observe_at < min_interval:
            return ""
        self.last_observe_at = now
        try:
            if page is None:
                page = await self._ensure_page(event)
            # 等待页面加载完成
            if bool(self._cfg("vision_wait_for_load", True)):
                try:
                    wait_timeout = float(self._cfg("vision_wait_timeout", 5) or 5) * 1000
                    await page.wait_for_load_state("domcontentloaded", timeout=wait_timeout)
                    await page.wait_for_timeout(500)
                except Exception:
                    pass
            shot = await self._capture_view(page, f"browser_observe_{action}", temp_dir=self._temp_dir(event))
            if not shot:
                return "\n\n[浏览器观察]\n截图失败。"
            title = _mask_sensitive(await page.title(), 300)
            url = _mask_sensitive(page.url, 500)
            preview = await self._page_text_preview(page)
            prompt = str(self._cfg("vision_prompt", "") or "").strip() or (
                "请分析这张网页截图。输出必须简短，包含：当前页面状态、是否完成刚才操作、"
                "可见按钮/输入框/报错/验证码/风控提示、下一步建议。"
            )
            prompt = (
                f"{prompt}\n\n"
                f"刚才执行的浏览器操作：{action}\n"
                f"页面标题：{title}\n"
                f"页面 URL：{url}\n"
                f"可见文本预览：{preview}\n"
            )
            vision_text = await self._call_vision_provider(event, shot, prompt)
            lines = ["", "[浏览器观察]", f"截图：{shot}", f"标题：{title}", f"URL：{url}"]
            if vision_text:
                lines.append("视觉分析：" + vision_text)
            elif preview:
                lines.append("可见文本预览：" + preview[:800])
            else:
                lines.append("未配置多模态模型提供商，仅保存截图。")
            return "\n" + "\n".join(lines)
        except Exception as e:
            return f"\n\n[浏览器观察失败] {_mask_sensitive(str(e), 800)}"

    async def _with_observation(self, event: AstrMessageEvent, action: str, message: str, page=None) -> str:
        return message + await self._observe_after_action(event, action, page)

    async def _observe_now(self, event: AstrMessageEvent, action: str = "manual", full_page: Optional[bool] = None) -> str:
        sensitive_block = self._sensitive_block_message(event)
        if sensitive_block:
            return sensitive_block
        page = await self._ensure_page(event)
        shot = await self._capture_view(page, f"browser_observe_{action}", full_page=full_page, temp_dir=self._temp_dir(event))
        if not shot:
            return "截图失败"
        title = _mask_sensitive(await page.title(), 300)
        url = _mask_sensitive(page.url, 500)
        preview = await self._page_text_preview(page)
        prompt = str(self._cfg("vision_prompt", "") or "").strip() or (
            "请分析这张网页截图，判断当前页面状态、可见按钮、输入框、是否成功跳转、"
            "是否有报错、是否有验证码/风控提示，并给出下一步建议。"
        )
        prompt = f"{prompt}\n\n页面标题：{title}\n页面 URL：{url}\n可见文本预览：{preview}\n"
        vision_text = await self._call_vision_provider(event, shot, prompt)
        data = {
            "title": title,
            "url": url,
            "screenshot_path": str(shot),
            "observation": vision_text or "未配置 vision_provider，未调用多模态模型。",
            "visible_text_preview": preview,
        }
        return _safe_json(data, 8000)

    @filter.on_decorating_result(priority=100)
    async def block_direct_browser_code(self, event: AstrMessageEvent):
        """不做每轮注入；只在最终回复出现直接浏览器自动化代码时熔断。"""
        try:
            result = event.get_result()
            chain = getattr(result, "chain", None)
            if not chain:
                return
            text = "\n".join(_component_to_text(comp) for comp in chain)
            if not _contains_browser_bypass(text):
                return
            chain.clear()
            chain.append(Comp.Plain(BROWSER_BYPASS_BLOCK_MESSAGE))
        except Exception:
            return

    @filter.llm_tool(name="browser_open")
    async def browser_open(self, event: AstrMessageEvent, url: str):
        '''打开网页。不会刷新旧页面，而是在当前持久页面中跳转到指定 URL。必须是 http:// 或 https:// 开头的网址。

        Args:
            url(string): 要打开的网页地址
        '''
        runtime = self._runtime(event)
        permission_error = self._permission_error(event, runtime)
        if permission_error:
            return permission_error
        try:
            url = validate_url(
                url,
                allow_private_network=runtime.allow_private_network,
                allowed_domains=runtime.allowed_domains,
                blocked_domains=runtime.blocked_domains,
            )
        except Exception as e:
            return f"错误：{_mask_sensitive(str(e), 500)}"
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                await page.goto(url, timeout=60000, wait_until="domcontentloaded")
                await page.wait_for_timeout(1500)
                self._clear_sensitive(event)
                msg = f"已打开网页\n标题：{_mask_sensitive(await page.title(), 300)}\nURL：{_mask_sensitive(page.url, 500)}\n\n[提醒] 页面未自动刷新；后续 click/type/scroll 都会继续操作当前页面。"
                return await self._with_observation(event, "open", msg, page)
            except Exception as e:
                try:
                    shot = await self._safe_error_screenshot(event, "open_error")
                    return f"打开网页失败：{_mask_sensitive(str(e), 800)}\n错误截图：{shot}"
                except Exception:
                    return f"打开网页失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_observe")
    async def browser_observe(self, event: AstrMessageEvent, full_page: bool = False):
        '''对当前页面截图，并调用配置的多模态模型分析页面状态。不会刷新页面。

        Args:
            full_page(boolean): 是否整页截图，默认 false，仅截当前视口
        '''
        async with _browser_controller._op_lock:
            try:
                return await self._observe_now(event, "manual", full_page=bool(full_page))
            except Exception as e:
                return f"观察失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_last_observation")
    async def browser_last_observation(self, event: AstrMessageEvent):
        '''返回上一次浏览器视觉观察结果和截图路径。不会刷新页面。'''
        data = {
            "last_screenshot_path": self.last_screenshot_path,
            "last_observation": self.last_observation,
        }
        return _safe_json(data, 5000)

    @filter.llm_tool(name="browser_text")
    async def browser_text(self, event: AstrMessageEvent, max_chars: int = 4000):
        '''读取当前网页正文。不会刷新页面。

        Args:
            max_chars(number): 最大返回字符数，默认4000，最大12000
        '''
        max_chars = max(200, min(int(max_chars), 12000))
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                text = await page.inner_text("body")
                return _mask_sensitive(text, max_chars)
            except Exception as e:
                return f"读取网页内容失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_html")
    async def browser_html(self, event: AstrMessageEvent, max_chars: int = 8000):
        '''读取当前页面 HTML。用于定位元素或诊断。不会刷新页面。

        Args:
            max_chars(number): 最大返回字符数，默认8000，最大20000
        '''
        max_chars = max(500, min(int(max_chars), 20000))
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                html = await page.content()
                return _mask_sensitive(html, max_chars)
            except Exception as e:
                return f"读取HTML失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_state")
    async def browser_state(self, event: AstrMessageEvent):
        '''获取当前页面状态：标题、URL、正文预览、页面数量。不会刷新页面。'''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                pages = _browser_controller.pages()
                preview = ""
                try:
                    preview = await page.inner_text("body")
                except Exception:
                    pass
                data = {
                    "title": await page.title(),
                    "url": page.url,
                    "page_count": len(pages),
                    "active_page_index": pages.index(page) if page in pages else -1,
                    "text_preview": preview[:1500],
                    "last_screenshot_path": self.last_screenshot_path,
                    "last_observation": self.last_observation[:1000],
                }
                return _safe_json(data, 6000)
            except Exception as e:
                return f"获取页面状态失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_click")
    async def browser_click(self, event: AstrMessageEvent, selector: str):
        '''点击当前页面元素。优先按按钮名/文本点击，失败后按 CSS 选择器点击。不会刷新页面，除非网站点击后自己跳转。

        Args:
            selector(string): CSS选择器或文本内容，例如 "登录"、"button.submit"、"#login-btn"
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                method = await _click_like(page, selector)
                await page.wait_for_timeout(1000)
                msg = f"点击成功（定位方式：{method}）\n当前标题：{_mask_sensitive(await page.title(), 300)}\n当前URL：{_mask_sensitive(page.url, 500)}"
                return await self._with_observation(event, "click", msg, page)
            except Exception as e:
                shot = await self._safe_error_screenshot(event, "click_error")
                return f"点击失败：{_mask_sensitive(str(e), 1000)}\n错误截图：{shot}\n提示：可先用 browser_list_elements 或 browser_dump_near_text 排查选择器。"

    @filter.llm_tool(name="browser_click_role")
    async def browser_click_role(self, event: AstrMessageEvent, role: str, name: str):
        '''按可访问性 role 和 name 点击元素。不会刷新页面，除非网站点击后自己跳转。

        Args:
            role(string): 元素角色，例如 button、link、textbox、checkbox
            name(string): 元素可见名称
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                await page.get_by_role(role, name=name).click(timeout=10000)
                await page.wait_for_timeout(1000)
                msg = f"点击成功\n当前URL：{_mask_sensitive(page.url, 500)}"
                return await self._with_observation(event, "click", msg, page)
            except Exception as e:
                shot = await self._safe_error_screenshot(event, "click_role_error")
                return f"点击失败：{_mask_sensitive(str(e), 1000)}\n错误截图：{shot}"

    @filter.llm_tool(name="browser_type")
    async def browser_type(self, event: AstrMessageEvent, selector: str, text: str, clear: bool = True):
        '''在当前页面输入框中输入文字。不会刷新页面。敏感字段输入后会跳过截图和自动观察。

        Args:
            selector(string): 输入框 CSS 选择器、label 或 placeholder 文本
            text(string): 要输入的文字内容
            clear(boolean): 是否先清空原内容，默认true
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                method, sensitive = await _fill_like(page, selector, text, bool(clear))
                msg = f"已输入文字（定位方式：{method}，长度 {len(text)}）"
                if sensitive:
                    self._mark_sensitive(event)
                    return msg + "\n检测到敏感字段，已跳过截图和自动观察。"
                return await self._with_observation(event, "type", msg, page)
            except Exception as e:
                shot = await self._safe_error_screenshot(event, "type_error")
                return f"输入失败：{_mask_sensitive(str(e), 1000)}\n错误截图：{shot}"

    @filter.llm_tool(name="browser_press")
    async def browser_press(self, event: AstrMessageEvent, key: str):
        '''按键盘按键，例如 Enter、Escape、Tab、Control+A。不会刷新页面，除非网站响应按键触发跳转。

        Args:
            key(string): 按键名称
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                await page.keyboard.press(key)
                await page.wait_for_timeout(700)
                msg = f"已按键：{key}\n当前URL：{_mask_sensitive(page.url, 500)}"
                return await self._with_observation(event, "press", msg, page)
            except Exception as e:
                return f"按键失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_select")
    async def browser_select(self, event: AstrMessageEvent, selector: str, value: str):
        '''选择 select 下拉框选项。不会刷新页面，除非网站响应选择触发跳转。

        Args:
            selector(string): select 元素 CSS 选择器
            value(string): option 的 value
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                result = await page.locator(selector).first.select_option(value)
                msg = f"已选择：{result}"
                return await self._with_observation(event, "select", msg, page)
            except Exception as e:
                return f"选择失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_check")
    async def browser_check(self, event: AstrMessageEvent, selector: str, checked: bool = True):
        '''勾选或取消 checkbox/radio。不会刷新页面。

        Args:
            selector(string): checkbox/radio 的 CSS 选择器或 label 文本
            checked(boolean): true 为勾选，false 为取消
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                try:
                    loc = page.get_by_label(selector).first
                    if checked:
                        await loc.check(timeout=5000)
                    else:
                        await loc.uncheck(timeout=5000)
                except Exception:
                    loc = page.locator(selector).first
                    if checked:
                        await loc.check(timeout=5000)
                    else:
                        await loc.uncheck(timeout=5000)
                msg = "已勾选" if checked else "已取消勾选"
                return await self._with_observation(event, "check", msg, page)
            except Exception as e:
                return f"勾选操作失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_screenshot")
    async def browser_screenshot(self, event: AstrMessageEvent, full_page: bool = True):
        '''对当前网页截图。不会刷新页面。只保存截图，不调用视觉模型；需要视觉分析请用 browser_observe。

        Args:
            full_page(boolean): 是否截取整个页面，默认true
        '''
        sensitive_block = self._sensitive_block_message(event)
        if sensitive_block:
            return sensitive_block
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                temp_dir = self._temp_dir(event)
                path = temp_dir / f"browser_screenshot_{_now_stamp()}.png"
                try:
                    await page.screenshot(path=str(path), full_page=bool(full_page))
                except Exception:
                    path = temp_dir / f"browser_viewport_{_now_stamp()}.png"
                    await page.screenshot(path=str(path), full_page=False)
                self.last_screenshot_path = str(path)
                return f"截图已保存到：{path}"
            except Exception as e:
                return f"截图失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_url")
    async def browser_url(self, event: AstrMessageEvent):
        '''获取当前页面 URL。不会刷新页面。'''
        try:
            page = await self._ensure_page(event)
            return f"当前URL：{_mask_sensitive(page.url, 500)}"
        except Exception as e:
            return f"获取URL失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_title")
    async def browser_title(self, event: AstrMessageEvent):
        '''获取当前页面标题。不会刷新页面。'''
        try:
            page = await self._ensure_page(event)
            return f"当前标题：{_mask_sensitive(await page.title(), 300)}"
        except Exception as e:
            return f"获取标题失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_reload")
    async def browser_reload(self, event: AstrMessageEvent):
        '''刷新当前网页。只有用户明确要求刷新，或登录态验证需要刷新时才调用。'''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                await page.reload(timeout=60000, wait_until="domcontentloaded")
                await page.wait_for_timeout(1000)
                self._clear_sensitive(event)
                msg = f"已刷新网页\n标题：{_mask_sensitive(await page.title(), 300)}\nURL：{_mask_sensitive(page.url, 500)}"
                return await self._with_observation(event, "reload", msg, page)
            except Exception as e:
                return f"刷新失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_back")
    async def browser_back(self, event: AstrMessageEvent):
        '''返回上一页。不会主动刷新页面。'''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                res = await page.go_back(timeout=60000, wait_until="domcontentloaded")
                await page.wait_for_timeout(1000)
                self._clear_sensitive(event)
                if res is None:
                    return "没有可返回的上一页"
                msg = f"已返回上一页\n标题：{_mask_sensitive(await page.title(), 300)}\nURL：{_mask_sensitive(page.url, 500)}"
                return await self._with_observation(event, "back", msg, page)
            except Exception as e:
                return f"返回失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_forward")
    async def browser_forward(self, event: AstrMessageEvent):
        '''前进到下一页。不会主动刷新页面。'''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                res = await page.go_forward(timeout=60000, wait_until="domcontentloaded")
                await page.wait_for_timeout(1000)
                self._clear_sensitive(event)
                if res is None:
                    return "没有可前进的下一页"
                msg = f"已前进\n标题：{_mask_sensitive(await page.title(), 300)}\nURL：{_mask_sensitive(page.url, 500)}"
                return await self._with_observation(event, "forward", msg, page)
            except Exception as e:
                return f"前进失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_wait")
    async def browser_wait(self, event: AstrMessageEvent, seconds: int = 3):
        '''等待指定秒数。不会刷新页面。

        Args:
            seconds(number): 等待秒数，默认3秒，最大30秒
        '''
        seconds = max(1, min(int(seconds), 30))
        try:
            page = await self._ensure_page(event)
            await page.wait_for_timeout(seconds * 1000)
            return f"已等待 {seconds} 秒"
        except Exception as e:
            return f"等待失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_wait_for")
    async def browser_wait_for(self, event: AstrMessageEvent, selector: str, timeout_seconds: int = 10):
        '''等待元素出现。不会刷新页面。

        Args:
            selector(string): CSS 选择器或文本内容
            timeout_seconds(number): 等待秒数，默认10秒，最大30秒
        '''
        timeout_ms = max(1000, min(int(timeout_seconds), 30) * 1000)
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                try:
                    await page.get_by_text(selector, exact=True).wait_for(timeout=timeout_ms)
                    return f"元素已出现：{selector}"
                except Exception:
                    await page.locator(selector).first.wait_for(timeout=timeout_ms)
                    return f"元素已出现：{selector}"
            except Exception as e:
                return f"等待元素失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_hover")
    async def browser_hover(self, event: AstrMessageEvent, selector: str):
        '''悬停到元素上，用于触发 hover 菜单。不会刷新页面。

        Args:
            selector(string): CSS选择器或文本内容
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                try:
                    await page.get_by_text(selector, exact=True).hover(timeout=5000)
                except Exception:
                    await page.locator(selector).first.hover(timeout=5000)
                await page.wait_for_timeout(1000)
                msg = f"已悬停在：{selector}"
                return await self._with_observation(event, "hover", msg, page)
            except Exception as e:
                return f"悬停失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_scroll")
    async def browser_scroll(self, event: AstrMessageEvent, direction: str = "down", amount: int = 500):
        '''滚动页面。不会刷新页面。

        Args:
            direction(string): 滚动方向，可选 up、down、top、bottom
            amount(number): 滚动像素数，默认500，最大5000，direction为top/bottom时无效
        '''
        amount = max(1, min(int(amount), 5000))
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                if direction == "top":
                    await page.evaluate("window.scrollTo(0, 0)")
                    msg = "已滚动到页面顶部"
                elif direction == "bottom":
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    msg = "已滚动到页面底部"
                elif direction == "down":
                    await page.mouse.wheel(0, amount)
                    msg = f"已向下滚动 {amount} 像素"
                elif direction == "up":
                    await page.mouse.wheel(0, -amount)
                    msg = f"已向上滚动 {amount} 像素"
                else:
                    return "错误：direction 必须是 up、down、top、bottom"
                await page.wait_for_timeout(800)
                return await self._with_observation(event, "scroll", msg, page)
            except Exception as e:
                return f"滚动失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_scroll_to")
    async def browser_scroll_to(self, event: AstrMessageEvent, selector: str):
        '''滚动到指定元素。不会刷新页面。

        Args:
            selector(string): 目标元素的 CSS 选择器或文本内容
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                try:
                    element = page.get_by_text(selector, exact=True).first
                    await element.scroll_into_view_if_needed(timeout=5000)
                except Exception:
                    element = page.locator(selector).first
                    await element.scroll_into_view_if_needed(timeout=5000)
                await page.wait_for_timeout(500)
                msg = f"已滚动到元素：{selector}"
                return await self._with_observation(event, "scroll_to", msg, page)
            except Exception as e:
                return f"滚动到元素失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_find_text")
    async def browser_find_text(self, event: AstrMessageEvent, keyword: str):
        '''在当前页面中查找指定文本。不会刷新页面。

        Args:
            keyword(string): 要查找的关键词
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                js_code = """(keyword) => {
                    const body = document.body.innerText || "";
                    const index = body.indexOf(keyword);
                    if (index === -1) return { found: false, position: -1 };
                    const totalLength = body.length || 1;
                    const percentage = Math.round((index / totalLength) * 100);
                    const start = Math.max(0, index - 120);
                    const end = Math.min(body.length, index + keyword.length + 120);
                    return { found: true, position: index, percentage, context: body.slice(start, end) };
                }"""
                result = await page.evaluate(js_code, keyword)
                if result["found"]:
                    return f"找到文本，位于页面约 {result['percentage']}% 的位置\n上下文：{_mask_sensitive(result.get('context', ''), 800)}"
                return "未找到该文本"
            except Exception as e:
                return f"查找失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_list_elements")
    async def browser_list_elements(self, event: AstrMessageEvent, kind: str = "interactive", limit: int = 50):
        '''列出当前页面可交互元素，辅助选择器定位。不会刷新页面。

        Args:
            kind(string): interactive、buttons、links、inputs 之一
            limit(number): 最大返回数量，默认50，最大100
        '''
        limit = max(1, min(int(limit), 100))
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                js_code = """([kind, limit]) => {
                    const sensitiveRe = /password|passwd|pwd|token|cookie|secret|api[_-]?key|authorization|auth|bearer|验证码|密码|令牌|密钥/i;
                    const isSensitive = (el) => {
                        const inputType = (el.getAttribute('type') || '').toLowerCase();
                        const meta = [
                            el.getAttribute('name'),
                            el.id,
                            el.getAttribute('placeholder'),
                            el.getAttribute('aria-label'),
                            el.getAttribute('autocomplete')
                        ].join(' ');
                        return inputType === 'password' || sensitiveRe.test(meta);
                    };
                    const displayName = (el) => {
                        if (isSensitive(el)) return '<sensitive input masked>';
                        return (el.innerText || el.placeholder || el.getAttribute('aria-label') || el.getAttribute('name') || '').slice(0, 160);
                    };
                    const selectors = {
                        buttons: 'button,[role="button"],input[type="button"],input[type="submit"]',
                        links: 'a[href]',
                        inputs: 'input,textarea,select,[contenteditable="true"]',
                        interactive: 'button,[role="button"],a[href],input,textarea,select,[contenteditable="true"]'
                    };
                    const selector = selectors[kind] || selectors.interactive;
                    return Array.from(document.querySelectorAll(selector)).slice(0, 300).filter(el => {
                        const r = el.getBoundingClientRect();
                        const s = getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                    }).slice(0, limit).map((el, i) => {
                        const r = el.getBoundingClientRect();
                        return {
                            index: i,
                            tag: el.tagName.toLowerCase(),
                            id: el.id || null,
                            className: String(el.className || '').slice(0, 120),
                            role: el.getAttribute('role'),
                            name: displayName(el),
                            href: el.href ? el.href.slice(0, 200) : null,
                            rect: {x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height)}
                        }
                    });
                }"""
                result = await page.evaluate(js_code, [kind, limit])
                return _safe_json(result, 10000)
            except Exception as e:
                return f"列出元素失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_elements_from_point")
    async def browser_elements_from_point(self, event: AstrMessageEvent, x: int, y: int):
        '''查看坐标点上的元素，解决被 div 覆盖或点击无效问题。不会刷新页面。

        Args:
            x(number): X坐标
            y(number): Y坐标
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                js_code = """([x, y]) => {
                    return document.elementsFromPoint(x, y).slice(0, 10).map(el => {
                        const r = el.getBoundingClientRect();
                        return {
                            tag: el.tagName,
                            id: el.id,
                            className: String(el.className || '').slice(0, 120),
                            text: (el.innerText || '').slice(0, 200),
                            role: el.getAttribute("role"),
                            pointerEvents: getComputedStyle(el).pointerEvents,
                            rect: {x:r.x, y:r.y, w:r.width, h:r.height}
                        };
                    });
                }"""
                result = await page.evaluate(js_code, [int(x), int(y)])
                return _safe_json(result, 5000)
            except Exception as e:
                return f"查询失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_dump_near_text")
    async def browser_dump_near_text(self, event: AstrMessageEvent, text: str):
        '''打印某个文字附近的 DOM 父级结构，用于排查元素定位。不会刷新页面。

        Args:
            text(string): 要查找的文字
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                loc = page.get_by_text(text, exact=True).first
                results = []
                for level in range(1, 8):
                    try:
                        js_code = """el => {
                            const r = el.getBoundingClientRect();
                            return {
                                tag: el.tagName,
                                id: el.id,
                                className: String(el.className || '').slice(0, 160),
                                text: (el.innerText || '').slice(0, 500),
                                rect: {x:r.x, y:r.y, w:r.width, h:r.height},
                                html: el.outerHTML.slice(0, 1500)
                            }
                        }"""
                        data = await loc.locator(f"xpath=ancestor::*[{level}]").evaluate(js_code)
                        results.append({"level": level, "data": data})
                    except Exception:
                        break
                return _safe_json(results, 10000)
            except Exception as e:
                return f"查询失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_click_at")
    async def browser_click_at(self, event: AstrMessageEvent, x: int, y: int):
        '''点击当前页面指定坐标。不会刷新页面，除非网站点击后自己跳转。

        Args:
            x(number): X坐标
            y(number): Y坐标
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                await page.mouse.click(int(x), int(y))
                await page.wait_for_timeout(1000)
                msg = f"已点击坐标 ({x}, {y})\n当前标题：{_mask_sensitive(await page.title(), 300)}\n当前URL：{_mask_sensitive(page.url, 500)}"
                return await self._with_observation(event, "click_at", msg, page)
            except Exception as e:
                return f"点击失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_active_element")
    async def browser_active_element(self, event: AstrMessageEvent):
        '''查看当前焦点元素。不会刷新页面。密码框等敏感 value 会被隐藏。'''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                js_code = """() => {
                    const sensitiveRe = /password|passwd|pwd|token|cookie|secret|api[_-]?key|authorization|auth|bearer|验证码|密码|令牌|密钥/i;
                    const el = document.activeElement;
                    if (!el) return null;
                    const r = el.getBoundingClientRect();
                    const type = el.getAttribute('type');
                    const meta = [
                        el.getAttribute('name'),
                        el.id,
                        el.getAttribute('placeholder'),
                        el.getAttribute('aria-label'),
                        el.getAttribute('autocomplete')
                    ].join(' ');
                    const sensitive = type === 'password' || sensitiveRe.test(meta);
                    const formLike = ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName);
                    return {
                        tag: el.tagName,
                        id: el.id,
                        className: String(el.className || '').slice(0, 120),
                        type,
                        value: formLike ? (sensitive ? '<masked>' : '<not returned>') : '',
                        text: String(el.innerText || '').slice(0, 200),
                        placeholder: el.getAttribute("placeholder"),
                        role: el.getAttribute("role"),
                        contenteditable: el.getAttribute("contenteditable"),
                        rect: {x:r.x, y:r.y, w:r.width, h:r.height}
                    };
                }"""
                result = await page.evaluate(js_code)
                return _safe_json(result, 3000)
            except Exception as e:
                return f"查询失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_download_click")
    async def browser_download_click(self, event: AstrMessageEvent, selector: str, filename: str = ""):
        '''点击页面元素并等待下载。下载文件保存到配置的 temp_dir。不会刷新页面，除非网站点击后自己跳转。

        Args:
            selector(string): 下载按钮/链接的文本或 CSS 选择器
            filename(string): 可选，自定义保存文件名；留空使用网站建议文件名
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                async with page.expect_download(timeout=30000) as download_info:
                    await _click_like(page, selector)
                download = await download_info.value
                suggested = download.suggested_filename or f"download_{_now_stamp()}"
                safe_name = sanitize_filename(Path(filename or suggested).name)
                save_path = self._temp_dir(event) / safe_name
                await download.save_as(str(save_path))
                max_bytes = self._runtime(event).max_download_size_mb * 1024 * 1024
                if save_path.exists() and save_path.stat().st_size > max_bytes:
                    save_path.unlink(missing_ok=True)
                    return f"下载文件超过大小限制（{self._runtime(event).max_download_size_mb} MB），已删除。"
                msg = f"下载完成：{save_path}"
                return await self._with_observation(event, "download", msg, page)
            except Exception as e:
                shot = await self._safe_error_screenshot(event, "download_error")
                return f"下载失败：{_mask_sensitive(str(e), 1000)}\n错误截图：{shot}"

    @filter.llm_tool(name="browser_upload")
    async def browser_upload(self, event: AstrMessageEvent, selector: str, file_path: str):
        '''上传文件。只允许上传配置 temp_dir 目录内的文件。不会刷新页面。

        Args:
            selector(string): input[type=file] 的 CSS 选择器
            file_path(string): 要上传的文件路径，必须位于配置 temp_dir
        '''
        async with _browser_controller._op_lock:
            try:
                path = Path(file_path).expanduser().resolve()
                if not path.exists():
                    return f"错误：文件不存在：{path}"
                temp_dir = self._temp_dir(event).resolve()
                if not _is_path_under(path, temp_dir):
                    return f"错误：为避免误上传敏感文件，只允许上传 {temp_dir} 目录内的文件"
                page = await self._ensure_page(event)
                await page.locator(selector).first.set_input_files(str(path))
                msg = f"已上传文件：{path.name}"
                return await self._with_observation(event, "upload", msg, page)
            except Exception as e:
                return f"上传失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_click_open_new_page")
    async def browser_click_open_new_page(self, event: AstrMessageEvent, selector: str):
        '''点击会打开新标签页/新窗口的元素，并切换当前活动页到新页面。不会刷新旧页面。

        Args:
            selector(string): 链接/按钮文本或 CSS 选择器
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                context = _browser_controller.context
                if len(_browser_controller.pages()) >= self._runtime(event).max_pages:
                    return f"错误：页面数量已达到上限 {self._runtime(event).max_pages}"
                async with context.expect_page(timeout=30000) as page_info:
                    await _click_like(page, selector)
                new_page = await page_info.value
                await _browser_controller._prepare_page(new_page, self._runtime(event))
                await new_page.wait_for_load_state("domcontentloaded", timeout=30000)
                await new_page.wait_for_timeout(1000)
                _browser_controller.set_page(new_page)
                msg = f"已打开并切换到新页面\n标题：{_mask_sensitive(await new_page.title(), 300)}\nURL：{_mask_sensitive(new_page.url, 500)}"
                return await self._with_observation(event, "new_page", msg, new_page)
            except Exception as e:
                return f"打开新页面失败：{_mask_sensitive(str(e), 1000)}"

    @filter.llm_tool(name="browser_pages")
    async def browser_pages(self, event: AstrMessageEvent):
        '''列出当前浏览器中的所有页面/标签页。不会刷新页面。'''
        async with _browser_controller._op_lock:
            try:
                await self._ensure_page(event)
                pages = _browser_controller.pages()
                result = []
                for i, p in enumerate(pages):
                    result.append({"index": i, "active": p == _browser_controller.page, "title": await p.title(), "url": p.url})
                return _safe_json(result, 6000)
            except Exception as e:
                return f"列出页面失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_switch_page")
    async def browser_switch_page(self, event: AstrMessageEvent, index: int):
        '''切换到指定标签页。不会刷新页面。

        Args:
            index(number): browser_pages 返回的页面序号
        '''
        async with _browser_controller._op_lock:
            try:
                await self._ensure_page(event)
                pages = _browser_controller.pages()
                idx = int(index)
                if idx < 0 or idx >= len(pages):
                    return f"错误：页面序号超出范围，当前共有 {len(pages)} 个页面"
                _browser_controller.set_page(pages[idx])
                msg = f"已切换到页面 {idx}\n标题：{_mask_sensitive(await pages[idx].title(), 300)}\nURL：{_mask_sensitive(pages[idx].url, 500)}"
                return await self._with_observation(event, "switch_page", msg, pages[idx])
            except Exception as e:
                return f"切换页面失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_close_current_page")
    async def browser_close_current_page(self, event: AstrMessageEvent):
        '''关闭当前标签页。如果只剩一个页面，则不关闭浏览器。不会刷新页面。'''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                pages = _browser_controller.pages()
                if len(pages) <= 1:
                    return "当前只有一个页面，未关闭；如需释放资源请调用 browser_close"
                await page.close()
                remaining = _browser_controller.pages()
                _browser_controller.set_page(remaining[0] if remaining else None)
                msg = f"已关闭当前页面，剩余 {len(remaining)} 个页面"
                if _browser_controller.page:
                    return await self._with_observation(event, "switch_page", msg, _browser_controller.page)
                return msg
            except Exception as e:
                return f"关闭当前页面失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_frame_text")
    async def browser_frame_text(self, event: AstrMessageEvent, frame_selector: str, max_chars: int = 4000):
        '''读取 iframe 内文本。不会刷新页面。

        Args:
            frame_selector(string): iframe 的 CSS 选择器，例如 iframe、iframe[name='xxx']
            max_chars(number): 最大返回字符数，默认4000
        '''
        max_chars = max(200, min(int(max_chars), 12000))
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                text = await page.frame_locator(frame_selector).locator("body").inner_text(timeout=10000)
                return _mask_sensitive(text, max_chars)
            except Exception as e:
                return f"读取 iframe 失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_click_in_frame")
    async def browser_click_in_frame(self, event: AstrMessageEvent, frame_selector: str, selector: str):
        '''点击 iframe 内元素。不会刷新页面，除非网站点击后自己跳转。

        Args:
            frame_selector(string): iframe 的 CSS 选择器
            selector(string): iframe 内元素的文本或 CSS 选择器
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                frame = page.frame_locator(frame_selector)
                try:
                    await frame.get_by_text(selector, exact=True).click(timeout=5000)
                except Exception:
                    await frame.locator(selector).first.click(timeout=5000)
                await page.wait_for_timeout(1000)
                msg = "iframe 内点击成功"
                return await self._with_observation(event, "frame_click", msg, page)
            except Exception as e:
                return f"iframe 内点击失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_type_in_frame")
    async def browser_type_in_frame(self, event: AstrMessageEvent, frame_selector: str, selector: str, text: str, clear: bool = True):
        '''在 iframe 内输入文字。不会刷新页面。

        Args:
            frame_selector(string): iframe 的 CSS 选择器
            selector(string): iframe 内输入框的 CSS 选择器、label 或 placeholder
            text(string): 要输入的文字
            clear(boolean): 是否先清空原内容，默认true
        '''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                frame = page.frame_locator(frame_selector)
                loc = frame.locator(selector).first
                sensitive = await _locator_sensitive(loc)
                if clear:
                    await loc.fill(text, timeout=5000)
                else:
                    await loc.type(text, timeout=5000)
                msg = f"iframe 内输入成功（长度 {len(text)}）"
                if sensitive:
                    self._mark_sensitive(event)
                    return msg + "\n检测到敏感字段，已跳过截图和自动观察。"
                return await self._with_observation(event, "frame_type", msg, page)
            except Exception as e:
                return f"iframe 内输入失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_dialog_mode")
    async def browser_dialog_mode(self, event: AstrMessageEvent, mode: str = "dismiss"):
        '''设置 alert/confirm/prompt 弹窗处理方式。不会刷新页面。

        Args:
            mode(string): dismiss、accept、ignore 之一；默认 dismiss
        '''
        if mode not in ("dismiss", "accept", "ignore"):
            return "错误：mode 必须是 dismiss、accept、ignore"
        _browser_controller.dialog_behavior = mode
        return f"弹窗处理方式已设置为：{mode}"

    @filter.llm_tool(name="browser_set_viewport")
    async def browser_set_viewport(self, event: AstrMessageEvent, width: int = 1280, height: int = 800):
        '''设置当前页面视口大小。不会刷新页面。

        Args:
            width(number): 宽度，默认1280
            height(number): 高度，默认800
        '''
        width = max(240, min(int(width), 3840))
        height = max(240, min(int(height), 5000))
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                await page.set_viewport_size({"width": width, "height": height})
                msg = f"视口已设置为 {width}x{height}"
                return await self._with_observation(event, "viewport", msg, page)
            except Exception as e:
                return f"设置视口失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_mobile_view")
    async def browser_mobile_view(self, event: AstrMessageEvent, width: int = 430, height: int = 932):
        '''设置移动端尺寸视口。注意：只改 viewport，不重建 context，也不会刷新页面。

        Args:
            width(number): 移动端宽度，默认430
            height(number): 移动端高度，默认932
        '''
        return await self.browser_set_viewport(event, width, height)

    @filter.llm_tool(name="browser_diagnostic")
    async def browser_diagnostic(self, event: AstrMessageEvent):
        '''保存当前页面诊断报告，包括 title、URL、console、request failed、正文预览。不会刷新页面。'''
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                report = []
                report.append(f"Title: {_mask_sensitive(await page.title(), 300)}")
                report.append(f"URL: {_mask_sensitive(page.url, 500)}")
                try:
                    body = await page.inner_text("body")
                    report.append("\nBody preview:\n" + _mask_sensitive(body, 3000))
                except Exception:
                    pass
                report.append("\nConsole messages:")
                report.extend(_browser_controller.console_messages[-20:])
                report.append("\nRequest failures:")
                report.extend(_browser_controller.request_failures[-20:])
                if self.last_screenshot_path:
                    report.append(f"\nLast screenshot: {self.last_screenshot_path}")
                if self.last_observation:
                    report.append("\nLast observation:\n" + self.last_observation[:2000])
                runtime = self._runtime(event)
                report.append(f"\nProfile key: {runtime.profile_key}")
                report.append(f"Profile dir: {runtime.profile_dir}")
                report.append(f"Private network allowed: {runtime.allow_private_network}")
                report.append(f"Sensitive mode: {runtime.profile_key in self.sensitive_profiles}")
                path = self._temp_dir(event) / f"browser_diagnostic_{_now_stamp()}.txt"
                path.write_text("\n".join(report), encoding="utf-8")
                shot = await _browser_controller.error_screenshot(page, "diagnostic", self._temp_dir(event))
                return f"诊断报告已保存：{path}\n截图：{shot}"
            except Exception as e:
                return f"诊断失败：{_mask_sensitive(str(e), 800)}"

    @filter.llm_tool(name="browser_eval")
    async def browser_eval(self, event: AstrMessageEvent, js: str):
        '''执行受控 JavaScript，用于 DOM 诊断。仅限管理员使用。不会刷新页面。

        Args:
            js(string): 要执行的 JavaScript 代码
        '''
        if str(event.get_sender_id()) != "2357050717":
            return "错误：此工具仅限管理员使用"
        async with _browser_controller._op_lock:
            try:
                page = await self._ensure_page(event)
                result = await page.evaluate(js)
                return "执行结果：\n" + _safe_json(result, 12000)
            except Exception as e:
                return f"执行失败：{_mask_sensitive(str(e), 1000)}"

    @filter.llm_tool(name="browser_close")
    async def browser_close(self, event: AstrMessageEvent):
        '''关闭浏览器，释放资源。下次调用会重新打开并复用同一个 profile 登录态。'''
        try:
            await _browser_controller.close()
            return "浏览器已关闭"
        except Exception as e:
            return f"关闭浏览器失败：{_mask_sensitive(str(e), 800)}"

    async def terminate(self):
        """插件卸载时关闭浏览器。"""
        await _browser_controller.close()
