# astrbot_plugin_browser_operator

给 AstrBot 提供基于 Playwright 的浏览器操作工具。插件会保留浏览器 profile，用于连续打开网页、点击、输入、滚动、截图观察、下载、上传、多标签页和 iframe 操作。

## 安装

1. 安装插件到 AstrBot 插件目录。
2. 安装 Python 依赖：

```bash
pip install -r requirements.txt
```

3. 安装浏览器。二选一：

```bash
playwright install chromium
```

或安装系统 Chromium，并在插件配置中填写 `chrome_path`，例如 `/usr/bin/chromium-browser`。

## 安全默认值

- 默认禁止访问 `localhost`、内网、link-local、IPv6 ULA 和云 metadata 地址。
- 默认按 `session` 隔离浏览器 profile，避免不同会话共用登录态。
- 默认不在 `type` 或 `frame_type` 后自动截图观察。
- 输入密码、token、cookie、验证码、密钥等敏感字段后，会进入敏感保护模式并阻止截图/视觉观察。
- 默认不启用代理，也不会自动探测 `127.0.0.1:7890`。
- 上传文件只允许来自配置的 `temp_dir`。
- 下载文件会保存到配置的 `temp_dir`，超过 `max_download_size_mb` 会自动删除。

## 关键配置

- `data_dir`：AstrBot 数据目录，默认 `/opt/AstrBot/data`。
- `temp_dir`：截图、下载和诊断文件目录，默认 `data_dir/temp`。
- `chrome_path`：系统 Chromium/Chrome 可执行文件路径。为空时使用 Playwright 默认浏览器。
- `profile_scope`：`global`、`session`、`user` 或 `platform_session`，默认 `session`。
- `allow_private_network`：是否允许访问本机和内网，默认 `false`。
- `allowed_users` / `allowed_sessions`：用户或会话白名单，空列表表示不限制。
- `allowed_domains` / `blocked_domains`：域名白名单/黑名单。
- `use_proxy` / `proxy_server`：显式代理配置。
- `max_pages`：最大标签页数量，默认 5。
- `max_download_size_mb`：最大下载文件大小，默认 50 MB。

## 工具列表

- `browser_open`：打开网页。
- `browser_state`、`browser_text`、`browser_html`：读取页面状态和内容。
- `browser_list_elements`、`browser_elements_from_point`、`browser_dump_near_text`：辅助定位页面元素。
- `browser_click`、`browser_click_role`、`browser_click_at`：点击元素。
- `browser_type`、`browser_press`、`browser_select`、`browser_check`：输入和表单操作。
- `browser_screenshot`、`browser_observe`、`browser_last_observation`：截图和视觉观察。
- `browser_reload`、`browser_back`、`browser_forward`、`browser_wait`、`browser_wait_for`：导航和等待。
- `browser_scroll`、`browser_scroll_to`、`browser_hover`：页面交互。
- `browser_download_click`、`browser_upload`：下载和上传。
- `browser_click_open_new_page`、`browser_pages`、`browser_switch_page`、`browser_close_current_page`：标签页管理。
- `browser_frame_text`、`browser_click_in_frame`、`browser_type_in_frame`：iframe 操作。
- `browser_dialog_mode`：设置 alert/confirm/prompt 处理方式。
- `browser_diagnostic`：保存诊断报告和截图。
- `browser_close`：关闭浏览器释放资源。

## 使用建议

公开群聊中建议配置 `allowed_users` 或 `allowed_sessions`。如果确实需要访问内网管理页面，显式开启 `allow_private_network`，并同时配置 `allowed_domains` 或 `allowed_users`。

如果输入过敏感信息后需要继续截图，先执行 `browser_open`、`browser_reload`、`browser_back` 或 `browser_forward` 进入新的页面状态，敏感保护会自动解除。

## 开发验证

```bash
python -m unittest discover -s tests -t . -v
python -m compileall .
```
