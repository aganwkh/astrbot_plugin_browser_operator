# Browser Operator System Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden `astrbot_plugin_browser_operator` for safer public use while keeping the existing AstrBot tool surface intact.

**Architecture:** Add small pure-Python modules for security policy, redaction, and runtime settings so high-risk logic can be tested without AstrBot or Playwright. Keep `main.py` as the AstrBot integration layer and wire those modules into browser launch, URL opening, element listing, typing, screenshots, uploads, downloads, diagnostics, and lifecycle cleanup.

**Tech Stack:** Python, AstrBot plugin APIs, Playwright async API, pytest.

---

### Task 1: Regression Tests For Safety Defaults

**Files:**
- Create: `tests/test_security.py`
- Create: `tests/test_redact.py`
- Create: `tests/test_settings.py`

- [ ] **Step 1: Write tests for URL policy**

Create tests that prove public HTTPS URLs pass, localhost/private/link-local/metadata hosts fail by default, and domain allow/block lists are enforced.

- [ ] **Step 2: Write tests for redaction**

Create tests that prove tokens are masked, sensitive input metadata is detected, and element names never expose sensitive values.

- [ ] **Step 3: Write tests for runtime settings**

Create tests that prove `profile_scope=session` generates per-session profile directories and that list-like config values parse from strings or lists.

- [ ] **Step 4: Run pytest and confirm RED**

Run: `python -m pytest tests -q`
Expected: fails because `security`, `redact`, and `settings` modules do not exist yet.

### Task 2: Implement Tested Helper Modules

**Files:**
- Create: `security.py`
- Create: `redact.py`
- Create: `settings.py`

- [ ] **Step 1: Implement URL and domain policy**

Add `validate_url`, `is_private_or_local_host`, `domain_matches`, and `check_domain_policy`.

- [ ] **Step 2: Implement redaction helpers**

Add `mask_sensitive`, `looks_sensitive`, `is_sensitive_metadata`, and `safe_element_name`.

- [ ] **Step 3: Implement runtime config helpers**

Add `BrowserRuntimeConfig`, `build_runtime_config`, `parse_list`, and stable event ID helpers.

- [ ] **Step 4: Run pytest and confirm GREEN**

Run: `python -m pytest tests -q`
Expected: all helper tests pass.

### Task 3: Wire Safety Into AstrBot Plugin

**Files:**
- Modify: `main.py`
- Modify: `_conf_schema.json`

- [ ] **Step 1: Make browser launch configurable**

Use runtime settings for Chromium path, temp/profile directories, headless mode, viewport, default timeout, proxy, and profile scope.

- [ ] **Step 2: Enforce permissions and URL policy**

Check `allowed_users`, `allowed_sessions`, `allowed_domains`, `blocked_domains`, and `allow_private_network` before high-risk browser actions.

- [ ] **Step 3: Protect sensitive fields**

Do not return input values for sensitive fields. Skip automatic observation after sensitive `type` and `frame_type`. Block explicit screenshots/observations while sensitive mode is active unless disabled by config.

- [ ] **Step 4: Remove unsafe proxy and observe defaults**

Disable automatic proxy detection. Default `vision_trigger_actions` to actions that do not include `type`.

### Task 4: Documentation And Installability

**Files:**
- Create: `README.md`
- Create: `requirements.txt`
- Create: `requirements-dev.txt`
- Modify: `metadata.yaml`

- [ ] **Step 1: Add runtime requirements**

Add Playwright runtime dependency and pytest dev dependency.

- [ ] **Step 2: Add README**

Document install steps, configuration, tool list, safety defaults, profile cleanup, and known risk boundaries.

- [ ] **Step 3: Align metadata**

Update metadata to remove fixed-path claims and describe configurable/safe defaults.

### Task 5: Verification

**Files:**
- Existing project files

- [ ] **Step 1: Run tests**

Run: `python -m pytest tests -q`
Expected: all tests pass.

- [ ] **Step 2: Compile Python**

Run: `python -m compileall .`
Expected: all Python files compile.

- [ ] **Step 3: Inspect git diff**

Run: `git diff --stat` and `git diff --check`
Expected: scoped changes, no whitespace errors.
