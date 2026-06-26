import unittest
from pathlib import Path

from settings import build_runtime_config, parse_list, safe_id


class DummyConfig(dict):
    pass


class DummyEvent:
    def __init__(self, sender_id="u/1", session_id="group:42", platform="test-platform"):
        self.sender_id = sender_id
        self.session_id = session_id
        self.platform = platform

    def get_sender_id(self):
        return self.sender_id

    def get_session_id(self):
        return self.session_id

    def get_platform_name(self):
        return self.platform


class SettingsTests(unittest.TestCase):
    def test_parse_list_accepts_lists_and_comma_strings(self):
        self.assertEqual(parse_list(["a", " b ", "", 3]), ["a", "b", "3"])
        self.assertEqual(parse_list("a, b,,c"), ["a", "b", "c"])
        self.assertEqual(parse_list(""), [])

    def test_safe_id_replaces_path_unsafe_characters(self):
        self.assertEqual(safe_id("group:42/user\\name"), "group_42_user_name")

    def test_build_runtime_config_defaults_to_session_profile_scope(self):
        tmp_path = Path("C:/tmp/browser-operator-tests")
        runtime = build_runtime_config(
            DummyConfig({"data_dir": str(tmp_path)}),
            DummyEvent(session_id="group:42"),
        )

        self.assertEqual(runtime.profile_scope, "session")
        self.assertEqual(runtime.profile_key, "session:group_42")
        self.assertEqual(runtime.profile_dir, tmp_path / "browser_profiles" / "sessions" / "group_42")
        self.assertEqual(runtime.temp_dir, tmp_path / "temp")

    def test_build_runtime_config_supports_user_profile_scope(self):
        tmp_path = Path("C:/tmp/browser-operator-tests")
        runtime = build_runtime_config(
            DummyConfig({"data_dir": str(tmp_path), "profile_scope": "user"}),
            DummyEvent(sender_id="user:99"),
        )

        self.assertEqual(runtime.profile_key, "user:user_99")
        self.assertEqual(runtime.profile_dir, tmp_path / "browser_profiles" / "users" / "user_99")


if __name__ == "__main__":
    unittest.main()
