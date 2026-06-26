import unittest

from redact import is_sensitive_metadata, mask_sensitive, safe_element_name


class RedactTests(unittest.TestCase):
    def test_mask_sensitive_hides_token_values(self):
        masked = mask_sensitive("access_token=abc123 password: hunter2 cookie=sessionid")

        self.assertNotIn("abc123", masked)
        self.assertNotIn("hunter2", masked)
        self.assertNotIn("sessionid", masked)
        self.assertIn("<masked>", masked)

    def test_sensitive_metadata_matches_password_and_token_fields(self):
        self.assertTrue(is_sensitive_metadata({"type": "password", "name": "login_password"}))
        self.assertTrue(is_sensitive_metadata({"id": "api-token", "placeholder": "API Token"}))
        self.assertTrue(is_sensitive_metadata({"aria": "验证码"}))
        self.assertFalse(is_sensitive_metadata({"type": "text", "name": "search", "placeholder": "Search"}))

    def test_safe_element_name_never_returns_sensitive_value(self):
        name = safe_element_name(
            {
                "tag": "input",
                "type": "password",
                "value": "secret-password",
                "placeholder": "Password",
            }
        )

        self.assertEqual(name, "<sensitive input masked>")
        self.assertNotIn("secret-password", name)

    def test_safe_element_name_prefers_non_sensitive_labels_over_value(self):
        name = safe_element_name(
            {
                "tag": "input",
                "type": "text",
                "value": "typed text",
                "placeholder": "Search docs",
                "aria": "",
                "name": "q",
            }
        )

        self.assertEqual(name, "Search docs")
        self.assertNotIn("typed text", name)


if __name__ == "__main__":
    unittest.main()
