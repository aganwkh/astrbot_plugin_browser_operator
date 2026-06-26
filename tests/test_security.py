import unittest

from security import check_domain_policy, validate_url


class SecurityTests(unittest.TestCase):
    def test_validate_url_allows_public_https(self):
        self.assertEqual(validate_url("https://93.184.216.34/path?q=1"), "https://93.184.216.34/path?q=1")

    def test_validate_url_blocks_unsafe_targets_by_default(self):
        for url in [
            "ftp://example.com",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://10.0.0.5",
            "http://172.16.0.5",
            "http://192.168.1.10",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/",
            "http://[fc00::1]/",
        ]:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    validate_url(url)

    def test_validate_url_can_allow_private_network_when_configured(self):
        self.assertEqual(
            validate_url("http://127.0.0.1:8000", allow_private_network=True),
            "http://127.0.0.1:8000",
        )

    def test_check_domain_policy_blocks_blacklisted_domain(self):
        with self.assertRaises(ValueError):
            check_domain_policy("sub.example.com", allowed_domains=[], blocked_domains=["example.com"])

    def test_check_domain_policy_enforces_allowlist(self):
        check_domain_policy("docs.example.com", allowed_domains=["example.com"], blocked_domains=[])
        with self.assertRaises(ValueError):
            check_domain_policy("other.test", allowed_domains=["example.com"], blocked_domains=[])


if __name__ == "__main__":
    unittest.main()
