import ipaddress
import socket
from urllib.parse import urlparse


PRIVATE_HOSTS = {"localhost", "local", "broadcasthost"}


def _host_ips(hostname: str):
    try:
        yield ipaddress.ip_address(hostname)
        return
    except ValueError:
        pass

    try:
        for item in socket.getaddrinfo(hostname, None):
            yield ipaddress.ip_address(item[4][0])
    except Exception:
        # Fail closed: unknown hosts should not bypass network policy.
        yield None


def _is_restricted_ip(ip) -> bool:
    if ip is None:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_private_or_local_host(hostname: str) -> bool:
    if not hostname:
        return True

    host = hostname.strip().lower().rstrip(".")
    if host in PRIVATE_HOSTS:
        return True

    return any(_is_restricted_ip(ip) for ip in _host_ips(host))


def domain_matches(host: str, rule: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    rule = (rule or "").strip().lower().rstrip(".")
    return bool(host and rule) and (host == rule or host.endswith("." + rule))


def check_domain_policy(host: str, allowed_domains=None, blocked_domains=None) -> None:
    allowed_domains = allowed_domains or []
    blocked_domains = blocked_domains or []

    if any(domain_matches(host, domain) for domain in blocked_domains):
        raise ValueError("该域名在黑名单中")

    if allowed_domains and not any(domain_matches(host, domain) for domain in allowed_domains):
        raise ValueError("该域名不在白名单中")


def validate_url(
    url: str,
    allow_private_network: bool = False,
    allowed_domains=None,
    blocked_domains=None,
) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("只允许 http/https URL")
    if not parsed.hostname:
        raise ValueError("URL 缺少 hostname")

    check_domain_policy(parsed.hostname, allowed_domains, blocked_domains)

    if not allow_private_network and is_private_or_local_host(parsed.hostname):
        raise ValueError("安全策略禁止访问 localhost、内网或 link-local 地址")

    return url
