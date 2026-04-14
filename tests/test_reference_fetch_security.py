import socket
import urllib.error
from email.message import Message

import vendor.infer_cvss31_from_references as reference_inference


fetch_url = reference_inference.fetch_url
validate_reference_url = reference_inference.validate_reference_url


def test_validate_reference_url_blocks_non_https() -> None:
    assert validate_reference_url("http://example.com/advisory") == "Reference URL blocked: only https URLs are allowed"


def test_validate_reference_url_blocks_private_hosts() -> None:
    assert validate_reference_url("https://127.0.0.1/advisory") == (
        "Reference URL blocked: hostname resolves to a private or reserved address"
    )


def test_validate_reference_url_allows_public_https(monkeypatch) -> None:
    monkeypatch.setattr(
        reference_inference.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("140.82.112.4", 443))],
    )

    assert validate_reference_url("https://github.com/example/project/security/advisories/GHSA-abcd-1234-wxyz") is None


def test_fetch_url_blocks_private_redirect_before_following(monkeypatch) -> None:
    opened_urls = []

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host == "public.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        if host == "127.0.0.1":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        raise socket.gaierror

    class FakeOpener:
        def open(self, request, timeout):
            opened_urls.append(request.full_url)
            headers = Message()
            headers["Location"] = "https://127.0.0.1/internal"
            raise urllib.error.HTTPError(request.full_url, 302, "Found", headers, None)

    monkeypatch.setattr(reference_inference.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(reference_inference, "NO_REDIRECT_OPENER", FakeOpener())

    content, content_type, error = fetch_url("https://public.example/advisory", timeout=1)

    assert content is None
    assert content_type is None
    assert error == "Reference URL blocked: hostname resolves to a private or reserved address"
    assert opened_urls == ["https://public.example/advisory"]
