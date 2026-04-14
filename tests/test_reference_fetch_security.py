import socket

import vendor.infer_cvss31_from_references as reference_inference


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
