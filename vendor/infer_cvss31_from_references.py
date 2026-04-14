#!/usr/bin/env python3
import argparse
import ipaddress
import json
import math
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


METRIC_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": "U", "C": "C"},
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},
}

PR_WEIGHTS = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}

REQUIRED_METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
MAX_REFERENCE_BYTES = 1_000_000

RULES: Dict[str, List[Tuple[str, str, float, str, str]]] = {
    "AV": [
        (r"\b(remote|via network|network[- ]based|over (?:the )?(?:internet|network)|http[s]?://|api endpoint|tcp|udp)\b", "N", 1.0, "Network attack path indicators", "direct"),
        (r"\b(adjacent network|same subnet|lan only)\b", "A", 0.9, "Adjacent network indicators", "direct"),
        (r"\b(local attacker|local user|local access to host|same machine)\b", "L", 0.9, "Local attack path indicators", "direct"),
        (r"\b(physical access|physical attacker)\b", "P", 0.9, "Physical access indicators", "direct"),
    ],
    "AC": [
        (r"\b(race condition|specific timing|unlikely conditions|complex chain|requires precise timing)\b", "H", 0.8, "High complexity indicators", "contextual"),
        (r"\b(easily exploited|straightforward|simple to exploit|no special conditions)\b", "L", 0.8, "Low complexity indicators", "contextual"),
    ],
    "PR": [
        (r"\b(unauthenticated|without authentication|no authentication required|anonymous attacker)\b", "N", 1.0, "No privileges required", "direct"),
        (r"\b(authenticated user|valid account|logged-in user|requires authentication|authorization: basic|bearer token)\b", "L", 1.0, "Authenticated access required", "direct"),
        (r"\b(admin(?:istrator)? only|root privileges required|requires admin)\b", "H", 1.0, "High privileges required", "direct"),
    ],
    "UI": [
        (r"\b(no user interaction|without user interaction|does not require user interaction)\b", "N", 1.0, "No user interaction required", "direct"),
        (r"\b(user interaction required|required user action|click link|open file|social engineering)\b", "R", 1.0, "User interaction required", "direct"),
    ],
    "S": [
        (r"\b(cross[- ]tenant|cross[- ]repository|across different repos|one repo impacts another|impacts resources in components beyond)\b", "C", 1.0, "Scope changed across security boundary", "direct"),
        (r"\b(scope unchanged|same security authority)\b", "U", 1.0, "Scope unchanged", "direct"),
    ],
    "C": [
        (r"\b(information disclosure|data leak|read arbitrary|confidential data|confidentiality impact)\b", "H", 0.9, "Confidentiality impact", "direct"),
    ],
    "I": [
        (r"\b(maliciously overwritten|tampered files|tamper|integrity impact|modify arbitrary|arbitrary write|injecting backdoor|supply-chain attack|overwrite this file)\b", "H", 1.0, "Integrity impact", "direct"),
        (r"\b(partial integrity|limited integrity impact)\b", "L", 0.8, "Limited integrity impact", "contextual"),
    ],
    "A": [
        (r"\b(denial of service|dos|service disruption|crash|availability impact)\b", "H", 0.9, "Availability impact", "direct"),
        (r"\b(limited availability impact|degraded availability)\b", "L", 0.8, "Limited availability impact", "contextual"),
    ],
}

FALLBACK_METRICS = {
    "AV": "L",
    "AC": "L",
    "PR": "L",
    "UI": "N",
    "S": "U",
    "C": "L",
    "I": "L",
    "A": "L",
}

BOILERPLATE_PATTERNS = [
    re.compile(r"learn more about base metrics cvss v3"),
    re.compile(r"more severe when"),
    re.compile(r"attack vector: more severe"),
    re.compile(r"scope: more severe"),
    re.compile(r"confidentiality: more severe"),
    re.compile(r"integrity: more severe"),
    re.compile(r"availability: more severe"),
]


def round_up_1_decimal(value: float) -> float:
    return math.ceil(value * 10.0) / 10.0


def severity_from_score(score: float) -> str:
    if score == 0.0:
        return "NONE"
    if score <= 3.9:
        return "LOW"
    if score <= 6.9:
        return "MEDIUM"
    if score <= 8.9:
        return "HIGH"
    return "CRITICAL"


def compute_base_score(metrics: Dict[str, str]) -> float:
    av = METRIC_WEIGHTS["AV"][metrics["AV"]]
    ac = METRIC_WEIGHTS["AC"][metrics["AC"]]
    ui = METRIC_WEIGHTS["UI"][metrics["UI"]]
    scope = METRIC_WEIGHTS["S"][metrics["S"]]
    c = METRIC_WEIGHTS["C"][metrics["C"]]
    i = METRIC_WEIGHTS["I"][metrics["I"]]
    a = METRIC_WEIGHTS["A"][metrics["A"]]
    pr = PR_WEIGHTS[scope][metrics["PR"]]

    isc_base = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope == "U":
        return round_up_1_decimal(min(impact + exploitability, 10.0))
    return round_up_1_decimal(min(1.08 * (impact + exploitability), 10.0))


def vector_from_metrics(metrics: Dict[str, str]) -> str:
    return "CVSS:3.1/" + "/".join(f"{k}:{metrics[k]}" for k in REQUIRED_METRICS)


def parse_vector(vector: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not vector or not vector.startswith("CVSS:3.1/"):
        return out
    for token in vector.split("/")[1:]:
        if ":" not in token:
            continue
        key, value = token.split(":", 1)
        out[key] = value.strip().upper()
    return out


def extract_cve_data(path: str) -> Dict[str, object]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    cve_id = data.get("cveMetadata", {}).get("cveId", "UNKNOWN")
    published_score = None
    published_vector = None
    published_source = None

    metrics = data.get("containers", {}).get("cna", {}).get("metrics", [])
    for metric in metrics:
        cv = metric.get("cvssV3_1")
        if not cv:
            continue
        published_score = cv.get("baseScore")
        published_vector = cv.get("vectorString")
        published_source = "cna"
        if published_score is not None or published_vector:
            break

    if published_source is None:
        for adp in data.get("containers", {}).get("adp", []):
            for metric in adp.get("metrics", []):
                cv = metric.get("cvssV3_1")
                if not cv:
                    continue
                published_score = cv.get("baseScore")
                published_vector = cv.get("vectorString")
                published_source = f"adp:{adp.get('providerMetadata', {}).get('shortName', 'unknown')}"
                if published_score is not None or published_vector:
                    break
            if published_source is not None:
                break

    references: List[str] = []
    for ref in data.get("containers", {}).get("cna", {}).get("references", []):
        url = ref.get("url")
        if url:
            references.append(url)
    for adp in data.get("containers", {}).get("adp", []):
        for ref in adp.get("references", []):
            url = ref.get("url")
            if url:
                references.append(url)

    descriptions = []
    for desc in data.get("containers", {}).get("cna", {}).get("descriptions", []):
        value = desc.get("value")
        if value:
            descriptions.append(value)

    return {
        "cve_id": cve_id,
        "references": sorted(set(references)),
        "provided_score": published_score,
        "provided_vector": published_vector,
        "provided_source": published_source,
        "descriptions": descriptions,
    }


def strip_html(raw: str) -> str:
    raw = re.sub(r"(?is)<script.*?>.*?</script>", " ", raw)
    raw = re.sub(r"(?is)<style.*?>.*?</style>", " ", raw)
    raw = re.sub(r"(?s)<[^>]+>", " ", raw)
    raw = re.sub(r"\s+", " ", raw)
    return raw.strip()


def is_blocked_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_reference_url(url: str) -> Optional[str]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https":
        return "Reference URL blocked: only https URLs are allowed"
    if not parsed.hostname:
        return "Reference URL blocked: missing hostname"

    try:
        addr_info = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return "Reference URL blocked: hostname could not be resolved"

    for family, _, _, _, sockaddr in addr_info:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        if is_blocked_ip(sockaddr[0]):
            return "Reference URL blocked: hostname resolves to a private or reserved address"

    return None


def read_limited_response(response, max_bytes: int) -> Tuple[Optional[bytes], Optional[str]]:
    content_length = response.headers.get("Content-Length")
    if content_length and int(content_length) > max_bytes:
        return None, "Reference response blocked: response is too large"

    data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        return None, "Reference response blocked: response is too large"
    return data, None


def fetch_url(url: str, timeout: int, headers: Optional[Dict[str, str]] = None) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    validation_error = validate_reference_url(url)
    if validation_error:
        return None, None, validation_error

    hdrs = {"User-Agent": "cvss-reference-inference/2.0"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            final_validation_error = validate_reference_url(resp.geturl())
            if final_validation_error:
                return None, None, final_validation_error
            data, size_error = read_limited_response(resp, MAX_REFERENCE_BYTES)
            if size_error:
                return None, None, size_error
            return data, resp.headers.get("Content-Type", ""), None
    except (ValueError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        return None, None, str(exc)


def decode_text(content_bytes: bytes) -> str:
    try:
        return content_bytes.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        return content_bytes.decode("latin-1", errors="ignore")


def github_advisory_api_url(url: str) -> Optional[str]:
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[A-Za-z0-9\-]+)", url)
    if not match:
        return None
    owner, repo, ghsa = match.group(1), match.group(2), match.group(3)
    return f"https://api.github.com/repos/{owner}/{repo}/security-advisories/{ghsa}"


def fetch_reference_docs(reference_urls: List[str], timeout: int, cve_descriptions: List[str]) -> List[Dict[str, Optional[str]]]:
    docs: List[Dict[str, Optional[str]]] = []

    for idx, value in enumerate(cve_descriptions):
        docs.append(
            {
                "url": f"cve_json_description:{idx + 1}",
                "text": re.sub(r"\s+", " ", value).strip().lower(),
                "error": None,
                "source_type": "structured",
            }
        )

    for url in reference_urls:
        api_url = github_advisory_api_url(url)
        if api_url:
            content, _, err = fetch_url(
                api_url,
                timeout,
                headers={"Accept": "application/vnd.github+json"},
            )
            if err is None and content is not None:
                payload = json.loads(decode_text(content))
                advisory_text = "\n\n".join(
                    [
                        str(payload.get("summary", "")),
                        str(payload.get("description", "")),
                    ]
                )
                docs.append(
                    {
                        "url": api_url,
                        "text": re.sub(r"\s+", " ", advisory_text).strip().lower(),
                        "error": None,
                        "source_type": "structured",
                    }
                )
            else:
                docs.append({"url": api_url, "text": None, "error": err, "source_type": "structured"})

        content, content_type, err = fetch_url(url, timeout)
        if err is not None:
            docs.append({"url": url, "text": None, "error": err, "source_type": "html_or_text"})
            continue

        assert content is not None
        text = decode_text(content)
        if (content_type and "html" in content_type.lower()) or "<html" in text[:500].lower():
            text = strip_html(text)
        else:
            text = re.sub(r"\s+", " ", text).strip()

        docs.append({"url": url, "text": text.lower(), "error": None, "source_type": "html_or_text"})

    return docs


def extract_snippet(text: str, start: int, end: int, radius: int = 90) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right].strip()


def is_boilerplate(snippet: str) -> bool:
    return any(pattern.search(snippet) for pattern in BOILERPLATE_PATTERNS)


def infer_metrics(reference_docs: List[Dict[str, Optional[str]]]) -> Tuple[Dict[str, str], Dict[str, List[dict]], List[str], List[str]]:
    evidence: Dict[str, List[dict]] = defaultdict(list)

    for doc in reference_docs:
        text = doc.get("text")
        if not text:
            continue
        source_type = doc.get("source_type") or "unknown"
        url = doc.get("url") or "unknown"

        for metric, metric_rules in RULES.items():
            for pattern, value, confidence, rationale, ev_type in metric_rules:
                for match in re.finditer(pattern, text):
                    snippet = extract_snippet(text, match.start(), match.end())
                    if is_boilerplate(snippet):
                        continue
                    evidence[metric].append(
                        {
                            "url": url,
                            "value": value,
                            "confidence": confidence,
                            "rationale": rationale,
                            "evidence_type": ev_type,
                            "source_type": source_type,
                            "snippet": snippet,
                        }
                    )

    resolved: Dict[str, str] = {}
    assumptions: List[str] = []
    fallback_metrics: List[str] = []

    for metric in REQUIRED_METRICS:
        candidates = evidence.get(metric, [])
        if not candidates:
            resolved[metric] = FALLBACK_METRICS[metric]
            fallback_metrics.append(metric)
            assumptions.append(f"No direct evidence for {metric}; used fallback={FALLBACK_METRICS[metric]}")
            continue

        score_by_value: Dict[str, float] = defaultdict(float)
        for item in candidates:
            weight = float(item["confidence"])
            if item["evidence_type"] == "direct":
                weight *= 1.15
            if item["source_type"] == "structured":
                weight *= 1.10
            score_by_value[item["value"]] += weight

        resolved[metric] = max(score_by_value, key=score_by_value.get)

    return resolved, evidence, assumptions, fallback_metrics


def contains_any(text: str, patterns: List[str]) -> bool:
    return any(re.search(pattern, text) for pattern in patterns)


def adjudicate_metrics(metrics: Dict[str, str], docs: List[Dict[str, Optional[str]]]) -> List[str]:
    overrides: List[str] = []
    merged = " ".join([doc.get("text", "") or "" for doc in docs])

    unauth = contains_any(merged, [r"\bunauthenticated\b", r"\bno authentication required\b", r"\bwithout authentication\b"])
    auth = contains_any(
        merged,
        [
            r"\bauthenticated user\b",
            r"\bvalid account\b",
            r"\bauthorization:\s*basic\b",
            r"\bbearer\s+[A-Za-z0-9\-_\.]+",
            r"\blogged-in\b",
        ],
    )
    if auth and not unauth and metrics.get("PR") == "N":
        metrics["PR"] = "L"
        overrides.append("PR overridden to L due to authenticated exploit preconditions in advisory/PoC evidence")

    network = contains_any(merged, [r"\bhttp://", r"\bhttps://", r"\bapi\b", r"\bnetwork\b", r"\bremote\b", r"\btcp\b"])
    local_attack = contains_any(merged, [r"\blocal attacker\b", r"\blocal user\b", r"\bsame machine\b"])
    if network and not local_attack and metrics.get("AV") == "L":
        metrics["AV"] = "N"
        overrides.append("AV overridden to N because exploit path evidence is network-based")

    cross_boundary = contains_any(
        merged,
        [
            r"\bcross-repository\b",
            r"\bacross different repos\b",
            r"\bone repo impacts another\b",
            r"\bcross-tenant\b",
        ],
    )
    if cross_boundary and metrics.get("S") == "U":
        metrics["S"] = "C"
        overrides.append("S overridden to C due to cross-boundary impact evidence")

    return overrides


def metric_reason(metric: str, old_value: str, new_value: str, evidence_items: List[dict], fallback_metrics: List[str]) -> Dict[str, object]:
    if metric in fallback_metrics:
        return {
            "reason": f"No direct evidence; fallback changed {metric} from {old_value} to {new_value}",
            "evidence_source": None,
            "evidence_type": "fallback",
        }

    if evidence_items:
        matching = [item for item in evidence_items if item.get("value") == new_value]
        pool = matching if matching else evidence_items
        pool = sorted(
            pool,
            key=lambda item: (
                0 if item.get("source_type") == "structured" else 1,
                0 if item.get("evidence_type") == "direct" else 1,
                -float(item.get("confidence", 0.0)),
            ),
        )
        best = pool[0]
        return {
            "reason": best.get("rationale") or f"Evidence supports {metric}:{new_value}",
            "evidence_source": best.get("url"),
            "evidence_type": best.get("evidence_type", "contextual"),
        }

    return {
        "reason": f"Insufficient direct evidence; inferred {metric}:{new_value}",
        "evidence_source": None,
        "evidence_type": "contextual",
    }


def confidence_summary(fallback_metrics: List[str], evidence: Dict[str, List[dict]]) -> Tuple[str, bool, List[str]]:
    evidence_backed = [metric for metric in REQUIRED_METRICS if evidence.get(metric)]
    fallback_count = len(fallback_metrics)
    direct_count = 0
    for metric in REQUIRED_METRICS:
        for item in evidence.get(metric, []):
            if item.get("evidence_type") == "direct":
                direct_count += 1
                break

    if fallback_count >= 3 or direct_count < 4:
        confidence = "low"
    elif fallback_count >= 1:
        confidence = "medium"
    else:
        confidence = "high"

    return confidence, confidence == "low", evidence_backed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Infer CVSS v3.1 metrics from CVE references with evidence quality controls."
    )
    parser.add_argument("--cve-json", required=True, help="Path to CVE v5 JSON file.")
    parser.add_argument("--timeout", type=int, default=20, help="HTTP timeout per reference URL in seconds.")
    parser.add_argument("--max-evidence", type=int, default=2, help="Max evidence items to emit per metric.")
    parser.add_argument(
        "--strict-undetermined",
        action="store_true",
        help="Do not apply fallback values; mark unsupported metrics as undetermined and skip final scoring.",
    )
    args = parser.parse_args()

    cve = extract_cve_data(args.cve_json)
    cve_id = str(cve["cve_id"])
    reference_urls = list(cve["references"])
    provided_score = cve["provided_score"]
    provided_vector = cve["provided_vector"]
    provided_source = cve["provided_source"]
    descriptions = list(cve["descriptions"])

    if not reference_urls and not descriptions:
        raise SystemExit("No references or descriptions found in CVE JSON")

    reference_docs = fetch_reference_docs(reference_urls, args.timeout, descriptions)
    metrics, evidence, assumptions, fallback_metrics = infer_metrics(reference_docs)
    overrides = adjudicate_metrics(metrics, reference_docs)

    undetermined_metrics: List[str] = []
    if args.strict_undetermined:
        for metric in REQUIRED_METRICS:
            if metric in fallback_metrics:
                undetermined_metrics.append(metric)

    final_vector = None
    final_score = None
    final_severity = None
    if not undetermined_metrics:
        final_vector = vector_from_metrics(metrics)
        final_score = compute_base_score(metrics)
        final_severity = severity_from_score(final_score)

    original_metrics = parse_vector(str(provided_vector or ""))
    changed_metrics = {}
    compact_evidence = {metric: evidence.get(metric, [])[: args.max_evidence] for metric in REQUIRED_METRICS}

    if original_metrics:
        for metric in REQUIRED_METRICS:
            original_value = original_metrics.get(metric)
            rescored_value = metrics.get(metric)
            if original_value is None or rescored_value is None:
                continue
            if original_value != rescored_value:
                changed_metrics[metric] = {
                    "original": original_value,
                    "rescored": rescored_value,
                    **metric_reason(metric, original_value, rescored_value, compact_evidence.get(metric, []), fallback_metrics),
                }

    confidence, low_confidence, evidence_backed_metrics = confidence_summary(fallback_metrics, compact_evidence)

    result = {
        "cve_id": cve_id,
        "analysis_mode": "references_only",
        "references_checked": reference_urls,
        "reference_fetch_errors": [doc for doc in reference_docs if doc.get("error")],
        "vector": final_vector,
        "score": final_score,
        "severity": final_severity,
        "assumptions": assumptions,
        "adjudication_overrides": overrides,
        "evidence": compact_evidence,
        "provided_vector_ignored": provided_vector,
        "provided_score_ignored": provided_score,
        "provided_score_source": provided_source,
        "delta_from_provided_score": None
        if (provided_score is None or final_score is None)
        else round(float(final_score) - float(provided_score), 1),
        "confidence": confidence,
        "low_confidence": low_confidence,
        "evidence_quality": {
            "evidence_backed_metrics": evidence_backed_metrics,
            "fallback_metrics": fallback_metrics,
            "undetermined_metrics": undetermined_metrics,
        },
        "comparison": {
            "original_vector": provided_vector,
            "original_score": provided_score,
            "original_source": provided_source,
            "rescored_vector": final_vector,
            "rescored_score": final_score,
            "rescored_severity": final_severity,
            "score_delta": None
            if (provided_score is None or final_score is None)
            else round(float(final_score) - float(provided_score), 1),
            "changed_metrics": changed_metrics,
        },
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
