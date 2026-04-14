# CVSS Metric Inference Rules

This document describes how CVSS Re-score Workbench infers CVSS v3.1 base metrics from CVE descriptions and reference text.

The scorer is a reference-based heuristic engine. It does not use the published CVSS vector as the input for the new score. Instead, it:

1. Fetches the CVE JSON from CVEProject.
2. Extracts CVE descriptions and reference URLs.
3. Fetches reference text.
4. Matches vulnerability-specific phrases against metric rules.
5. Resolves CVSS v3.1 base metrics.
6. Computes a fresh CVSS v3.1 base score.
7. Compares the result against the published score, if one exists.

The bundled implementation lives in [`vendor/infer_cvss31_from_references.py`](../vendor/infer_cvss31_from_references.py).

## Required Metrics

The scorer resolves these CVSS v3.1 base metrics:

```text
AV, AC, PR, UI, S, C, I, A
```

## Attack Vector: `AV`

### `AV:N` Network

Triggered by phrases like:

- `remote`
- `via network`
- `network-based`
- `over the internet`
- `over the network`
- `http://`
- `https://`
- `api endpoint`
- `tcp`
- `udp`

Example:

```text
A remote attacker can exploit the API endpoint over the network.
```

Result:

```text
AV:N
```

### `AV:A` Adjacent

Triggered by:

- `adjacent network`
- `same subnet`
- `lan only`

Example:

```text
An attacker on the same subnet can trigger the vulnerability.
```

Result:

```text
AV:A
```

### `AV:L` Local

Triggered by:

- `local attacker`
- `local user`
- `local access to host`
- `same machine`

Example:

```text
A local user on the same machine can exploit the issue.
```

Result:

```text
AV:L
```

### `AV:P` Physical

Triggered by:

- `physical access`
- `physical attacker`

Example:

```text
Exploitation requires physical access to the device.
```

Result:

```text
AV:P
```

Fallback if no `AV` evidence is found:

```text
AV:L
```

## Attack Complexity: `AC`

### `AC:H` High

Triggered by:

- `race condition`
- `specific timing`
- `unlikely conditions`
- `complex chain`
- `requires precise timing`

Example:

```text
The vulnerability requires precise timing to exploit the race condition.
```

Result:

```text
AC:H
```

### `AC:L` Low

Triggered by:

- `easily exploited`
- `straightforward`
- `simple to exploit`
- `no special conditions`

Example:

```text
The flaw is straightforward to exploit and requires no special conditions.
```

Result:

```text
AC:L
```

Fallback if no `AC` evidence is found:

```text
AC:L
```

## Privileges Required: `PR`

### `PR:N` None

Triggered by:

- `unauthenticated`
- `without authentication`
- `no authentication required`
- `anonymous attacker`

Example:

```text
An unauthenticated remote attacker can exploit this vulnerability.
```

Result:

```text
PR:N
```

### `PR:L` Low

Triggered by:

- `authenticated user`
- `valid account`
- `logged-in user`
- `requires authentication`
- `authorization: basic`
- `bearer token`

Example:

```text
An authenticated user with a valid account can submit the malicious request.
```

Result:

```text
PR:L
```

### `PR:H` High

Triggered by:

- `administrator only`
- `admin only`
- `root privileges required`
- `requires admin`

Example:

```text
Exploitation requires admin privileges.
```

Result:

```text
PR:H
```

Fallback if no `PR` evidence is found:

```text
PR:L
```

## User Interaction: `UI`

### `UI:N` None

Triggered by:

- `no user interaction`
- `without user interaction`
- `does not require user interaction`

Example:

```text
The vulnerability can be exploited without user interaction.
```

Result:

```text
UI:N
```

### `UI:R` Required

Triggered by:

- `user interaction required`
- `required user action`
- `click link`
- `open file`
- `social engineering`

Example:

```text
Exploitation requires the victim to open a crafted file.
```

Result:

```text
UI:R
```

Fallback if no `UI` evidence is found:

```text
UI:N
```

## Scope: `S`

### `S:C` Changed

Triggered by:

- `cross-tenant`
- `cross-repository`
- `across different repos`
- `one repo impacts another`
- `impacts resources in components beyond`

Example:

```text
A vulnerability in one tenant can impact resources in another tenant.
```

Result:

```text
S:C
```

### `S:U` Unchanged

Triggered by:

- `scope unchanged`
- `same security authority`

Example:

```text
The impact remains within the same security authority.
```

Result:

```text
S:U
```

Fallback if no `S` evidence is found:

```text
S:U
```

## Confidentiality: `C`

### `C:H` High

Triggered by:

- `information disclosure`
- `data leak`
- `read arbitrary`
- `confidential data`
- `confidentiality impact`

Example:

```text
The attacker can read arbitrary files containing confidential data.
```

Result:

```text
C:H
```

There are currently no direct rules for:

```text
C:L
C:N
```

Fallback if no `C` evidence is found:

```text
C:L
```

This means independent mode can infer low confidentiality impact when references are silent. Use strict mode when unsupported confidentiality impact should remain undetermined.

## Integrity: `I`

### `I:H` High

Triggered by:

- `maliciously overwritten`
- `tampered files`
- `tamper`
- `integrity impact`
- `modify arbitrary`
- `arbitrary write`
- `injecting backdoor`
- `supply-chain attack`
- `overwrite this file`

Example:

```text
An attacker can perform an arbitrary write and tamper with application files.
```

Result:

```text
I:H
```

### `I:L` Low

Triggered by:

- `partial integrity`
- `limited integrity impact`

Example:

```text
The issue results in limited integrity impact.
```

Result:

```text
I:L
```

There is currently no direct rule for:

```text
I:N
```

Fallback if no `I` evidence is found:

```text
I:L
```

## Availability: `A`

### `A:H` High

Triggered by:

- `denial of service`
- `dos`
- `service disruption`
- `crash`
- `availability impact`

Example:

```text
A crafted request can crash the service, causing denial of service.
```

Result:

```text
A:H
```

### `A:L` Low

Triggered by:

- `limited availability impact`
- `degraded availability`

Example:

```text
The issue may cause degraded availability.
```

Result:

```text
A:L
```

There is currently no direct rule for:

```text
A:N
```

Fallback if no `A` evidence is found:

```text
A:L
```

## Fallback Policy

Independent mode uses fallback defaults when no evidence supports a required metric:

```text
AV:L
AC:L
PR:L
UI:N
S:U
C:L
I:L
A:L
```

Fallback metrics are recorded in the response:

```json
{
  "evidence_quality": {
    "fallback_metrics": ["AC", "S", "C"]
  }
}
```

Strict mode does not apply fallback values. Unsupported metrics become undetermined, and no final vector or score is produced if any required metric is undetermined.

## Evidence Weighting

When multiple values match for the same metric, the scorer weights candidates and selects the strongest value.

Current weighting behavior:

- Each rule has a base confidence value, usually `1.0`, `0.9`, or `0.8`.
- Direct evidence is multiplied by `1.15`.
- Structured sources are multiplied by `1.10`.

Structured sources include CVE JSON descriptions and GitHub Security Advisory API responses.

Example:

```text
An unauthenticated remote attacker can exploit this issue.
```

This gives direct evidence for:

```text
AV:N
PR:N
```

## Boilerplate Filtering

The scorer skips snippets that look like generic CVSS help text rather than vulnerability-specific evidence.

Ignored patterns include:

- `learn more about base metrics cvss v3`
- `more severe when`
- `attack vector: more severe`
- `scope: more severe`
- `confidentiality: more severe`
- `integrity: more severe`
- `availability: more severe`

This helps avoid treating advisory UI boilerplate as evidence.

## Reference Fetch Guardrails

Reference fetching is intentionally bounded because CVE records can point to arbitrary external URLs.

Current guardrails:

- only `https` reference URLs are fetched
- hosts resolving to private, loopback, link-local, multicast, reserved, or unspecified addresses are blocked
- reference responses are capped at `1,000,000` bytes
- reference fetch failures are recorded in `reference_fetch_errors`

These controls reduce SSRF and resource-exhaustion risk, but they also mean some references may be skipped if they use `http`, redirect to blocked hosts, or return very large responses.

## Post-Inference Overrides

After initial inference, the scorer applies a small set of override rules.

### Privileges Required Override

If evidence contains authentication indicators, does not contain unauthenticated indicators, and `PR` was inferred as `N`, the scorer changes:

```text
PR:N -> PR:L
```

Authentication indicators include:

- `authenticated user`
- `valid account`
- `authorization: basic`
- `bearer ...`
- `logged-in`

Example:

```text
The PoC requires a logged-in user with a valid account.
```

### Attack Vector Override

If evidence contains network indicators, does not contain local-attacker indicators, and `AV` was inferred as `L`, the scorer changes:

```text
AV:L -> AV:N
```

Network indicators include:

- `http://`
- `https://`
- `api`
- `network`
- `remote`
- `tcp`

Example:

```text
The exploit is delivered through an HTTP API.
```

### Scope Override

If evidence contains cross-boundary indicators and `S` was inferred as `U`, the scorer changes:

```text
S:U -> S:C
```

Cross-boundary indicators include:

- `cross-repository`
- `across different repos`
- `one repo impacts another`
- `cross-tenant`

Example:

```text
A compromise in one tenant can affect another tenant.
```

## Example End-To-End

Reference text:

```text
An unauthenticated remote attacker can send a crafted HTTP request that crashes the service.
No user interaction is required.
```

Matched rules:

```text
remote / HTTP -> AV:N
unauthenticated -> PR:N
crash -> A:H
no user interaction -> UI:N
```

Fallbacks likely used:

```text
AC:L
S:U
C:L
I:L
```

Independent vector:

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H
```

Strict mode:

```text
No score, because AC, S, C, and I were not directly supported.
```

## Current Gaps

- `C` only has a direct rule for `H`; there are no direct `C:L` or `C:N` rules.
- `I` has rules for `H` and `L`; there is no direct `I:N` rule.
- `A` has rules for `H` and `L`; there is no direct `A:N` rule.
- `AC` uses limited phrase matching, and many advisories do not explicitly describe exploit complexity.
- `S:C` detection is narrow and mostly focused on tenant or repository boundary language.
- The fallback policy can infer low impact for `C`, `I`, or `A` when references are silent.

For higher-assurance analysis, review fallback-heavy results manually or use strict mode as the primary signal.
