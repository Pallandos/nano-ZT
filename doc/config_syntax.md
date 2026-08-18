# Policy Configuration Syntax Reference

This document describes the YAML configuration syntax for the **nano-ZT** policy engine (`internal/evaluator`). Policy configurations define Zero-Trust security rules, thresholds, inclusions, exclusions, and binary verification requirements evaluated against system collectors.

The policy file is located at `config/config.yml`.

---

## Structure Overview

The policy configuration uses a top-level `policy` key with three primary evaluation sections:

```yaml
policy:
  name: "Corporate Endpoint Zero-Trust Policy"
  version: "1.0"
  os_version: { ... }
  security: { ... }
  applications: [ ... ]
```

---

## 1. Operating System Policy (`os_version`)

Evaluates Windows OS version metrics returned by the `os_version` collector.

### Syntax & Field Definitions

| Field | Type | Description |
| :--- | :--- | :--- |
| `enabled` | `bool` | Enables or disables OS version evaluation. |
| `min_major` | `integer` | Minimum required Windows major version (e.g., `10`). |
| `min_minor` | `integer` | Minimum required Windows minor version (e.g., `0`). |
| `min_ubr` | `integer` | Minimum required Update Build Revision (UBR / security patch level). |
| `allowed_display_versions` | `list[string]` | Whitelist of accepted Windows commercial releases (e.g., `"22H2"`, `"23H2"`). |
| `excluded_builds` | `list[string]` | Blacklist of prohibited Windows build numbers (e.g., `"10240"`). |

### Example

```yaml
os_version:
  enabled: true
  min_major: 10
  min_minor: 0
  min_ubr: 1000
  allowed_display_versions:
    - "22H2"
    - "23H2"
    - "24H2"
  excluded_builds:
    - "10240"
    - "10586"
```

---

## 2. Security Providers Policy (`security`)

Evaluates Windows Security Center (WSC) status metrics for Antivirus (`antivirus`) and Firewall (`firewall`).

### Syntax & Field Definitions

| Field | Type | Description |
| :--- | :--- | :--- |
| `enabled` | `bool` | Enables or disables evaluation for the specified provider. |
| `require_healthy` | `bool` | Requires provider `IsHealthy` property to be `true`. |
| `allowed_statuses` | `list[string]` | Whitelist of accepted status codes (e.g., `["GOOD"]`). |
| `disallowed_statuses` | `list[string]` | Blacklist of prohibited status codes (e.g., `["POOR", "SNOOZE", "NOT_MONITORED"]`). |

### Example

```yaml
security:
  antivirus:
    enabled: true
    require_healthy: true
    allowed_statuses:
      - "GOOD"
    disallowed_statuses:
      - "POOR"
      - "SNOOZE"
      - "NOT_MONITORED"

  firewall:
    enabled: true
    require_healthy: true
    allowed_statuses:
      - "GOOD"
    disallowed_statuses:
      - "POOR"
      - "NOT_MONITORED"
```

---

## 3. Applications Policy (`applications`)

Evaluates installed software applications collected from the Windows Registry and executable binaries.

### Syntax & Field Definitions

| Field | Type | Description |
| :--- | :--- | :--- |
| `name` | `string` | Target application name (matched against `DisplayName`). |
| `enabled` | `bool` | Enables or disables evaluation for this specific application rule. |
| `disallowed` | `bool` | If `true`, the application is blacklisted and **must NOT** be installed. |
| `require_installed` | `bool` | If `true`, the application is mandatory and **MUST** be installed. |
| `min_version` | `string` | Minimum allowed version threshold (e.g., `"120.0.0.0"`). |
| `max_version` | `string` | Maximum allowed version threshold. |
| `exact_version` | `string` | Required exact version match. |
| `allowed_versions` | `list[string]` | Whitelist of allowed application versions. |
| `excluded_versions` | `list[string]` | Blacklist of banned or vulnerable application versions. |
| `expected_publisher` | `string` | Required publisher name (e.g., `"Google LLC"`). |
| `require_signed` | `bool` | If `true`, requires a valid Windows Authenticode digital signature on the binary. |
| `allowed_sha256` | `list[string]` | Whitelist of allowed SHA-256 binary checksums. |

### Example

```yaml
applications:
  # Mandatory application with minimum version and excluded vulnerable releases
  - name: "Google Chrome"
    enabled: true
    require_installed: true
    min_version: "120.0.0.0"
    excluded_versions:
      - "119.0.0.0"
      - "118.0.5993.70"
    expected_publisher: "Google LLC"
    require_signed: true

  # Mandatory security sensor
  - name: "CrowdStrike Falcon Sensor"
    enabled: true
    require_installed: true
    require_signed: true

  # Blacklisted application
  - name: "CCleaner"
    enabled: true
    disallowed: true
```

---

## Evaluation Results & Severity Levels

When evaluated by `internal/evaluator`, policy checks produce structured `Violation` objects categorized by severity:

- **`CRITICAL`**: Immediate security risk (e.g., prohibited software detected, disabled antivirus, blacklisted OS build, missing digital signature).
- **`HIGH`**: Non-compliant security baseline (e.g., mandatory app missing, version below minimum threshold, unallowed provider status).
- **`MEDIUM`**: Non-standard configuration (e.g., version above maximum threshold, non-whitelisted OS display version).
- **`LOW`**: Informational discrepancy.
