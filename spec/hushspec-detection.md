# HushSpec Detection Extension Specification

**Version:** 0.1.0
**Status:** Draft
**Date:** 2026-03-15
**Companion to:** HushSpec Core v0.1.0

---

## 1. Overview

The Detection extension provides threshold configuration for content analysis guards: prompt injection detection, jailbreak detection, and threat intelligence screening. The actual detection algorithms are engine-specific -- this extension only declares thresholds, enablement flags, and resource limits.

Detection is declared under `extensions.detection` in a HushSpec document. When a conformant engine supports the detection extension, the declared thresholds govern when detection findings produce warnings or denials. Engines that do not support a particular detection capability SHOULD ignore the corresponding section and SHOULD document which detection capabilities they support.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### 1.2 Design Principle

This extension separates POLICY (thresholds, limits) from IMPLEMENTATION (algorithms, models). A HushSpec document with detection thresholds is portable across any engine that supports the detection extension, but the detection quality -- false positive rates, evasion resistance, latency -- depends entirely on the engine's implementation.

---

## 2. Schema

The detection extension is declared under `extensions.detection`:

```yaml
extensions:
  detection:
    prompt_injection:              # OPTIONAL. Prompt injection detection config.
      enabled: <bool>              # OPTIONAL. Default: true.
      warn_at_or_above: <level>    # OPTIONAL. Default: "suspicious".
      block_at_or_above: <level>   # OPTIONAL. Default: "high".
      max_scan_bytes: <integer>    # OPTIONAL. Default: 200000.
    jailbreak:                     # OPTIONAL. Jailbreak detection config.
      enabled: <bool>              # OPTIONAL. Default: true.
      block_threshold: <integer>   # OPTIONAL. Default: 80. Range: 0-100.
      warn_threshold: <integer>    # OPTIONAL. Default: 50. Range: 0-100.
      max_input_bytes: <integer>   # OPTIONAL. Default: 200000.
    threat_intel:                   # OPTIONAL. Threat intelligence screening.
      enabled: <bool>              # OPTIONAL. Default: false.
      pattern_db: <string>         # OPTIONAL. Path or "builtin:<name>".
      similarity_threshold: <number> # OPTIONAL. Default: 0.7. Range: 0.0-1.0.
      top_k: <integer>            # OPTIONAL. Default: 5.
```

All three subsections are independently optional. An empty `detection` object is valid and applies engine defaults for all subsections.

---

## 3. Prompt Injection Detection

The `prompt_injection` section configures detection of prompt injection attempts in agent inputs.

### 3.1 Fields

| Field               | Type    | Default        | Description                                          |
|---------------------|---------|----------------|------------------------------------------------------|
| `enabled`           | boolean | `true`         | Whether prompt injection detection is active.        |
| `warn_at_or_above`  | string  | `"suspicious"` | Minimum level that produces a warning.               |
| `block_at_or_above` | string  | `"high"`       | Minimum level that produces a denial.                |
| `max_scan_bytes`    | integer | `200000`       | Maximum input size to scan, in bytes.                |

### 3.2 Detection Levels

Detection levels form an ordered severity scale:

| Level        | Ordinal | Description                                      |
|--------------|---------|--------------------------------------------------|
| `safe`       | 0       | No injection detected.                           |
| `suspicious` | 1       | Possible injection, low confidence.              |
| `high`       | 2       | Probable injection, high confidence.             |
| `critical`   | 3       | Definite injection, very high confidence.        |

The ordering is: `safe` < `suspicious` < `high` < `critical`.

### 3.3 Threshold Semantics

When the engine's detection algorithm produces a level for a given input:
- If the level is >= `block_at_or_above`, the decision is **deny**.
- If the level is >= `warn_at_or_above` but < `block_at_or_above`, the decision is **warn**.
- Otherwise, the decision is **allow**.

### 3.4 Scan Limits

Inputs exceeding `max_scan_bytes` are truncated to that length before scanning. Engines MAY choose to deny inputs exceeding the scan limit instead of truncating; this behavior is engine-specific and MUST be documented.

---

## 4. Jailbreak Detection

The `jailbreak` section configures detection of jailbreak attempts (prompts designed to bypass the model's safety training).

### 4.1 Fields

| Field              | Type    | Default  | Description                                           |
|--------------------|---------|----------|-------------------------------------------------------|
| `enabled`          | boolean | `true`   | Whether jailbreak detection is active.                |
| `block_threshold`  | integer | `80`     | Risk score at or above which the input is denied.     |
| `warn_threshold`   | integer | `50`     | Risk score at or above which a warning is produced.   |
| `max_input_bytes`  | integer | `200000` | Maximum input size to scan, in bytes.                 |

### 4.2 Risk Score

The risk score is an integer in the range 0 to 100 inclusive, where 0 indicates no jailbreak risk and 100 indicates maximum risk. The score is produced by the engine's detection algorithm; this specification does not prescribe how the score is computed.

### 4.3 Threshold Semantics

When the engine produces a risk score for a given input:
- If the score is >= `block_threshold`, the decision is **deny**.
- If the score is >= `warn_threshold` but < `block_threshold`, the decision is **warn**.
- Otherwise, the decision is **allow**.

### 4.4 Scan Limits

The same truncation behavior as prompt injection (Section 3.4) applies, using `max_input_bytes`.

---

## 5. Threat Intelligence Screening

The `threat_intel` section configures threat intelligence pattern matching, where inputs are compared against a database of known threat patterns using similarity scoring.

### 5.1 Fields

| Field                  | Type   | Default | Description                                                 |
|------------------------|--------|---------|-------------------------------------------------------------|
| `enabled`              | boolean| `false` | Whether threat intelligence screening is active.            |
| `pattern_db`           | string | --      | Path to pattern database or `"builtin:<name>"`.             |
| `similarity_threshold` | number | `0.7`   | Minimum similarity score (0.0-1.0) to consider a match.    |
| `top_k`                | integer| `5`     | Number of top matches to return in evidence.                |

### 5.2 Pattern Database

The `pattern_db` field specifies the source of threat patterns:
- **File path:** A relative or absolute path to a JSON file containing pattern entries. Path resolution is engine-specific.
- **Built-in prefix:** A string starting with `"builtin:"` references an engine-bundled pattern database (e.g., `"builtin:s2bench-v1"`). Available built-in databases are engine-specific.

If `enabled` is `true` and `pattern_db` is absent, the engine SHOULD use its default pattern database if one exists, or SHOULD produce a warning and treat the section as disabled.

### 5.3 Similarity Threshold

The `similarity_threshold` value is a floating-point number between 0.0 and 1.0 inclusive. It represents the minimum similarity score (e.g., cosine similarity of embeddings) required for a pattern match to be considered a finding. Lower thresholds produce more matches (higher recall, lower precision); higher thresholds produce fewer matches (lower recall, higher precision).

The similarity computation method (cosine similarity, Jaccard index, edit distance normalization, etc.) is engine-specific.

### 5.4 Top K

The `top_k` value controls how many of the highest-scoring matches are included in the evaluation evidence. This does not affect the deny/allow decision -- it only controls the richness of the audit trail.

### 5.5 Decision Semantics

Threat intelligence screening produces a **deny** if any pattern match exceeds the `similarity_threshold`. If no match exceeds the threshold, the decision is **allow**. There is no intermediate **warn** level for threat intelligence; engines that wish to support warn-level threat intelligence findings MAY do so as an engine-specific extension.

---

## 6. Validation Requirements

Conformant validators MUST enforce the following:

1. **Level enum values.** `warn_at_or_above` and `block_at_or_above` MUST each be one of `"safe"`, `"suspicious"`, `"high"`, or `"critical"`. Invalid values MUST cause document rejection.

2. **Level ordering.** `block_at_or_above` SHOULD be >= `warn_at_or_above` (using the ordinal ordering in Section 3.2). Validators SHOULD produce a warning if this constraint is violated, but MUST NOT reject the document.

3. **Threshold ordering.** `block_threshold` SHOULD be >= `warn_threshold`. Validators SHOULD produce a warning if this constraint is violated, but MUST NOT reject the document.

4. **Threshold range.** `block_threshold` and `warn_threshold` MUST be integers in the range 0 to 100 inclusive. Values outside this range MUST cause document rejection.

5. **Similarity threshold range.** `similarity_threshold` MUST be a number between 0.0 and 1.0 inclusive. Values outside this range MUST cause document rejection.

6. **Top K value.** `top_k` MUST be a positive integer (>= 1). Zero or negative values MUST cause document rejection.

7. **Byte limits.** `max_scan_bytes` and `max_input_bytes` MUST be positive integers (>= 1). Zero or negative values MUST cause document rejection.

8. **Unknown fields.** Unknown fields within detection subsection objects MUST cause document rejection.

---

## 7. Note on Portability

A HushSpec document with detection thresholds is portable across engines that support the detection extension. However:

- **Detection quality varies.** An engine using a simple regex-based prompt injection detector will produce different results than one using a fine-tuned transformer model, even with identical threshold configuration.
- **Score calibration varies.** A `block_threshold` of 80 may be conservative on one engine and aggressive on another, depending on how the engine calibrates its risk scores.
- **Not all engines support all subsections.** An engine may support prompt injection detection but not threat intelligence screening. Engines MUST document which detection subsections they support.

Policy authors SHOULD test their detection thresholds against their target engine before deploying to production.

---

## 8. Merge Semantics

When a child document extends a base document that contains detection configuration, the following merge rules apply under `deep_merge` strategy:

### 8.1 Subsection Merge

Each detection subsection (`prompt_injection`, `jailbreak`, `threat_intel`) is merged independently. Within each subsection, child fields override base fields. Base fields not specified in the child are preserved.

### 8.2 Replace and Merge Strategies

Under `replace` strategy, the child's detection object entirely replaces the base's. Under `merge` strategy, the child's detection object entirely replaces the base's.

---

## Appendix A. Example

```yaml
hushspec: "0.1.0"
name: "detection-example"

extensions:
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: "suspicious"
      block_at_or_above: "high"
      max_scan_bytes: 500000

    jailbreak:
      enabled: true
      block_threshold: 85
      warn_threshold: 60
      max_input_bytes: 300000

    threat_intel:
      enabled: true
      pattern_db: "builtin:s2bench-v1"
      similarity_threshold: 0.75
      top_k: 10
```

## Appendix B. Minimal Detection Configuration

```yaml
hushspec: "0.1.0"

extensions:
  detection:
    prompt_injection:
      enabled: true
    jailbreak:
      enabled: true
```

This enables both detectors with engine defaults for all thresholds.
