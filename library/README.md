# HushSpec Vertical Policy Library

Curated, compliance-mapped HushSpec policies for regulated industries and common deployment scenarios. Each policy is a valid HushSpec document that can be used directly or extended via the `extends` field.

> **DISCLAIMER:** These policies are starting points, not certified compliance solutions. Organizations MUST review and customize each policy for their specific environment, threat model, and regulatory requirements. Engage qualified compliance professionals (HIPAA Privacy Officers, QSAs, 3PAOs, etc.) before deploying in production.

## Policies

| Policy | File | Compliance Framework | Description |
|--------|------|---------------------|-------------|
| HIPAA Base | `healthcare/hipaa-base.yaml` | HIPAA Security Rule (45 CFR 164.312) | PHI protection, restricted egress to health endpoints, clinical data pattern detection |
| SOC2 Base | `finance/soc2-base.yaml` | AICPA SOC2 Trust Services (CC6, CC7, CC8) | Access controls, change management, transmission security for SOC2-audited environments |
| PCI-DSS | `finance/pci-dss.yaml` | PCI-DSS v4.0 (Reqs 3, 4, 6, 7, 10) | Card number detection (Visa, MC, Amex, Discover), CVV/track data blocking, CDE path protection |
| FedRAMP Base | `government/fedramp-base.yaml` | NIST SP 800-53 Rev 5 (AC, AU, CM, SC) | .gov/.mil egress default, CUI path protection, minimal tool access |
| FERPA Student | `education/ferpa-student.yaml` | FERPA (34 CFR Part 99) | Student PII detection, education record path protection, approved LMS egress |
| CI/CD Hardened | `devops/cicd-hardened.yaml` | N/A (operational hardening) | Pipeline-safe egress (registries only), CI token detection, build/test tools only |
| Air-Gapped | `general/air-gapped.yaml` | N/A (maximum isolation) | Zero egress, zero shell, read-only tools |
| Recommended | `general/recommended.yaml` | N/A (production baseline) | Sensible defaults with broad secret detection and patch limits |

## Usage

### Direct use

Reference a library policy directly in your HushSpec document:

```yaml
hushspec: "0.1.0"
name: my-org-policy
extends: "library/healthcare/hipaa-base.yaml"
merge_strategy: deep_merge

rules:
  # Override or add rules specific to your organization
  egress:
    allow:
      - "api.my-ehr-vendor.com"
      - "*.my-org.com"
    default: block
```

### As a starting point

Copy a library policy and customize it:

```bash
cp library/finance/soc2-base.yaml my-policy.yaml
# Edit my-policy.yaml to match your control environment
hushspec validate my-policy.yaml
```

### Validation

All library policies pass the HushSpec validator:

```bash
cargo run -p hushspec-cli -- validate library/**/*.yaml
```

## Directory Structure

```
library/
  healthcare/
    hipaa-base.yaml           # HIPAA Security Rule compliance
  finance/
    soc2-base.yaml            # SOC2 Trust Services Criteria
    pci-dss.yaml              # PCI-DSS v4.0 payment data
  government/
    fedramp-base.yaml         # FedRAMP / NIST 800-53
  education/
    ferpa-student.yaml        # FERPA student data protection
  devops/
    cicd-hardened.yaml        # CI/CD pipeline hardening
  general/
    air-gapped.yaml           # Zero-network isolation
    recommended.yaml          # Production baseline
  README.md                   # This file
```

## Contribution Guidelines

When adding a new policy to the library:

1. **Valid HushSpec.** The policy MUST parse and validate successfully with `hushspec validate`.
2. **Comment headers.** Include a comment block at the top of the file with:
   - The compliance framework and specific control mappings
   - A disclaimer noting this is a starting point, not a certification
3. **Inline comments.** Map each rule block to specific compliance controls using YAML comments.
4. **Extends.** Use `extends: "builtin:default"` or `extends: "builtin:strict"` as the base unless the policy requires standalone operation.
5. **Realistic patterns.** Use practical, tested regex patterns. Avoid placeholders or overly broad patterns that produce excessive false positives.
6. **Focused scope.** Keep policies auditable. A single policy should address one compliance framework or deployment scenario, not try to cover everything.
7. **Test.** Run `cargo run -p hushspec-cli -- validate <your-file>` before submitting.

## Compliance Control Quick Reference

### HIPAA (45 CFR 164)
- 164.312(a)(1) -- Access Control (forbidden_paths, tool_access)
- 164.312(b) -- Audit Controls (forbidden_paths for audit logs)
- 164.312(c)(1) -- Integrity Controls (patch_integrity, secret_patterns)
- 164.312(e)(1) -- Transmission Security (egress)
- 164.514(b)(2) -- De-identification identifiers (secret_patterns)

### SOC2 Trust Services Criteria
- CC6.1 -- Logical Access Controls (forbidden_paths, secret_patterns)
- CC6.3 -- Restricted Access (tool_access, forbidden_paths)
- CC7.1 -- Detection of Changes (secret_patterns)
- CC7.2 -- Monitoring (egress to observability services)
- CC8.1 -- Change Management (patch_integrity)

### PCI-DSS v4.0
- Req 3.2 -- Do not store SAD after authorization (secret_patterns)
- Req 3.4 -- Render PAN unreadable (secret_patterns)
- Req 4.1 -- Strong cryptography for transmission (egress)
- Req 6.3 -- Security vulnerabilities in development (patch_integrity)
- Req 7.1 -- Restrict access to system components (tool_access, forbidden_paths)
- Req 10.2 -- Audit trail (shell_commands, forbidden_paths)

### NIST 800-53 (FedRAMP)
- AC -- Access Control (forbidden_paths, tool_access)
- AU -- Audit and Accountability (forbidden_paths for logs)
- CM -- Configuration Management (patch_integrity)
- SC -- System and Communications Protection (egress)

### FERPA (34 CFR 99)
- 99.3 -- Definition of education records and PII (secret_patterns)
- 99.30 -- Conditions for prior consent (patch_integrity)
- 99.31 -- Exceptions to prior consent (tool_access)
- 99.33 -- Limitations on redisclosure (egress)
