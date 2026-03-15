# HushSpec Versioning Policy

**Applies to:** HushSpec Core and all extension modules
**Date:** 2026-03-15

---

## Specification Independence

HushSpec versioning is entirely independent of any engine, SDK, runtime, or implementation that consumes HushSpec documents. A security engine at version 5.0 may implement HushSpec 0.1.0. A CLI tool at version 0.3 may implement HushSpec 1.2.0. There is no coupling, implied or explicit, between specification version numbers and implementation version numbers.

The `hushspec` field in a document declares which version of the specification the document conforms to. Implementations declare which specification version(s) they support. These are separate concerns.

## v0.x: Unstable Development Series

The v0.x series (0.1.0, 0.2.0, etc.) is the initial development series. During this series:

- **Breaking changes between minor versions are permitted.** A document valid under 0.1.0 may be invalid under 0.2.0. Fields may be renamed, removed, or have their semantics changed.
- **Patch versions (0.1.0 to 0.1.1) are non-breaking.** Patch releases contain only clarifications, errata corrections, and editorial improvements that do not change document validity or evaluation semantics.
- **Implementations should pin to a specific minor version** and document which v0.x version(s) they support. Multi-version support is encouraged but not required.

The v0.x series exists to allow the specification to evolve rapidly based on implementation experience before committing to stability guarantees.

## v1.0+: Stable Series

Upon reaching v1.0.0, HushSpec commits to backward compatibility within each major version:

- **Minor versions (1.0 to 1.1, 1.2, etc.) are additive only.** New optional fields, new rule blocks, and new extension points may be introduced. Existing valid documents remain valid and retain their semantics. No existing field may be removed or have its meaning changed.
- **Patch versions (1.0.0 to 1.0.1) are non-breaking.** Clarifications and errata only.
- **Major versions (1.x to 2.0) may introduce breaking changes.** A new major version resets the compatibility contract. Documents valid under 1.x may require migration to conform to 2.0.

Implementations supporting v1.x MUST accept any valid v1.y document where y <= x (i.e., an implementation supporting 1.3 must accept documents declaring 1.0, 1.1, 1.2, or 1.3).

## Extension Module Versioning

Each extension module (`posture`, `origins`, `detection`) maintains its own independent version track. Extension versions are declared within the extension object in the document (e.g., `extensions.posture.version: "0.1.0"`).

- A core HushSpec version bump does not imply any extension version change.
- An extension version bump does not require a core HushSpec version change.
- Extension modules follow the same v0.x/v1.0+ stability rules described above, applied independently.

This independence allows extensions to evolve at their own pace. A stable core specification (v1.x) may coexist with experimental extensions (v0.x) without contradiction.
