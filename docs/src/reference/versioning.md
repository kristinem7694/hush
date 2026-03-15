# Versioning

The full versioning policy is at [`spec/versioning.md`](https://github.com/backbay-labs/hush/blob/main/spec/versioning.md).

## Summary

HushSpec uses Semantic Versioning (SemVer 2.0.0). The specification version is independent of any engine or SDK version.

### v0.x: Unstable

The current series. Breaking changes are permitted between minor versions (e.g., 0.1.0 to 0.2.0). Patch versions (0.1.0 to 0.1.1) contain only clarifications and errata.

Implementations should pin to a specific minor version and document which v0.x version(s) they support.

### v1.0+: Stable

Upon reaching v1.0.0, backward compatibility is guaranteed within each major version:

- **Minor versions** (1.1, 1.2, ...) add new optional fields and rule blocks. Existing documents remain valid.
- **Patch versions** (1.0.1, 1.0.2, ...) contain clarifications and errata only.
- **Major versions** (2.0) may introduce breaking changes.

### Extension Module Versioning

Each extension (`posture`, `origins`, `detection`) maintains its own independent version track. A core version bump does not imply an extension version change, and vice versa. Extensions follow the same v0.x/v1.0+ stability rules independently.

## Current Version

HushSpec Core: **v0.1.0** (Draft)

Extension modules: **v0.1.0** (Draft)
