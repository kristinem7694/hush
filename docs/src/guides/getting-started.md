# Getting Started

## Installation

### Rust

```bash
cargo add hushspec
```

### TypeScript / Node.js

```bash
npm install @hushspec/core
```

### Python

```bash
pip install hushspec
```

## Parsing a Document

### Rust

```rust
use hushspec::HushSpecDocument;

let yaml = std::fs::read_to_string("policy.yaml")?;
let doc = HushSpecDocument::from_yaml(&yaml)?;

println!("Policy: {}", doc.name.unwrap_or_default());
println!("Version: {}", doc.hushspec);
```

### TypeScript

```typescript
import { parseHushSpec } from "@hushspec/core";

const yaml = await fs.readFile("policy.yaml", "utf-8");
const doc = parseHushSpec(yaml);

console.log(`Policy: ${doc.name}`);
console.log(`Version: ${doc.hushspec}`);
```

### Python

```python
from hushspec import parse

with open("policy.yaml") as f:
    doc = parse(f.read())

print(f"Policy: {doc.name}")
print(f"Version: {doc.hushspec}")
```

## Validating a Document

All conformant parsers reject documents with unknown fields, missing `hushspec` version, or invalid field types. If `from_yaml` / `parseHushSpec` / `parse` returns successfully, the document is structurally valid.

```rust
// Rust: invalid documents produce errors, not silent misconfiguration
match HushSpecDocument::from_yaml(&yaml) {
    Ok(doc) => println!("Valid"),
    Err(e) => eprintln!("Rejected: {e}"),
}
```

## What Next

- [Write your first policy](first-policy.md)
- [Use HushSpec with Clawdstrike](clawdstrike.md)
- Read the [Rules Reference](../rules-reference.md)
