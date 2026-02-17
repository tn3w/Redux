---
name: readme-creator
description: Create high-quality, visually compelling GitHub README files that provide exceptional value to developers. Use when the user asks to create, improve, or rewrite a README.md file for a GitHub repository. Generates professional documentation with clear structure, working examples, and GitHub-supported visual formatting.
---

# README Creator

Create professional, developer-focused GitHub README files that balance visual appeal with information density. Generate documentation that helps developers quickly evaluate, install, and use the project.

## Core Principles

### Information Hierarchy

Structure content for three reader types:

1. **The Skimmer (5 seconds)**: Project name, one-line description, badges, quick links
2. **The Evaluator (30 seconds)**: Problem statement, key features, quick start example
3. **The Implementer (5+ minutes)**: Installation, detailed examples, configuration, API reference

### Visual Design

Use GitHub-supported formatting to create visual impact:

- **Badges**: shields.io badges for version, license, CI, downloads (consistent style)
- **HTML tables**: Side-by-side feature presentation
- **Centered headers**: `<h1 align="center">` for hero sections
- **Emojis**: Strategic use for section headers (✨ Features, 🚀 Quick Start, 💡 Examples)
- **Code blocks**: Always specify language for syntax highlighting
- **Collapsible sections**: `<details>` for advanced content

### Content Quality

- **Concise**: Every sentence must justify its existence
- **Accurate**: All code examples must work
- **Specific**: "40% faster" not "very fast"
- **Active voice**: "Provides type safety" not "Type safety is provided"
- **Developer-focused**: Technical accuracy over marketing speak

## README Structure

### Required Sections

**1. Hero Section**
```markdown
<h1 align="center">Project Name</h1>

<h3 align="center">Compelling one-line description</h3>
<p align="center">
  Additional value proposition
</p>

<p align="center">
  [Badges: version, license, CI, stars]
</p>

<p align="center">
  <a href="#quick-start">🚀 Quick Start</a> •
  <a href="#examples">💡 Examples</a> •
  <a href="docs-url">📚 Docs</a>
</p>
```

**2. Overview**

Answer "What is this?" and "Why should I care?" in 2-3 paragraphs:
- What the project does
- Who it's for
- Key value proposition and differentiator
- Common use cases

Include a minimal code example (5-10 lines) showing the core value.

**3. Features**

Present capabilities clearly:
- Use HTML tables for side-by-side presentation (2-column layout)
- Or categorized bullet lists with **bold** feature names
- Focus on user benefits, not implementation details
- Keep descriptions concise (one line per feature)

**4. Quick Start**

Get developers running code in under 60 seconds:
- Installation command
- Minimal working example (5-10 lines)
- Must be copy-pasteable
- Include output if helpful

**5. Examples**

Show real-world usage patterns:
- Start simple, progress to complex
- One concept per example
- Include comments for non-obvious parts
- Show error handling
- Organize with `###` subheadings

### Optional Sections (include when relevant)

**Feature Flags / Configuration**: For projects with optional features or extensive configuration

**Comparison Table**: When positioning against alternatives (be factual, not promotional)

**Performance**: For performance-critical projects (include specific metrics)

**Security**: For security-relevant projects (list security features and practices)

**Testing**: How to run tests

**Requirements**: System dependencies, language versions

**API Reference**: Brief table linking to detailed docs (full API docs belong elsewhere)

**Contributing**: Brief guidelines with link to CONTRIBUTING.md

**License**: License name with link to LICENSE file

## Writing Guidelines

### Code Examples

- Always specify language for syntax highlighting
- Test all examples before including
- Use comments to explain key concepts
- Keep examples focused (one concept per example)
- Show realistic usage, not toy examples
- Include error handling in non-trivial examples

### Technical Writing

- **Active voice**: "This library provides" not "This library is provided"
- **Present tense**: "Returns a result" not "Will return a result"
- **Specific claims**: "Reduces memory by 40%" not "Improves performance"
- **Consistent terminology**: Pick one term and stick with it
- **No marketing speak**: Avoid "revolutionary", "game-changing", "best-in-class"

### Formatting Conventions

- Commands and file paths: Use `code` formatting
- Technical terms: Use `code` on first mention
- Emphasis: Use **bold** for key concepts
- Lists: Use `-` for unordered, `1.` for ordered
- Headings: `##` for main sections, `###` for subsections (max 3 levels)

## Visual Patterns

### Badges

Use shields.io with consistent styling:

```markdown
![Version](https://img.shields.io/crates/v/package?style=for-the-badge&logo=rust&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)
![CI](https://img.shields.io/github/actions/workflow/status/user/repo/ci.yml?style=for-the-badge)
```

Common badge types: version, license, CI/CD, coverage, downloads, documentation

### Feature Grid

Use HTML tables for visual impact:

```markdown
<table>
<tr>
<td width="50%">

### Feature Category 1

Description and details

- Point 1
- Point 2

</td>
<td width="50%">

### Feature Category 2

Description and details

- Point 1
- Point 2

</td>
</tr>
</table>
```

### Section Headers with Emojis

Use strategically for visual hierarchy:
- ✨ Features
- 🚀 Quick Start / Installation
- 💡 Examples
- 📦 API Reference / Modules
- 🔒 Security
- ⚡ Performance
- 🛠️ Development / Requirements
- 🧪 Testing
- 📄 License
- 🤝 Contributing

## Language-Specific Patterns

### Rust

```markdown
## Installation

Add to `Cargo.toml`:
\`\`\`toml
[dependencies]
package-name = "1.0"
\`\`\`

Or via cargo:
\`\`\`bash
cargo add package-name
\`\`\`
```

### Python

```markdown
## Installation

\`\`\`bash
pip install package-name
\`\`\`

Or with poetry:
\`\`\`bash
poetry add package-name
\`\`\`
```

### JavaScript/TypeScript

```markdown
## Installation

\`\`\`bash
npm install package-name
\`\`\`

Or with yarn:
\`\`\`bash
yarn add package-name
\`\`\`
```

## Anti-Patterns to Avoid

**Content**:
- Marketing speak without substance
- Vague claims without evidence
- Outdated examples or version numbers
- Broken links
- Walls of text without structure
- Starting with installation before explaining what the project does

**Structure**:
- Deep nesting (more than 3 heading levels)
- Missing quick start for complex projects
- Examples before overview
- Duplicate information across sections

**Visual**:
- Excessive emojis (more than 1-2 per section)
- Inconsistent badge styling
- Overuse of bold/italic/code formatting
- Screenshots that quickly become outdated

## Workflow

1. **Understand the project**: Review code, dependencies, and existing docs
2. **Identify target audience**: Who will use this? What do they need to know?
3. **Structure content**: Organize by information hierarchy (skimmer → evaluator → implementer)
4. **Write sections**: Start with overview, then features, quick start, examples
5. **Add visual elements**: Badges, tables, emojis for hierarchy
6. **Test examples**: Verify all code examples work
7. **Review for conciseness**: Remove unnecessary words and sections

## Advanced Visual Patterns

### Badge Styles and Types

**Shield.io badge styles**: `flat`, `flat-square`, `plastic`, `for-the-badge`, `social`

**Common badge types**:
- Version: `crates/v`, `npm/v`, `pypi/v`, `github/v/release`
- License: `github/license`, `badge/license-{name}`
- CI/CD: `github/actions/workflow/status`
- Coverage: `codecov/c/github`
- Downloads: `crates/d`, `npm/dt`, `pypi/dm`
- Documentation: `docsrs/{crate}`, `badge/docs-passing`

Example with full styling:
```markdown
![Version](https://img.shields.io/crates/v/package-name?style=for-the-badge&logo=rust&logoColor=white&color=f74c00)
![CI](https://img.shields.io/github/actions/workflow/status/user/repo/ci.yml?style=for-the-badge&logo=github&logoColor=white&label=CI)
![Stars](https://img.shields.io/github/stars/user/repo?style=for-the-badge&logo=github&logoColor=white)
```

### ASCII Art Headers

For distinctive branding:
```markdown
     ____            _           _   
    |  _ \ _ __ ___ (_) ___  ___| |_ 
    | |_) | '__/ _ \| |/ _ \/ __| __|
    |  __/| | | (_) | |  __/ (__| |_ 
    |_|   |_|  \___// |\___|\___|\__|
                  |__/                
```

### Collapsible Sections

For detailed content that shouldn't clutter the main view:
```markdown
<details>
<summary>Click to expand: Advanced Configuration</summary>

Detailed content here...

</details>
```

### Comparison Tables

**Feature comparison**:
```markdown
| Feature | This Project | Alternative A | Alternative B |
|---------|--------------|---------------|---------------|
| Feature 1 | ✅ | ✅ | ❌ |
| Feature 2 | ✅ | ❌ | ✅ |
| Feature 3 | ✅ | ❌ | ❌ |
```

**Performance benchmarks**:
```markdown
| Operation | Time | Memory |
|-----------|------|--------|
| Parse 1MB | 12ms | 2.1MB |
| Query 10K | 45ms | 5.3MB |
```

### Navigation Patterns

**Table of contents** (for longer READMEs):
```markdown
## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Examples](#examples)
- [API Reference](#api-reference)
- [Contributing](#contributing)
```

**Quick links bar**:
```markdown
<p align="center">
  <a href="https://example.com">🌐 Website</a> •
  <a href="https://docs.example.com">📚 Docs</a> •
  <a href="#examples">💡 Examples</a> •
  <a href="#contributing">🤝 Contributing</a>
</p>
```

### Footer Patterns

**Centered footer**:
```markdown
<p align="center">
  <a href="link1">Link 1</a> •
  <a href="link2">Link 2</a> •
  <a href="link3">Link 3</a>
</p>

<p align="center">
  <sub>Built with ❤️ by the contributors</sub>
</p>
```

## Section Templates

### Overview Template

```markdown
## Overview

**[Project Name]** is [what it does] for [target audience]. It provides [key value proposition] while [key differentiator].

Whether you're [use case 1], [use case 2], or [use case 3] — [project name] gives you [benefit] with [advantage].
```

### Feature Flags / Configuration

```markdown
## Configuration

### Feature Flags

| Flag | Description | Default |
|------|-------------|---------|
| `feature1` | Description | Enabled |
| `feature2` | Description | Disabled |

### Custom Configuration

[Configuration examples]
```

### Security Section

```markdown
## 🔒 Security

- **Memory safety** — No unsafe code
- **Input validation** — Prevents injection attacks
- **Constant-time comparison** — For sensitive data
- **Audit trail** — All operations logged
```

### Performance Section

```markdown
## ⚡ Performance

- **Zero-copy parsing** — Efficient memory usage
- **Async-first** — Non-blocking I/O
- **Lazy evaluation** — Compute only what's needed
- **Connection pooling** — Reuse resources
```

### Requirements Section

```markdown
## 🛠️ Requirements

- **Language** version X.Y+
- **Runtime** (if applicable)
- **System dependencies** (if any)
- **Optional features** and their requirements
```

### Testing Section

```markdown
## Testing

\`\`\`bash
# Run tests
[test command]

# Run with coverage
[coverage command]

# Run integration tests
[integration test command]
\`\`\`
```

### Contributing Section

```markdown
## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.
```

### License Section

```markdown
## License

[License name] - see [LICENSE](LICENSE) file for details.

[Optional: Brief explanation of license choice]
```

## README Length Guidelines

- **Short (< 200 lines)**: Simple libraries with focused functionality
- **Medium (200-500 lines)**: Most libraries and frameworks with multiple features
- **Long (500-1000 lines)**: Complex frameworks with extensive configuration
- **Very Long (> 1000 lines)**: Avoid - move content to separate documentation

## Maintenance Checklist

**Keep updated**:
- Version numbers in examples
- Badge URLs and status
- Code examples (test them!)
- Links to external resources
- Screenshots and GIFs
- Dependency versions

**Regular review**:
- Quarterly: Review for accuracy
- On major releases: Update examples and features
- On breaking changes: Update migration guides
- On security issues: Update security section

**Deprecation notices**:
```markdown
> **⚠️ Deprecation Notice**: Feature X is deprecated as of version Y.Z. Use Feature A instead. See [migration guide](link) for details.
```
