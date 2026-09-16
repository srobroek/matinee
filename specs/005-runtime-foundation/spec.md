# Feature Specification: Runtime Foundation

**Feature Branch**: `005-runtime-foundation`

**Created**: 2026-09-11

**Status**: Implemented

**Input**: Preserve Matinee's released CLI behavior while defining safe, deterministic
resolution of local configuration and runtime directories. Do not expose unfinished
product surfaces.

## Clarifications

### Session 2026-09-11

- Q: What should Matinee do with an unknown configuration key? → A: Reject the
  configuration before product-state mutation and identify only its redacted
  layer or source, never the key.

## User Scenarios & Testing

### User Story 1 - Preserve the Released CLI Baseline (Priority: P1)

A Matinee user runs a source build after contributors reorganize the runtime. The
documented `help`, `version`, and `doctor` behavior remains available. Before later
specifications land, Matinee does not expose daemon, MCP, extension, or workflow
commands.

**Why this priority**: The foundation replaces the program structure. It must preserve
the released behavior and must not present inert commands as working behavior.

**Independent Test**: Exercise the 0.0.2 help, version, and browser-detection journeys.
Compare their observable contracts with the released baseline.

**Acceptance Scenarios**:

1. **Given** the reorganized runtime, **When** a user requests help or version output,
   **Then** Matinee returns the released command set and package version through the
   same output channels and exit-code classes.
2. **Given** Firefox or Google Chrome at a released discovery location, **When** a user
   runs `doctor`, **Then** Matinee reports the detected browser as 0.0.2 does. This is
   detection-only compatibility; this feature does not automate or control Firefox.
3. **Given** no supported browser, **When** a user runs `doctor`, **Then** Matinee
   returns the released failure class and does not create product state.
4. **Given** a product surface assigned to a later specification, **When** a user asks
   for command help, **Then** Matinee does not advertise that surface.

---

### User Story 2 - Resolve Configuration Safely (Priority: P1)

A user combines Matinee defaults with user, project, environment, or command-line
configuration. Matinee applies the documented precedence, identifies each winning
source, and refuses lower-trust attempts to set protected values.

**Why this priority**: Later daemon and security work needs one configuration result
that cannot weaken local ownership or authorization rules.

**Independent Test**: Resolve every precedence pair and every protected setting from
each permitted and prohibited layer. Verify the result and source without writing
product state.

**Acceptance Scenarios**:

1. **Given** no overrides, **When** Matinee resolves configuration, **Then** every value
   comes from a documented default.
2. **Given** an allowed value in multiple layers, **When** Matinee resolves it, **Then**
   command-line, environment, project, user, and default values win in that order.
3. **Given** a protected value in project or environment configuration, **When**
   Matinee resolves configuration, **Then** it rejects that value and identifies its
   source.
4. **Given** resolved non-secret configuration, **When** a diagnostic caller requests
   provenance, **Then** each value names its winning layer without exposing a secret.

---

### User Story 3 - Isolate Local Runtime State (Priority: P2)

A user or test run selects a local state root without mixing files, locks, or endpoint
identities with another Matinee instance. Equivalent paths resolve to one root
identity, while distinct roots remain separate.

**Why this priority**: Daemon ownership cannot be correct until every process agrees
whether two paths identify the same local state.

**Independent Test**: Resolve platform directories and explicit state roots in
isolated temporary environments. Verify canonical identity, separation, and failure
behavior without creating product state.

**Acceptance Scenarios**:

1. **Given** no path overrides, **When** Matinee resolves its environment, **Then** it
   returns platform-appropriate config, state, runtime, cache, and log directories for
   the current user.
2. **Given** two distinct explicit state roots, **When** two instances resolve their
   environments, **Then** their state paths and lock identities do not overlap.
3. **Given** two path representations of the same state root, **When** Matinee resolves
   them, **Then** both produce the same root identity.
4. **Given** an invalid or inaccessible required directory, **When** Matinee resolves
   its environment, **Then** it returns a structured failure and creates no product
   state.
5. **Given** a project configuration path outside the selected project root, **When**
   Matinee resolves it, **Then** it rejects the path without reading that file.

### Edge Cases

- A platform directory environment variable is unset, empty, relative, or inaccessible.
- A project configuration path traverses a parent directory or symbolic link.
- Two configuration layers use different representations of the same path.
- A symbolic link makes two state roots refer to the same directory.
- The process has no home directory.
- The current directory disappears during resolution.
- A configuration file is unreadable, malformed, or changes during resolution.
- A configuration layer defines the same key twice.
- Any configuration layer contains an unknown key.
- A configuration file exceeds its byte, key, nesting, or text-value limit.
- Differently cased Windows environment names map to the same configuration key.
- A project configuration file changes identity while Matinee reads it.
- A future command is registered before its owning specification is complete.
- A syntactically pathological 1 MiB TOML file attempts to exceed key, nesting, or text limits before typed deserialization.
- Distinct canonical state-root identities could collide if a lock identity is truncated or hashed.
- An operating-system error, raw path, or rejected configuration value could reach a diagnostic field.
- A fixture descriptor classifies an otherwise well-typed value as secret material.

## Requirements

### Functional Requirements

- **FR-005-001**: Matinee MUST preserve the observable `help`, `version`, and `doctor`
  contracts released in Matinee 0.0.2.
- **FR-005-002**: Matinee MUST NOT expose a command, mode, tool, endpoint, or extension
  surface whose owning specification is not implemented.
- **FR-005-003**: Before any product-state mutation, Matinee MUST resolve one local
  runtime environment.
- **FR-005-004**: The resolved environment MUST provide platform-appropriate config,
  state, runtime, cache, and log directories for macOS, Linux, and Windows.
- **FR-005-005**: Ordinary configuration precedence MUST be defaults, user
  configuration, project configuration, environment variables, then command-line
  arguments.
- **FR-005-006**: Only user configuration or an explicit command-line argument MAY
  select the state directory, daemon endpoint, native principal, or development
  extension identity.
- **FR-005-007**: Project and environment configuration MUST NOT set protected values
  or weaken authentication, loopback binding, redaction, authorization, or approval
  requirements.
- **FR-005-008**: When a prohibited layer sets a protected value, Matinee MUST reject
  the configuration and identify the offending source.
- **FR-005-009**: The resolved environment MUST return a canonical path and winning
  source for each non-secret configuration value.
- **FR-005-010**: Equivalent canonical state roots MUST produce one root identity and
  the same lock identity. A lock identity MUST contain the exact canonical root identity,
  without hashing or truncation. Distinct root identities MUST therefore produce distinct,
  non-overlapping state paths and lock identities.
- **FR-005-011**: Matinee MUST reject a project configuration path that resolves
  outside the selected project root.
- **FR-005-012**: An invalid directory, unreadable configuration file, malformed value,
  duplicate key, or other resolution failure MUST return one closed structured failure
  before product-state mutation. The failure MUST contain only a stable code, a static
  safe summary, a redacted source, and a static safe next action; raw operating-system
  errors, raw paths, and input values MUST NOT enter any field.
- **FR-005-013**: CLI results MUST use standard output. Diagnostics MUST use standard
  error. Existing result classes MUST retain their 0.0.2 exit-code behavior.
- **FR-005-014**: A later specification MAY add a runtime mode only when that mode
  delivers every behavior advertised by its public surface.
- **FR-005-015**: Descriptor lookup MUST precede material-class, source-policy, and value
  validation. A key without a registered descriptor, including a reserved key before its
  owner registers it, MUST return `config.key_unknown` with a redacted layer or source
  before product-state mutation. Only a registered protected descriptor MAY return
  `config.source_forbidden`. The failure MUST NOT echo or otherwise identify the
  unaccepted key.
- **FR-005-016**: Matinee MUST validate an implicit project configuration path before
  reading the file and MUST reject a file whose identity changes during the read.
- **FR-005-017**: Each configuration file MUST be at most 1 MiB. Before typed TOML
  deserialization, a bounded TOML-aware lexical preflight MUST scan no more than those
  bytes and reject more than 100 assignments, more than four dotted-key segments, a text
  value longer than 4,096 Unicode scalar values, or a duplicate key. Exact-limit,
  one-over-limit, and syntactically pathological 1 MiB inputs MUST have deterministic
  outcomes.
- **FR-005-018**: Matinee MUST apply platform environment-name comparison before it
  maps names to keys. Two source names that map to one key MUST fail as a duplicate.
- **FR-005-019**: Diagnostic provenance and failures MUST use the closed safe projection
  defined by the configuration contract. Successful provenance MAY name accepted keys;
  user paths render relative to `~`, project paths relative to the project root, and
  environment and argument origins use accepted key names. A failure `source` MAY contain
  only a redacted file origin or fixed layer class and MUST never contain an unaccepted
  key token, raw absolute path, raw value, or operating-system error text. Built-ins render
  as `built-in`.
- **FR-005-020**: Every configuration key descriptor MUST declare one material class:
  `non_secret`, `opaque_secret_reference`, or `secret_material`. Spec 005 MUST accept only
  `non_secret` descriptors and MUST reject either other class with
  `config.secret_forbidden`. It MUST NOT guess whether arbitrary raw text is secret.
  Later specifications MAY admit opaque references but MUST NOT admit credential, private
  key, token, cookie, or browser-profile secret material through configuration.

### Key Entities

- **Resolved Environment**: Canonical local directories plus non-secret configuration
  and provenance.
- **Configuration Layer**: One ordered source of configuration values.
- **Protected Setting**: A non-secret value that only user configuration or an explicit
  command-line argument may select.
- **Material Class**: A descriptor-owned classification that distinguishes non-secret
  values, opaque secret references, and forbidden secret material without inspecting
  arbitrary value text heuristically.
- **Project Root**: The canonical directory that bounds project configuration.
- **State Root**: The canonical directory identity that scopes one future daemon and
  its durable state.
- **Root Identity**: The comparison value used to determine whether two state-root
  representations name the same root.

## Success Criteria

### Measurable Outcomes

- **SC-005-001**: Every released 0.0.2 help, version, and doctor acceptance scenario
  passes after the runtime reorganization.
- **SC-005-002**: A configuration matrix covering every layer, protected key, unknown
  key, descriptor material class, precedence pair, exact and one-over size limit,
  pathological 1 MiB input, and environment-name collision returns the expected value or
  rejection with the correct redacted source and no raw error or input disclosure.
- **SC-005-003**: Platform-path fixtures for macOS, Linux, and Windows resolve every
  required directory without consulting the host platform.
- **SC-005-004**: One hundred isolated environment-resolution runs use pairwise-disjoint
  state paths and exact, pairwise-distinct lock identities and leave no files outside
  their assigned temporary roots.
- **SC-005-005**: Every equivalent-path fixture produces one root identity and one lock
  identity, including relative, absolute, normalized, case-equivalent, and symbolic-link
  representations where the target platform treats them as equivalent.
- **SC-005-006**: Missing home directory, inaccessible directory, malformed or
  oversized configuration, duplicate or forbidden key, escaped project path, and changed
  file identity return the closed structured failure without raw error, path, or input
  disclosure and without product-state mutation.
- **SC-005-007**: The user-visible command list contains zero surfaces assigned to
  specs 006-016 until their implementations land.

## Assumptions

- Spec 001 remains the normative source for product terminology and external contract
  semantics.
- The constitution retains Rust 1.85 as the minimum supported version. The plan owns
  the concrete workspace and module design needed to meet that constraint.
- This specification does not create a stable public Rust library commitment.
- Spec 016 owns published packaging and end-to-end installation. This specification
  validates the released 0.0.2 CLI baseline.
- Later specifications can add runtime modes only when they deliver the complete
  behavior advertised by those modes.
- Retaining Firefox in `doctor` is detection-only compatibility with 0.0.2. Firefox automation and control remain outside this feature and the first complete release.
