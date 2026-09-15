# Critique Report: Runtime Foundation, Conductor Pass

**Date**: 2026-09-12

**Feature**: [spec.md](../spec.md)

**Plan**: [plan.md](../plan.md)

**Verdict**: PROCEED WITH UPDATES

## Scope and evidence

This is a fresh product-strategy and engineering-risk review after the decisions recorded on
`matinee-mol-wdh`, `matinee-mol-jn0`, and `matinee-mol-asq`. It reviewed `spec.md`,
`plan.md`, `research.md`, `data-model.md`, `contracts/configuration.md`, `quickstart.md`,
`checklists/requirements.md`, `checklists/foundation.md`, the constitution, the three
previous critique reports, and the current authoritative Beads graph. The deleted
`tasks.md` was not used.

The graph under `matinee-mol-hyr` has three direct implementation features and exactly 44
T001-T044 descendants:

- `matinee-mol-hyr.1`: Preserve released CLI in workspace (T001, T003, T007-T013).
- `matinee-mol-hyr.3`: Resolve local runtime environment (T002, T004-T006, T014-T037).
- `matinee-mol-hyr.2`: Prove runtime compatibility and acceptance (T038-T044).

The graph is authoritative for implementation readiness; the earlier closed
`matinee-mol-0mu` task-decomposition step and deleted `tasks.md` are historical only.

## Executive summary

The product boundary is sound. The slice preserves the released 0.0.2 CLI, keeps the new
resolver private, bounds local configuration, and exposes no unfinished daemon, MCP,
extension, or workflow surface. The five-layer source policy, platform path fixtures,
pre-read containment checks, post-read file snapshots, redacted provenance, Rust 1.85 gate,
and measured-baseline intent are all coherent after the approved decisions.

The artifacts and graph are not ready to proceed without updates. The authoritative graph
contains no task-level dependency edge beyond parent-child links, so the 44 tasks do not
encode the ordering required by the plan's parser, identity, integration, and acceptance
seams. Three security/evidence gaps remain in the current design and graph: parser limits
are not tied to a bounded pre-deserialization boundary, failure rendering is not a closed
redacted schema, and lock-identity uniqueness has no dedicated acceptance case. The
performance task records CLI startup but not the environment-resolution baseline promised
by the plan. The Firefox wording also needs an explicit detection-only boundary to avoid a
constitution conflict.

These are resolvable updates, not a request to redesign the feature. Proceed with updates
and re-run the critique/analysis gates before implementation assignment.

## Product lens findings

### Problem validation

**Pass.** The problem is a real foundation prerequisite rather than an exposed feature:
`spec.md:9-11` defines preservation of released behavior and safe local resolution;
`.specify/memory/roadmap.md:123-133` assigns this slice the shared executable layout,
configuration, directories, identifiers, and deterministic seams. The scope is bounded
against later specs and the plan makes no claim of installation, daemon behavior, or browser
control.

### User value assessment

**P1 — Must address: Firefox detection is not explicitly separated from Firefox automation.**

- **Evidence**: `spec.md:40-45` requires `doctor` to report Firefox and Chrome, while
  `spec.md:204-214` does not say that Firefox is detection-only. The constitution
  (`.specify/memory/constitution.md:76-79`) says the first release must not provide Firefox
  support. `checklists/foundation.md:15` (CHK003) asks the reviewer to verify this boundary
  but cites only User Story 1 and Assumptions, where the distinction is not stated.
  Beads `matinee-mol-hyr.1.4`/T008 and `.1.5`/T009 repeat the Firefox discovery behavior
  without an explicit no-automation condition.
- **Impact**: An implementer can preserve the legacy discovery row correctly yet infer that
  Firefox control is in scope, conflicting with the constitution and the roadmap's scope-out
  of browser operations (`.specify/memory/roadmap.md:129-132`).
- **Required update**: State in `spec.md` and the CHK003 citation that this feature retains
  only the released Firefox discovery/doctor row; it does not automate or control Firefox.
  Keep T008/T009 as discovery-only tests and prohibit a Firefox-control surface in T013.

### Alternative approaches

**Pass.** `research.md:16-28` compares the staged workspace with both an all-crates
placeholder layout and a retained monolith. `research.md:29-51` likewise compares a local
resolver with a general configuration framework. The selected private runtime seam is the
smallest approach that preserves future reuse without shipping placeholders.

### Edge cases and user experience

The specification covers missing home, inaccessible directories, path traversal and links,
changed files, malformed/duplicate/unknown/excessive input, Windows aliases, and no
mutation (`spec.md:104-118`, `spec.md:149-167`, `spec.md:186-202`). User-facing failures
have codes and safe next actions (`contracts/configuration.md:75-92`). However, the
failure-field redaction gap in E3 below means the user-facing error contract is not yet
safe for every failure path.

### Success measurement

**P2 — Recommendation: make the performance evidence and rollback trigger explicit.**
The plan says to record cold and warm environment-resolution and CLI startup baselines and
only choose a threshold after measured variance (`plan.md:32-34`), but it does not identify
the durable evidence format, repeat count, or decision owner for a regression. Add those
fields to the validation artifact and state what action follows a regression. E5 below is
the blocking task-coverage defect for the missing resolver measurement; this recommendation
covers the remaining measurement governance.

## Engineering lens findings

### Architecture soundness

**E1 — Must address: the 3-feature/44-task Beads graph has no task-level ordering.**

- **Evidence**: The current `bd list --all --json` graph has three direct children and 44
  T001-T044 descendants. Every descendant has only its parent-child dependency; there are
  zero non-parent task edges. The only feature-level edges are `.3` depends on `.1`, and
  `.2` depends on `.1` and `.3`. Representative tasks whose required order is absent are
  `matinee-mol-hyr.3.10`/T020 (bounded TOML reads), `.3.12`/T021 (unknown/depth/value/
  source/secret validation), `.3.13`/T022 (merge), `.3.16`/T025 (all-or-failure result),
  `.3.28`/T037 (integration), and `.2.6`/T043 (FR/SC traceability).
- **Impact**: Once the feature parents unblock, the graph permits sibling work that edits
  the same `config.rs`, `lib.rs`, and platform modules without an encoded prerequisite.
  T020/T021/T022/T025/T037 can be claimed without a graph edge proving the parser and
  descriptor seams exist; T043/T044 can be claimed without explicit links to every control.
  This weakens reproducibility and makes the intended Stage 1 -> Stage 2 -> Stage 3 ->
  Stage 4 sequence in `plan.md:142-184` advisory rather than enforced.
- **Required update**: Add explicit task dependencies (or split integration gates) for
  package/workspace setup before interfaces, interfaces before implementations,
  implementations before contract tests, and all implementation/security controls before
  T043/T044. Preserve the three feature ownership boundaries, but make the executable DAG
  match the plan's sequence.

**Architecture pass with E1 applied.** The private `matinee-runtime` boundary and one
platform adapter are coherent (`plan.md:120-140`), and the dependency direction is
acyclic. The risk is orchestration precision, not the selected architecture.

### Failure mode analysis

**E2 — Must address: numeric parser limits are not connected to a bounded parser boundary.**

- **Evidence**: `spec.md:159-161` and `contracts/configuration.md:63-73` specify 1 MiB,
  100 accepted keys, four dotted segments, and 4,096 Unicode scalar values; they only
  say the byte limit precedes parsing and the remaining limits precede merge. The state
  machine parses while loading and validates limits later (`data-model.md:133-138`).
  T020 (`matinee-mol-hyr.3.11`) promises bounded reads and duplicate detection before
  deserialization, while T021 (`.3.12`) assigns depth/value/unknown/secret rejection to a
  later task. Neither task defines the parser configuration or lexical preflight that
  prevents a pathological 1 MiB document from materializing excessive structure before
  rejection. The fresh security review corroborates this as SEC-001 in
  `security-review-plan-2026-09-12-conductor.md:137-179`.
- **Required update**: Add one shared enforcement contract: either a parser/loader with
  explicit total-entry, nesting, and scalar bounds, or a bounded lexical preflight before
  deserialization. Require exact-limit, one-over-limit, and pathological 1 MiB cases, and
  link T020/T021/T016/T043/T044 to that evidence.

**E3 — Must address: failure rendering does not have a closed redacted schema.**

- **Evidence**: `contracts/configuration.md:75-92` requires a code, summary, failed
  source, and safe next action; `data-model.md:141-148` redacts terminal provenance. No
  artifact says that an OS error string, raw path, or rejected secret must not enter the
  summary or next action. T004 (`matinee-mol-hyr.3.2`), T018 (`.3.9`), and T024 (`.3.15`)
  mention safe fields/projection but their acceptance text does not cover every failure
  renderer. The fresh security review corroborates this as SEC-002 in
  `security-review-plan-2026-09-12-conductor.md:181-215`.
- **Required update**: Define a closed failure shape of code, safe summary, redacted
  source, and safe next action; discard raw OS error text and raw input values. Add
  negative cases for unreadable, changed, escaped, oversized, malformed, duplicate,
  unknown, forbidden, and invalid inputs, and make T043/T044 record the results.

**Security/privacy pass with E4 and E6 below.** The approved threat model is coherent:
project files are untrusted, lower-trust layers cannot set protected keys, and an active
same-user replacement attacker is explicitly outside scope (`research.md:88-101`,
`data-model.md:103-116`). The remaining gaps are evidence and contract precision rather
than a claim of an implemented vulnerability.

### Security and privacy

**E4 — Must address: lock-identity uniqueness is an invariant without a dedicated test.**

- **Evidence**: `spec.md:143-146` requires equivalent state roots to converge and distinct
  roots to have non-overlapping state paths and lock identities. `data-model.md:69-90`
  repeats the invariant. T036 (`matinee-mol-hyr.3.27`) derives lock identities, but T030
  (`.3.21`) names 100-root isolation and zero mutation without asserting lock-ID
  uniqueness. `quickstart.md:35-43` lists roots, aliases, escapes, and replacement but
  not lock-ID collision behavior; T043 (`.2.6`) has no current lock-ID assertion. The fresh
  security review corroborates this as SEC-003 in
  `security-review-plan-2026-09-12-conductor.md:217-249`.
- **Required update**: Add a dedicated acceptance case that defines deterministic lock-ID
  construction from canonical root identity, proves alias convergence, and proves
  pairwise non-collision for distinct roots. Link T030/T036/T043 and confirm it in T044.

**E5 — Must address: the performance task omits the environment-resolution baseline.**

- **Evidence**: `plan.md:32-34` promises cold and warm baselines for both environment
  resolution and CLI startup. T041 (`matinee-mol-hyr.2.4`) is titled and described only as
  recording interleaved 0.0.2 and feature-branch cold/warm **startup** measurements. T042
  (`.2.5`) runs quickstart commands but does not promise timing evidence.
- **Impact**: The plan's performance gate cannot be evidenced from the authoritative graph;
  a passing T041 could omit the resolver path entirely.
- **Required update**: Expand T041 to record both resolver and CLI cold/warm measurements,
  interleaved baseline/branch runs, repeat counts, and variance. Then require T043 to map
  this evidence to the performance goal and state the threshold decision rule.

**E6 — Must address: secret-bearing configuration is prohibited but not objectively defined.**

- **Evidence**: `spec.md:166-167` prohibits credentials, private keys, tokens, cookies,
  and browser-profile secrets. `data-model.md:29-38` says a descriptor cannot accept
  those materials, and `contracts/configuration.md:43-46` says every source rejects them,
  but no descriptor registry, key-class rule, detector, or failure code defines how an
  arbitrary text value is classified. `config.value_invalid` (`contracts/configuration.md:
  82-87`) covers wrong type/normalization, not secret rejection. T021
  (`matinee-mol-hyr.3.12`) and T015 (`.3.6`) name secret rejection but do not define an
  objective oracle.
- **Impact**: Different implementers can accept the same secret-like value or reject
  ordinary configuration inconsistently, so CHK008 and CHK012 cannot be independently
  evaluated and the no-secret guarantee is not reproducible.
- **Required update**: Specify the closed policy for secret handling (for example, which
  descriptor/key classes are non-secret and which explicitly reject secret material), a
  stable failure code/source projection, and representative boundary cases. Tie T015/T021
  and T043/T044 to those cases. Do not rely on heuristic secret scanning without an
  explicit false-positive/false-negative policy.

### Performance and scalability

The 1 MiB/100-key/four-segment/4,096-scalar limits bound intended input, and the private
resolver avoids network or database scale concerns (`research.md:29-43`,
`contracts/configuration.md:63-73`). E2 and E5 are the remaining parser-boundary and
measurement gaps. A cache is not needed for this no-state slice.

### Testing strategy

The plan's table-driven matrices, injected platform adapter, filesystem fixtures, and
retained CLI cases are appropriate (`research.md:126-139`, `plan.md:142-184`). The graph
has explicit behavioral tasks for most edge cases, but E1 means their ordering and
integration contract is not encoded. E2, E3, E4, and E6 require negative and boundary
cases to be named in the task acceptance, not only in the prose artifacts.

### Operational readiness

**Recommendation R1:** This feature writes no product state and has no service rollout,
so blue-green deployment, alerting, and migration rollback are correctly out of scope.
Still, `plan.md:176-184` should name the rollback owner for a regression in the published
CLI package/workspace move and preserve the recorded 0.0.2 comparison artifact. This is a
release-process improvement, not a blocker to the resolver design.

### Dependencies and integration risks

**Recommendation R2:** `research.md:78-87` correctly notes that `directories` 6.0.0 has
no packaged MSRV declaration and `plan.md:178-180` requires an executable Rust 1.85 gate.
Add lockfile provenance and a license/advisory snapshot to T039's evidence so a future
dependency refresh cannot silently change the validated graph. The current Rust gate is
otherwise the right mitigation.

## Cross-lens synthesis

**X1 (linked to E1/E2/E3, no additional severity count):** The strongest product choice is
that users see no new command while contributors gain one reusable resolver. That same
choice makes the deep `resolve_environment` seam and its evidence graph the only safety
boundary for later daemon and MCP work (`plan.md:120-140`, `data-model.md:118-148`). An
under-specified task DAG or an unbounded/over-disclosing failure path therefore affects both
future user trust and implementation correctness. Add the sequencing and negative evidence
before exposing this seam to downstream specs.

## Foundation checklist evaluation

The independent-reviewer ownership correction is present at
`checklists/foundation.md:8,50`. The checklist itself remains intentionally unchecked;
that is not a defect, because the independent reviewer is the actor who must mark it after
this review. Every item was evaluated as follows:

| Item | Result | Evidence / finding |
|---|---|---|
| CHK001 | Pass | `spec.md:22-46,124-152`; `plan.md:144-150`; T007/T009/T013 |
| CHK002 | Pass | `spec.md:35-46,124-152`; `quickstart.md:8-23`; T007/T009 |
| CHK003 | **Gap** | Firefox discovery is named but detection-only/no-automation is not; P1 |
| CHK004 | Pass | `spec.md:126-127,153-154,201-202`; T013 |
| CHK005 | Pass | `spec.md:126-127,153-154`; `plan.md:120-128`; T013 |
| CHK006 | Pass | `spec.md:132-134`; `data-model.md:3-16`; T022 |
| CHK007 | Pass | `spec.md:135-142`; `contracts/configuration.md:26-46`; T015/T021 |
| CHK008 | **Partial** | Failure mapping exists, but secret classification is not objective; E2/E3/E6 |
| CHK009 | Pass | `spec.md:159-161`; `contracts/configuration.md:63-73`; T016 |
| CHK010 | Pass | `spec.md:162-163`; `contracts/configuration.md:22-24`; T017/T023 |
| CHK011 | **Partial** | Ordinary provenance is redacted, but all error fields are not closed; E3 |
| CHK012 | **Partial** | Prohibition is stated but secret-bearing-value oracle is unspecified; E6 |
| CHK013 | Pass | `research.md:88-101`; `data-model.md:69-90`; T032/T033 |
| CHK014 | **Partial** | Root convergence/isolation is measurable, but lock-ID uniqueness lacks a case; E4 |
| CHK015 | Pass | `spec.md:147-158`; `data-model.md:128-135`; T028/T034 |
| CHK016 | Pass | `spec.md:104-118`; `spec.md:186-200`; T027/T028/T034 |
| CHK017 | Pass | `spec.md:157-158`; `data-model.md:103-116`; T029/T035 |
| CHK018 | Pass | `research.md:94-97`; `data-model.md:113-116`; T035 |
| CHK019 | Pass | `spec.md:128-129,149-150`; `data-model.md:81-84,141-148`; T025/T030/T037 |
| CHK020 | Pass | `research.md:53-69`; `spec.md:130-131,191-193`; T026/T031 |
| CHK021 | Pass | `spec.md:104-118,149-150`; `contracts/configuration.md:75-92`; T030/T035 |
| CHK022 | **Partial** | Source and no-mutation requirements exist, but error-field redaction is incomplete; E3 |
| CHK023 | Pass (pending evidence) | `spec.md:124-167,186-202`; T043 owns the mapping |
| CHK024 | **Partial** | Numeric limits are objective, but parser-boundary and lock-ID proof are missing; E2/E4 |
| CHK025 | Pass in plan / task gap | `plan.md:32-34`; T041 omits resolver timing; E5 |

**Checklist result:** 18 items pass, 7 are partial/gaps. The only checklist-authoring
defect is CHK003's missing detection-only citation/boundary; the prior ownership defect is
fixed. The unchecked markers are an expected independent-reviewer state, not evidence that
requirements failed.

## Findings summary

| ID | Lens | Severity | Category | Finding | Required action |
|---|---|---|---|---|---|
| P1 | Product | Must address | User value / scope | Firefox detection vs Firefox automation is ambiguous against the constitution | State detection-only compatibility and prohibit Firefox control; repair CHK003 citation |
| E1 | Engineering | Must address | Architecture / task graph | Three features and 44 tasks have zero non-parent task dependencies | Add explicit sequencing/integration edges and gate T043/T044 |
| E2 | Engineering | Must address | Failure modes / resource bounds | Limits are not tied to a bounded pre-deserialization parser boundary | Define parser or lexical preflight and pathological boundary cases |
| E3 | Engineering | Must address | Security / diagnostics | Failure summaries and next actions are not guaranteed redacted | Define closed failure schema and negative disclosure tests |
| E4 | Engineering | Must address | Security / identity | Lock identity is an invariant without a dedicated acceptance case | Add deterministic lock-ID collision/convergence proof |
| E5 | Engineering | Must address | Performance / acceptance | T041 records startup only, not resolver cold/warm baselines promised by the plan | Expand T041 and map evidence in T043 |
| E6 | Engineering | Must address | Security / configuration | Secret-bearing value rejection lacks an objective classification/oracle | Define closed key/value policy and failure evidence |
| R1 | Engineering | Recommendation | Operational readiness | Workspace/package regression rollback ownership is not recorded | Name rollback owner and preserve comparison artifact |
| R2 | Engineering | Recommendation | Dependencies | T039 lacks lockfile provenance/license/advisory evidence | Record dependency graph and review metadata with Rust gate |

**Counts**: 7 must-address findings, 2 recommendations, 0 questions. Product: 1
must-address. Engineering: 6 must-address, 2 recommendations. Cross-lens: 0 additional
findings (X1 links the counted architecture and safety findings).

## Recommended next steps

1. Amend the spec/CHK003 boundary and encode the E1 graph dependencies without creating a
   replacement `tasks.md`.
2. Add explicit acceptance controls for E2, E3, E4, and E6; link them from the relevant
   implementation beads and T043/T044.
3. Expand T041 for resolver and CLI baselines; preserve the measured variance rule.
4. Have the independent reviewer mark the 18 passing foundation items only after recording
   this evidence and resolve the seven partial/gap items before closing the analysis gate.
5. Re-run `/speckit.critique` and the security-plan follow-up after artifact and Beads graph
   updates. No product/source implementation should begin until the must-address updates
   are resolved.
