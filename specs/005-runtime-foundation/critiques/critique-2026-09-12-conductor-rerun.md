# Critique Rerun: Runtime Foundation

**Date**: 2026-09-12  
**Feature**: [spec.md](../spec.md)  
**Plan**: [plan.md](../plan.md)  
**Verdict**: PROCEED

## Scope and evidence

This is an independent product-strategy and engineering-risk rerun after remediation of P1,
E1-E6, and R1-R2. I reviewed `spec.md`, `plan.md`, `research.md`, `data-model.md`,
`contracts/configuration.md`, `quickstart.md`, both checklists, the constitution at
`.specify/memory/constitution.md`, prior critique and security reports, and the current
authoritative Beads graph. I did not use or recreate `tasks.md`; the graph under
`matinee-mol-hyr` is the task authority.

The scoped graph contains 50 Beads rows: the feature root, three implementation feature
children, and 47 task descendants covering T001-T044. It contains 74 blocking edges: three
feature-level edges and 71 task-level edges. `bd dep cycles --json` returned `[]`. The
feature-level order is runtime resolution after the released CLI feature, and compatibility
acceptance after runtime resolution and the CLI feature. The task-level edges now encode the
parser, identity, integration, and acceptance order rather than relying on prose alone.

The root is a `feature`, not an `epic` or `molecule`; therefore the molecule-only swarm
validator is not applicable. The direct dependency cycle check is the applicable graph
acyclicity evidence for this authoritative feature-rooted graph.

## Previous finding reconciliation

| Finding | Result | Evidence and verification |
|---|---|---|
| Prior P1 (upgrade/scope wording) | Closed | The user story now describes a source build after reorganization (`spec.md:22-32`); packaging and installation remain owned by spec 016 (`spec.md:230-241`). |
| P1 (Firefox boundary) | Closed | The doctor scenario says Firefox is detection-only and that this feature does not automate or control it (`spec.md:40-46`); the assumption repeats the boundary (`spec.md:241`). T013 (`matinee-mol-hyr.1.9`) excludes Firefox-control and browser-control surfaces. This satisfies Constitution II and the first-release Firefox constraint (`.specify/memory/constitution.md:20-27,76-86`). |
| E1 (task ordering) | Closed | The graph has 71 task-level blocking edges and no cycles. T003 (`matinee-mol-hyr.1.2`) is semantically placed under the runtime feature (`parent=matinee-mol-hyr.3`), depends on T002 (`.3.1`), and defines runtime environment types. Its opaque Beads suffix `.1.2` is not a task-number contract. The parser chain orders T019/T020/T021/T022, and the acceptance chain orders T041, T042, T043, and T044. T043 depends on T042 and TASK-SEC-006/007/008; T044 depends on T043 and its direct security/control cases. |
| E2 (bounded parser boundary) | Closed | The specification requires a byte-bounded TOML-aware preflight before typed deserialization and defines exact and one-over outcomes (`spec.md:169-174`). The contract repeats the scanner boundary and syntax forms (`contracts/configuration.md:74-98`); the data model requires counters and lexical state before deserialization (`data-model.md:124-135`). TASK-SEC-006 (`matinee-mol-hyr.3.29`) requires pathological, exact-limit, and one-over-limit proof, with no deserialization, merge, or product-state mutation. |
| E3 (closed redacted failure shape) | Closed | The contract defines exactly four public fields and excludes OS errors, paths, values, parser excerpts, and rejected secrets from every rendered field (`contracts/configuration.md:100-128`). The terminal model makes the same exclusion (`data-model.md:137-148,175-182`). TASK-SEC-007 (`matinee-mol-hyr.3.30`) covers unreadable, changed, escaped, oversized, malformed, duplicate, unknown, forbidden, limit, and invalid cases and requires the closed four-field result. |
| E4 (lock-identity acceptance) | Closed | The requirement and data model require exact canonical identity, alias convergence, and no hashing or truncation (`spec.md:148-153`; `data-model.md:85-95,97-107`). The quickstart names alias convergence and pairwise lock non-collision (`quickstart.md:39-49`). T030 (`matinee-mol-hyr.3.21`), T036 (`.3.27`), and TASK-SEC-008 (`.3.31`) require 100-root pairwise state-path and lock-identity distinction with no mutation. |
| E5 (resolver performance evidence) | Closed | The plan requires 30 interleaved CLI baseline/branch pairs and 30 cold/warm resolver runs, raw samples, median, p95, coefficient of variation, and an evidence-based threshold (`plan.md:34-39`). T041 (`matinee-mol-hyr.2.4`) explicitly records both CLI and environment-resolution measurements and requires repeat counts, samples, variance, decision owner, and rollback/blocking outcome. T043 (`.2.6`) maps the performance decision into `validation.md`. |
| E6 (secret classification oracle) | Closed | The descriptor owns one of three material classes; production accepts only `non_secret`, while fixture `opaque_secret_reference` and `secret_material` descriptors fail with `config.secret_forbidden` without raw-text heuristics (`data-model.md:16-42`; `contracts/configuration.md:47-58`; `spec.md:182-187`). T019 (`matinee-mol-hyr.3.10`) defines the registry and T015/T021 (`.3.6`, `.3.12`) require distinct descriptor-class failures and non-heuristic behavior. |
| R1 (rollback ownership) | Closed | Stage 4 requires preserving the 0.0.2 comparison artifact and says the release owner blocks publication and reverts the workspace/package move on regression or absent accepted threshold (`plan.md:187-205`). |
| R2 (dependency provenance) | Closed | T039 (`matinee-mol-hyr.2.2`) requires a locked Rust 1.85 build and records the `Cargo.lock` checksum, locked dependency tree, declared licenses, and advisory scan output. Its acceptance requires actionable provenance in `validation.md`. This complements the MSRV caveat in `research.md:78-86`. |

No previous must-address finding remains open. The prior P2 performance recommendation is
covered by the same plan/T041 evidence. The prior X1 cross-lens observation is addressed by
the private runtime seam, no-placeholder rule, and graph sequencing (`plan.md:127-148`).

## Product-strategy review

### Problem and boundary

**Pass.** The feature is a foundation slice, not a new user-visible product mode. It preserves
the released CLI and resolves a safe local environment before product-state mutation
(`spec.md:9-11,125-187`). The plan keeps only the published CLI and private runtime crate,
explicitly defers later crates and behavior, and preserves spec 001 product contracts
(`plan.md:100-135`). The constitution's local-state, least-privilege, and observable-contract
obligations are represented in the requirements (`.specify/memory/constitution.md:29-66`).

### User value and compatibility

**Pass.** The three user stories have independent tests and observable acceptance scenarios
(`spec.md:20-103`). The released help/version/doctor surface, output streams, and exit classes
are explicit (`spec.md:129-162`; `quickstart.md:8-23`). Firefox is explicitly detection-only,
so retaining the released doctor row does not silently expand browser ownership.

### Alternatives and scope discipline

**Pass.** The research compares a staged workspace with both empty final crates and a retained
monolith, and compares a local resolver with a general configuration framework
(`research.md:3-51`). It rejects placeholder crates and preserves one private environment
interface. No later command, endpoint, extension, or workflow surface is advertised before
its owning specification is complete (`spec.md:131-145,163-164,227-241`).

### Edge cases and user-facing failure behavior

**Pass.** The edge-case inventory covers missing home, inaccessible directories, links,
traversal, aliases, file replacement, malformed/duplicate/unknown/excessive inputs,
Windows name collisions, pathological TOML, lock collisions, and disclosure
(`spec.md:105-123`). The closed failure contract gives a stable code, static summary,
redacted source, and static next action without returning a partial environment
(`contracts/configuration.md:60-72,100-128`).

### Success measurement

**Pass.** SC-005-001 through SC-005-007 cover released behavior, configuration policy,
platform fixtures, isolation, equivalence/non-collision, failure containment, and public
surface containment (`spec.md:205-228`). Performance evidence now has repeat counts, raw
samples, variance, owner, and a block/rollback rule (`plan.md:34-39,195-205`; T041).

## Engineering-risk review

### Architecture and sequencing

**Pass.** The dependency direction is explicit: runtime depends on its focused host and
configuration dependencies; CLI depends on runtime; runtime does not depend on CLI or later
product crates (`plan.md:137-148`). The current graph preserves that boundary and encodes
ordering through 71 task-level edges. T003 is correctly owned by the runtime feature and
follows T002; no task contract depends on the deleted `tasks.md`.

### Configuration and parser safety

**Pass pending implementation proof.** The requirements now connect byte, assignment, dotted
segment, and scalar limits to a bounded lexical preflight before typed deserialization and
merge (`spec.md:169-174`; `data-model.md:124-135`). TASK-SEC-006 and T016/T020 carry exact,
one-over, and pathological cases. This is requirements/task evidence, not a claim that the
implementation already exists; all implementation beads remain open.

### Identity, containment, and race boundary

**Pass pending implementation proof.** The identity algorithm uses an existing filesystem
anchor and platform comparison behavior (`research.md:88-101`; `data-model.md:73-95`).
Containment and link type are checked before opening the implicit project file, and snapshots
are checked after reading (`data-model.md:109-122,160-172`; `contracts/configuration.md:14-17`).
The same-user replacement race is explicitly outside the local threat model, consistently in
research and data model (`research.md:94-97`; `data-model.md:119-122`).

### Diagnostics, secrets, and no mutation

**Pass pending implementation proof.** Descriptor-owned material classes make secret handling
objective and fail closed (`data-model.md:30-42`). Every terminal outcome is resolved or one
closed failure, with no product-state mutation and no raw disclosure (`data-model.md:173-182`).
TASK-SEC-007 and T044 require negative evidence for all named failure families and all eight
security controls.

### Portability and dependency risk

**Pass pending implementation proof.** Platform directory outcomes are specified for macOS,
Linux, and Windows and can be tested through injected fixtures (`research.md:53-69`;
`quickstart.md:39-60`). The Rust 1.85 gate covers direct and transitive dependencies, while
T039 records lockfile, license, and advisory provenance (`plan.md:187-205`; T038/T039).

## Foundation checklist evaluation

Every criterion was evaluated against its cited requirement text. Markers in
`checklists/foundation.md` mean requirements quality only, not implementation completion.

| Item | Result | Evidence |
|---|---|---|
| CHK001 | Pass | `spec.md:22-46,125-153`; `plan.md:151-158`; T007-T013 |
| CHK002 | Pass | `spec.md:129-162`; `quickstart.md:8-23`; T007/T009 |
| CHK003 | Pass | `spec.md:40-46,241`; T013 |
| CHK004 | Pass | `spec.md:131-132,163-164`; T013 |
| CHK005 | Pass | `spec.md:131-132,227-241`; `plan.md:127-135` |
| CHK006 | Pass | `spec.md:137-139`; `data-model.md:3-14`; T022 |
| CHK007 | Pass | `spec.md:140-147`; `contracts/configuration.md:26-45`; T015/T021 |
| CHK008 | Pass | `spec.md:146-187`; `contracts/configuration.md:100-128`; T015/T016/T020/T021/T025 |
| CHK009 | Pass | `spec.md:169-174`; `contracts/configuration.md:74-98`; `data-model.md:124-135`; TASK-SEC-006 |
| CHK010 | Pass | `spec.md:175-176`; `contracts/configuration.md:22-24`; T017/T023 |
| CHK011 | Pass | `spec.md:156-160,177-181`; `data-model.md:137-148,175-182`; TASK-SEC-007 |
| CHK012 | Pass | `spec.md:182-187`; `contracts/configuration.md:47-58`; T015/T019/T021 |
| CHK013 | Pass | `research.md:88-101`; `data-model.md:73-95` |
| CHK014 | Pass | `spec.md:148-153,217-222`; `quickstart.md:45-49`; T030/T036/TASK-SEC-008 |
| CHK015 | Pass | `spec.md:154-168`; `data-model.md:160-172`; T028/T034 |
| CHK016 | Pass | `spec.md:105-123`; `spec.md:217-222`; T027/T028/T034 |
| CHK017 | Pass | `spec.md:167-168,223-226`; `data-model.md:109-122`; T029/T035 |
| CHK018 | Pass | `research.md:94-97`; `data-model.md:119-122`; T035 |
| CHK019 | Pass | `spec.md:133-134,217-226`; `data-model.md:85-88,173-182`; T025/T030/T037 |
| CHK020 | Pass | `research.md:53-69`; `spec.md:135-136,215-216`; T026/T031 |
| CHK021 | Pass | `spec.md:105-118,156-160,223-226`; `contracts/configuration.md:100-116`; T030/T035 |
| CHK022 | Pass | `spec.md:146-160,177-181`; `data-model.md:137-148,173-182`; TASK-SEC-007 |
| CHK023 | Pass | `spec.md:125-187,205-228`; T043 |
| CHK024 | Pass | `spec.md:169-174,217-226`; `quickstart.md:31-49`; T016/T030/TASK-SEC-006/TASK-SEC-008 |
| CHK025 | Pass | `plan.md:34-39,195-205`; T041/T043 |

**Checklist result: 25 pass, 0 partial/gap, 25 total.** The markers in
`checklists/foundation.md:13-46` match this evidence. The requirements checklist remains a
separate earlier gate and its markers are not implementation evidence.

## Prose and document-quality judgement

The parent-supplied `uvx slopvac ... --profile normal --format json` run passed with score
80.0/100, 0 errors, 169 warnings, 76 suggestions, 4.73 warnings per 100 words, and no
unchecked rules. Those warning and suggestion classes are advisory pattern candidates; they
do not override the cited requirement or Beads evidence. No mechanical error or unchecked
rule creates a material requirements defect.

**Register**: The artifacts read as internal specification, plan, contract, research, and
acceptance prose. Their heading outlines are coherent: scope and stories precede requirements,
requirements precede data/contracts, and plan stages precede acceptance evidence. The plan's
pre-design/post-design constitution sections are symmetric, and the research entries pair
decisions with rationale and alternatives.

**Unsupported status claim**: `spec.md:7` still says `Status: Ready for planning`, although
`plan.md` exists and the authoritative graph has 47 implementation tasks. This is a stale
workflow label, not a product requirement defect. Exact remediation: after the human gates
resolve, change the status to the repository's approved implementation-ready state (or retain
the label only if the project intentionally defines it as a pre-implementation status).

**Deletable passages and weakest claim**: No normative paragraph can be deleted without
removing a boundary, invariant, acceptance condition, or rationale. The weakest claim is the
stale status label above because it can mislead a contributor about workflow state. No other
material claim is unsupported by the reviewed artifacts.

**Prose verdict**:

```text
VERDICT: PASS
Gate:     score 80.0/100 - 0 errors, 169 warnings, 4.73/100w (parent-supplied run)
Register: internal specification and implementation-plan prose with a coherent outline
Claims:   requirements and graph claims are supported; spec.md:7 has a stale workflow status
Action:   update the workflow status after human-gate resolution
False positives: none asserted; the supplied aggregate did not include warning spans
```

## Remaining recommendations

### R3 — Refresh the specification workflow status (non-blocking)

At `spec.md:7`, replace `Ready for planning` with the repository's approved status for a
planned feature awaiting human approval/implementation, once the human gates permit that
transition. Do not change the requirement content as part of this wording cleanup.

## Findings summary and final verdict

| Metric | Count |
|---|---:|
| Must-address findings | 0 |
| Recommendations | 1 (R3) |
| Questions | 0 |
| Checklist criteria passed | 25/25 |
| Task descendants | 47 (T001-T044) |
| Task-level blocking edges | 71 |
| Dependency cycles | 0 |

The amended artifacts and authoritative graph resolve P1, E1-E6, R1, and R2. The one
remaining recommendation is workflow-status alignment and does not undermine the
requirements, safety boundaries, sequencing, or acceptance evidence.

**FINAL VERDICT: PROCEED** (implementation remains subject to the open human gates and to
behavioral proof in the implementation and acceptance tasks; this report does not claim those
tasks are complete).
