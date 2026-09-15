# Critique Rerun 3: Configuration Classification Precedence

**Date**: 2026-09-12  
**Feature**: [spec.md](../spec.md)  
**Plan**: [plan.md](../plan.md)  
**Verdict**: PROCEED for this requirements-quality review

## Scope and evidence

This independent rerun checks the reserved-key classification change across `spec.md`,
`plan.md`, `contracts/configuration.md`, `data-model.md`, `quickstart.md`, and
`checklists/foundation.md`. It also checks the named runtime Beads contracts: T015
(`matinee-mol-hyr.3.6`), T021 (`matinee-mol-hyr.3.12`), TASK-SEC-007
(`matinee-mol-hyr.3.30`), T043 (`matinee-mol-hyr.2.6`), and T044
(`matinee-mol-hyr.2.7`). This review does not claim implementation completion or
validation evidence from the still-open implementation and acceptance tasks.

The parent prose gate supplied for this rerun passed with score 80.7/100, 0 errors,
165 warnings, 73 suggestions, and 4.556 warnings per 100 words. That aggregate is not
treated as evidence for the requirements; the artifact text and Beads acceptance
contracts are the evidence below.

## Reserved-key ambiguity and classification order

The order is explicit and consistent at every decision point:

1. **Requirements**: `spec.md:166-171` requires descriptor lookup before material-class,
   source-policy, and value validation. A missing descriptor, including a reserved key
   before its owner registers it, returns `config.key_unknown`, with a redacted layer or
   source and no key disclosure. Only a registered protected descriptor can return
   `config.source_forbidden`. `spec.md:189-194` separately defines the descriptor-owned
   material classes and rejects non-`non_secret` classes as `config.secret_forbidden`.
2. **Failure contract**: `contracts/configuration.md:43-65` keeps reserved keys unknown
   until their owners register descriptors, then states the order as descriptor presence,
   material class, source permission, and value validity. The failure table at
   `contracts/configuration.md:115-128` assigns stable, distinct codes: unknown keys
   (including reserved-unowned keys), forbidden sources for registered protected
   descriptors, invalid values after source authorization, and forbidden registered
   secret classes.
3. **Data model and state machine**: `data-model.md:30-42` gives unknown keys no
   implicit descriptor and makes material class descriptor-owned. The transition at
   `data-model.md:173-177` repeats the same first-failure order and explicitly names an
   unregistered reserved key as `config.key_unknown`; `data-model.md:181-189` prevents a
   failure from reaching merge and preserves the closed diagnostic projection.
4. **Plan order**: `plan.md:145-173` makes descriptors the only accepted-key/source
   registry, then orders preflight, typed parsing, descriptor lookup, material class,
   source permission, and value normalization. It separately places environment-name
   normalization before duplicate checks at `plan.md:168`, so it does not replace or
   reorder descriptor classification.
5. **Task acceptance**: T015 (`matinee-mol-hyr.3.6`) requires tests for a reserved-unowned
   key returning `config.key_unknown`, a registered protected descriptor returning
   `config.source_forbidden` only when its source is prohibited, and a registered
   secret-class descriptor returning `config.secret_forbidden`, with no partial state or
   key disclosure. T021 (`matinee-mol-hyr.3.12`) requires the same first-failure order in
   implementation before merge. TASK-SEC-007 (`matinee-mol-hyr.3.30`) requires exhaustive
   rendering cases for reserved-unowned, source-forbidden, and secret-forbidden inputs
   and the same non-disclosure/no-mutation invariants.
6. **Traceability**: T043 (`matinee-mol-hyr.2.6`) requires every FR/SC/security-control
   mapping to record the exact reserved-unowned versus registered-protected scenario and
   observed result, including `config.key_unknown` without key text. T044
   (`matinee-mol-hyr.2.7`) requires the eight security-control acceptance records to
   include those observable outcomes and the unknown-key non-disclosure case.

The quickstart command and matrix at `quickstart.md:25-37` cover precedence, protected
sources, duplicate and unknown keys, environment-name collisions, descriptor classes,
and malformed values. The exact reserved-unowned versus registered-protected split is
owned by the configuration contract and the T015/T021/TASK-SEC-007 cases rather than
being restated in the runbook summary; this is consistent and does not weaken the
acceptance contract.

## Layer precedence and environment-name normalization

Layer precedence remains the independent five-source order. `spec.md:138-148` and
`data-model.md:3-14` define default, user file, project file, environment, and command
line order, with protected settings selectable only from user file or command line and
project/environment attempts rejected when the descriptor is registered. The contract
table at `contracts/configuration.md:26-45` preserves the same source policy and the
reserved-unowned exception.

Environment-name normalization is a separate identity and duplicate check. The contract
at `contracts/configuration.md:22-24`, the requirement at `spec.md:180-181`, and the
plan at `plan.md:168` require native platform comparison before mapping environment
names to dotted keys and before duplicate rejection. The state machine performs that
identity check while locating, before file loading (`data-model.md:162-172`). No artifact
uses normalization to infer descriptor presence, material class, source permission, or
value validity. The two orders therefore remain distinct and uncontradicted.

## Checklist outcome

All four assigned criteria in `checklists/foundation.md` are satisfied and marked `[x]`:

- **CHK007 — `[x]` at line 22**: protected sources are fixed by `spec.md:141-148`,
  `contracts/configuration.md:26-52`, `data-model.md:30-40`, and the T015/T021 acceptance
  contracts. The built-in row is limited to a non-selecting default; registered protected
  descriptors accept only user file or command line, while unregistered reserved names
  remain unknown.
- **CHK008 — `[x]` at line 23**: stable failure codes and fail-all behavior are defined
  by `spec.md:157-192`, `contracts/configuration.md:85-86,115-143`, and
  `data-model.md:173-189`; T015, T021, and TASK-SEC-007 cover the classification and
  rendering cases.
- **CHK012 — `[x]` at line 27**: the closed descriptor material-class policy is defined
  by `spec.md:189-194`, `contracts/configuration.md:54-65`, and
  `data-model.md:26-40`; it rejects `opaque_secret_reference` and `secret_material`
  without raw-text heuristics, as required by T015/T021/TASK-SEC-007.
- **CHK023 — `[x]` at line 44**: the twenty functional requirements have user-story
  scenarios or measurable outcomes at `spec.md:36-104,130-194,216-235`, and T043 owns
  the exact command/scenario traceability record. T044 extends the record to all eight
  security controls.

The foundation checklist is **25/25 criteria passed**. The markers indicate
requirements quality, not implementation completion.

## Findings and workflow status

No actionable requirements or task-contract finding remains in the assigned scope. The
classification order closes the reserved-key ambiguity, and environment-name
normalization remains a separate pre-classification identity check.

The human gates `matinee-mol-bv9` (analyze approval) and `matinee-mol-tra`
(verify sign-off) remain open. This review does not resolve, close, or bypass either
human gate. Therefore the requirements verdict is **PROCEED**, while downstream workflow
execution remains **BLOCKED** until a human records both decisions with `bd gate resolve`.

**FINAL VERDICT: PROCEED** for the assigned critique and checklist gate; implementation
and downstream approval remain subject to the open human gates and to observed proof
recorded by T043/T044.
