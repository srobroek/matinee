# Foundation Requirements Checklist: Runtime Foundation

**Purpose**: Test whether the 005 requirements are complete, clear, consistent, and measurable across every approved foundation boundary.
**Created**: 2026-09-12
**Feature**: [spec.md](../spec.md)

**Note**: This checklist evaluates requirements quality, not implementation behavior.
**Review Ownership**: An independent reviewer owns this requirements-quality gate. Mark an item `[x]` only after reviewing the cited requirement text.
**Marker Semantics**: `[x]` means the requirements-quality criterion is satisfied. It does not mean implementation is complete.

## Scope and compatibility

- [x] CHK001 Is the complete released 0.0.2 CLI compatibility surface identified without implying new commands? [Completeness, Spec §FR-005-001--002]
- [x] CHK002 Are help, version, doctor success, doctor failure, invalid input, output streams, and exit classes covered by measurable requirements? [Coverage, Spec §FR-005-001, §FR-005-013]
- [x] CHK003 Is released Firefox detection explicitly limited to detection-only compatibility, with Firefox automation and control deferred? [Clarity, Spec §User Story 1 scenario 2, §Assumptions]
- [x] CHK004 Are later runtime modes prohibited until their complete advertised behavior is specified and implemented? [Consistency, Spec §FR-005-002, §FR-005-014]
- [x] CHK005 Is the boundary between spec 005 and specs 006--016 explicit enough to prevent placeholder surfaces? [Coverage, Spec §FR-005-002, §SC-005-007]

## Configuration trust and limits

- [x] CHK006 Is the precedence of all five configuration layers stated in one unambiguous order? [Clarity, Spec §FR-005-005]
- [x] CHK007 Are the permitted sources for every protected-setting class defined without contradiction? [Consistency, Spec §FR-005-006--008]
- [x] CHK008 Are unknown, duplicate, malformed, excessive, secret-class, and source-forbidden inputs assigned stable failure codes and closed fail-all behavior? [Completeness, Spec §FR-005-008, §FR-005-012, §FR-005-015, §FR-005-017, §FR-005-020; Contract §Failure codes]
- [x] CHK009 Are byte, assignment-count, key-depth, and text-length boundaries numerically defined and enforced by a bounded lexical preflight before typed deserialization? [Measurability, Spec §FR-005-017; Contract §Resource limits]
- [x] CHK010 Is Windows environment-name identity defined before mapping names to configuration keys? [Clarity, Spec §FR-005-018]
- [x] CHK011 Are all diagnostic fields closed to static templates or redacted sources, with raw paths, values, parser excerpts, and operating-system errors excluded? [Coverage, Spec §FR-005-012, §FR-005-019; Contract §Failure codes]
- [x] CHK012 Does a closed descriptor material-class policy reject secret material and opaque references without heuristic raw-text scanning? [Security, Spec §FR-005-020; Contract §Source policy]

## Path identity and filesystem safety

- [x] CHK013 Is canonical state-root equivalence distinguished from ordinary normalized path text? [Clarity, Spec §FR-005-009--010]
- [x] CHK014 Are equivalent and distinct roots assigned measurable root-identity, state-path, and exact lock-identity convergence or non-collision outcomes? [Measurability, Spec §FR-005-010, §SC-005-004--005]
- [x] CHK015 Is project-root containment required before reading project configuration? [Security, Spec §FR-005-011, §FR-005-016]
- [x] CHK016 Are symbolic-link, path-traversal, alias, case-equivalence, and nonexistent-descendant scenarios addressed? [Coverage, Spec §Edge Cases, §SC-005-005]
- [x] CHK017 Is project-file replacement during a read assigned an explicit rejection outcome? [Recovery, Spec §FR-005-016, §SC-005-006]
- [x] CHK018 Is the residual malicious same-user process threat boundary documented consistently with the approved local threat model? [Assumption, Plan §research.md]
- [x] CHK019 Is no-mutation behavior required for every success and failure path during environment resolution? [Consistency, Spec §FR-005-003, §SC-005-004, §SC-005-006]

## Portability, failures, and acceptance

- [x] CHK020 Are macOS, Linux, and Windows directory outcomes defined independently of the host running the tests? [Portability, Spec §FR-005-004, §SC-005-003]
- [x] CHK021 Are missing home, inaccessible directory, unreadable file, malformed input, and changed identity covered as distinct failure classes? [Exception Coverage, Spec §FR-005-012, §SC-005-006]
- [x] CHK022 Does each structured failure requirement identify a redacted source, prohibit raw disclosure, and require absence of product-state mutation? [Clarity, Spec §FR-005-008, §FR-005-012, §FR-005-015, §FR-005-019]
- [x] CHK023 Are all 20 functional requirements covered by an acceptance scenario or measurable outcome? [Traceability, Spec §FR-005-001--020, §SC-005-001--007]
- [x] CHK024 Do exact-limit, one-over-limit, pathological 1 MiB, 100-run isolation, alias-convergence, and lock non-collision cases provide objective acceptance criteria? [Measurability, Spec §SC-005-002, §SC-005-004--005]
- [x] CHK025 Does performance acceptance define repeat counts, raw evidence, variance statistics, decision ownership, and the rule for setting or withholding a threshold? [Clarity, Plan §Performance Goals]

## Notes

An independent reviewer evaluates every item before critique closes. Later implementation and release gates use separate behavioral evidence.
