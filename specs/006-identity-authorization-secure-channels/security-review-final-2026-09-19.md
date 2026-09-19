---
document_type: security-review
review_type: export
assessment_date: 2026-09-19
codebase_analyzed: matinee, /Users/sjors/tmp/worktrees/matinee/omp-agent-fix-sec010-reset
total_files_analyzed: 37
total_findings: 10
overall_risk: LOW
critical_count: 0
high_count: 0
medium_count: 0
low_count: 5
informational_count: 0
owasp_categories: [A01, A02, A03, A04]
cwe_ids: [CWE-204, CWE-226, CWE-284, CWE-307, CWE-693]
assessment_kind: whitebox-review
source_artifacts: [security-review-plan-2026-09-16.md, security-review-tasks-2026-09-16.md, security-review-branch-2026-09-19.md, spec.md, plan.md, tasks.md, validation.md]
commit_or_branch: a9731080, omp/agent/fix-sec010-reset
---

# Matinee - Whitebox Security Assessment

## 1. Executive Summary

This final export records six converged review passes for Spec 006, Identity, Authorization, and Secure Channels, at commit `a9731080`. Source code, contracts, tests, validation evidence, and the roadmap entry were reviewed. The earlier branch report at `66a0943b` remains historical and is superseded by this report.

All 32 functional requirements and 9 success criteria are satisfied. No Critical, High, or active Medium finding remains. Five Low, Tier-3 residuals remain as defense-in-depth or public API integration hazards. Both `matinee-security` and `matinee-runtime` crates are `publish = false`, and no production route reaches the affected APIs at this commit.

**Overall Risk Rating: LOW**

| Severity | Count | Primary Categories |
| --- | --- | --- |
| Critical | 0 | None |
| High | 0 | None |
| Medium | 0 | None |
| Low | 5 | A01, A02, A04 |
| Informational | 0 | None |

**Final verdict: safe to merge with tracked residuals.**

## 2. Assessment Methodology

### Scope

- **Code:** `crates/matinee-security/**`, runtime enrollment integration, manifests, tests, vectors, and Spec 006 artifacts.
- **Documentation:** Spec 006 specification, plan, tasks, four contracts, constitution, roadmap, and validation record.
- **Commit:** `a9731080` on `omp/agent/fix-sec010-reset`.

### Evidence

The final gate evidence is recorded below. Formatting passed. Default workspace tests passed with 427 passed and 0 failed. All-features workspace tests passed with 435 passed and 0 failed. The security library listed 230 tests. The `enrollment_lifecycle` example completed. Pinned cargo-deny advisories were okay. No remote daemon or browser route exists at this commit.

## 3. Six Review Passes

1. **Conformance, head `8547f066`, verdict DO NOT LAND.** All 32 FR and 9 SC were walked. SC-001 and SC-002 were unimplemented because bootstrap committed a `BootstrapRecord` without creating a daemon keypair or registering the native administrator. FR-002, FR-004, FR-007, FR-018, FR-019, FR-027, and FR-030 diverged. FR-032 and SC-003, SC-004, SC-005, SC-007, SC-008, and SC-009 were untested. This corrected an earlier unsupported claim of 41/41 with 370 tests green.
2. **Code, errors, types, and branch security, head `66a0943b`.** D1 found the ten-minute default treated as an absolute 600000 ms deadline, rejecting a correct `created + 600000` deadline. D2 and D3 found seven `consume_enrollment` prechecks, including replay, authentication, expired, and consumed proofs, returning without required facts. Security found SEC-001, the unreviewed `p256` dependency and sole merge blocker; SEC-002 missing key zeroization; SEC-003 caller-seeded principal snapshots through public registry insertion; and SEC-004 unknown enrollment lookup bypassing the host budget and fact path.
3. **Repair review, head `f8167899`, verdict not security-clear.** SEC-005 found caller-controlled `created_ms` could future-date the ten-minute window. SEC-006 found `create_enrollment` returned decided rejections without the required fact; a conflicting test asserting silence was rejected as non-authoritative because tests cannot narrow the normative contract.
4. **Repair review, head `736a780`, verdict not security-clear.** SEC-009 found expired attempts charged the host budget but returned before the exhausted-budget check and discarded `record_failure`'s `RateLimited` result, allowing unlimited expired attempts and extra replay facts. Code review also found a Priority 2 endpoint-class defect: `active_principal` hard-coded `EndpointClass::Native`, misclassifying revoked browser-extension and MCP-client refusals. A test passed while proving nothing because its revoked principal was NativeAdmin.
5. **Repair review, head `c7f7b863`, verdict DO NOT MERGE.** SEC-010 found expired-path precheck calling `reset_if_elapsed` before the required fact was accepted. With ten stored failures and an elapsed window, an unavailable sink returned `EventUnavailable`, silently clearing the budget without an audit record. Both reviewers found this independently; the same root cause existed at two further sites.
6. **Final review, head `a9731080`, both reviews clean.** Security found the implementation safe to merge with tracked non-blocking residuals. Code, errors, and types found no Critical or Important issue and recorded a 16-exit table proving fact-before-mutation on every reachable exit.

Six of the 21 defects were introduced by repairs. Seven tests passed while proving nothing, including a mapping test asserting only identifier contiguity, an SC-008 test whose confirmed work never happened, and the endpoint-class test whose sole case matched the hard-coded default. The turning point was mutation proof: reintroducing a defect must make a named test fail with a specific message.

## 4. Technical Findings and Final Dispositions

### SEC-001 - Unreviewed second cryptographic library

**Severity:** MEDIUM historical, resolved. The branch report at `66a0943b` identified `p256` outside the fixed single-library boundary and `libc` without rationale. The repair removed `p256`. Ring-only P-256 validation was proven over 2,528 differential inputs. **Disposition: resolved; no merge blocker.**

### SEC-002 - Enrollment private and wrapping-key lifetime

**Severity:** LOW, Tier 3, tracked residual. PKCS#8 enrollment material and wrapping keys do not yet have complete bounded lifetime and zeroization across every clone, error, and drop path. **Disposition: accepted Low residual.** Harden before publication or external enrollment exposure.

### SEC-003 - Caller-built principal and registry admission

**Severity:** LOW, Tier 3, tracked residual. Public principal construction, activation, registry insertion, and handshake configuration let a trusted consumer assemble an arbitrary active principal. Snapshot admission closes the mismatch race but not the broader forgeability hazard. **Disposition: accepted Low residual.** Constrain construction or issue a non-forgeable registry token before publication.

### SEC-004 - Unknown enrollment lookup and budget disclosure

**Severity:** MEDIUM historical, resolved. Unknown and unbound attempts now charge the host budget and use normalized external failure behavior. This also fixed the `[::1]` versus `::1` bucket split. **Disposition: resolved.**

### SEC-005 - Expiry validity anchored to caller-supplied future time

**Severity:** MEDIUM historical, resolved. Creation validity is anchored to trusted time; the runtime host reads its own clock and refuses a future anchor outside the permitted window. **Disposition: resolved.**

### SEC-006 - Authorization and creation denial fact floor

**Severity:** LOW historical, resolved. Five decided creation rejections now emit required facts, covered by a seven-case matrix. **Disposition: resolved.**

### SEC-007 - Caller-claimed clock, capability, and owner provenance

**Severity:** LOW, Tier 3, tracked residual. `EnrollmentBundle::create` and `EnrollmentClock::new` accept caller-provided clock values, while `SecurityTransitions::receive` and `send_projection` accept caller-claimed capability and owner context. Both crates are unpublished and no production route reaches these paths. **Disposition: accepted Low residual.** Move provenance behind owner-controlled seams before publication.

### SEC-008 - Host budget state lost on event failure

**Severity:** MEDIUM historical, resolved. Elapsed host budgets are preserved across event failure under the same mutex, and the transition remains fail-closed. **Disposition: resolved at `a9731080`.**

### SEC-009 - Expired-attempt budget ordering and reset path

**Severity:** LOW historical, resolved, with maintenance recommendation. The budget is enforced before replay classification and the mutating reset was removed from all three prechecks. `reset_if_elapsed` now has no callsite. **Disposition: security finding resolved.** Recommend an explicit assertion or removal for the dead defensive arm.

### SEC-010 - Event-unavailable reset mutation

**Severity:** LOW historical, resolved. No precheck mutates budget state before the required fact is accepted; the three prechecks preserve fact-before-mutation. **Disposition: resolved.**

## 5. Tracked Residuals and Suggestions

The five tracked Low/Tier-3 residuals are SEC-002 enrollment secret zeroization, SEC-003 public principal construction and registry insertion, SEC-007 caller-provided clock and projection provenance, the residual API hardening represented by SEC-009's dead-arm recommendation, and `sign_sealed_for_test` remaining in non-test all-features builds under SEC-010's residual tracking. Both relevant crates set `publish = false`, and no production route reaches these APIs at `a9731080`; therefore they are non-blocking but must be addressed before publication or route exposure.

Two non-blocking Suggestions remain:

1. Extract the three identical read-only host-budget closures into one helper.
2. Replace policy duplication with one decision token shared by the three call sites, `before_attempt`, and `record_failure`, rather than splitting the 60-second and ten-failure rules.

The dead defensive arm recommendation is explicit: replace it with an assertion or remove it so future state-machine changes cannot silently create an untested path.

## 6. Gate and Structural Evidence

- `cargo fmt --all -- --check`: pass.
- Default `cargo test --workspace --all-targets --no-fail-fast`: 427 passed, 0 failed.
- All-features workspace tests: 435 passed, 0 failed.
- `cargo test -p matinee-security --lib -- --list`: 230 listed security library tests.
- `cargo run -p matinee-runtime --features test-support --example enrollment_lifecycle`: completed.
- `mise x cargo:cargo-deny@0.20.2 -- cargo deny check advisories`: advisories okay.
- `reset_if_elapsed` has no callsite.
- Exactly three `record_failure` calls sit behind `before_attempt` under one mutex.

## 7. Architectural Drift and Systemic Risks

Spec 006 delivered its stated outcome: approved principals connect through specified channels, while unknown, revoked, downgraded, and replayed peers fail before mutation. It stayed within scope: credential-store integration, roles, ECDSA identity, key agreement, framing, origin checks, rotation, and revocation. Browser operations and human approval policy remain out of scope. Browser realization belongs to Spec 008; durable history belongs to Spec 015. No governed-by constraint violation was found.

The process lesson is systemic: implementation claims require observable mutation proof, not only green tests. This was corrected in the final acceptance evidence and is not a remaining product finding.

## 8. Final Verdict

**Safe to merge with tracked residuals.** SEC-001, SEC-004, SEC-005, SEC-006, SEC-008, SEC-009, and SEC-010's security behavior are resolved. SEC-002, SEC-003, SEC-007, and the two explicitly tracked hardening items (dead-arm cleanup and test-helper gating) remain Low/Tier-3 residuals. No production source change is required by this report.

## 9. Evidence Provenance

This report synthesizes direct whitebox review at the six stated heads, the prior plan, task, and branch reports, the Spec 006 contracts and validation record, and final gate results for `a9731080`. It is not a new remote penetration test. No credentials, private keys, or exploit-enabling secrets are included.
