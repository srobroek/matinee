#!/usr/bin/env bash
#
# Self-check for the status discovery scripts. Builds a throwaway spec-kit-shaped
# project and asserts the JSON output of every runtime that is installed, then
# checks the runtimes agree with each other. Run it directly:
#
#   ./tests/test-status.sh
#
# No framework, no fixtures — it exits non-zero on the first failure.
# PowerShell is skipped when pwsh is absent; bash and python are required.

set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
RUNTIME=""

# Invoke the current runtime with the given arguments.
run_status() {
    case "$RUNTIME" in
        bash) sh "$ROOT/scripts/bash/get-project-status.sh" "$@" ;;
        python) python3 "$ROOT/scripts/python/get_project_status.py" "$@" ;;
        powershell)
            # The PowerShell script takes -Json / -Feature rather than --json / --feature.
            local ps_args=()
            while [ $# -gt 0 ]; do
                case "$1" in
                    --json) ps_args+=("-Json") ;;
                    --feature) ps_args+=("-Feature" "$2"); shift ;;
                    *) ps_args+=("$1") ;;
                esac
                shift
            done
            pwsh -NoProfile -File "$ROOT/scripts/powershell/Get-ProjectStatus.ps1" "${ps_args[@]}"
            ;;
    esac
}

assert_json() {
    local label="$1" expr="$2" expected="$3" json="$4" actual
    actual=$(printf '%s' "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print($expr)")
    if [ "$actual" = "$expected" ]; then
        echo "  ok   $label"
    else
        echo "  FAIL [$RUNTIME] $label — expected '$expected', got '$actual'"
        FAILURES=$((FAILURES + 1))
    fi
}

# ── Build a fixture project ───────────────────────────────────────────────────

cd "$WORK"
git init -q .
git config user.email test@example.com
git config user.name test
mkdir -p .specify/memory
echo "# Constitution" > .specify/memory/constitution.md

# Three feature directories covering every prefix shape spec-kit emits:
# sequential three-digit, sequential four-digit, and --timestamp.
for f in 001-onboarding 1000-scale 20260910-123456-legacy; do
    mkdir -p "specs/$f"
    echo "# Spec" > "specs/$f/spec.md"
done

mkdir -p specs/001-onboarding/checklists
echo "- [x] done" > specs/001-onboarding/checklists/ux.md

cat > specs/001-onboarding/tasks.md <<'EOF'
- [x] T001 Done
- [ ] T002 Not done
EOF

git add -A
git commit -qm init
git checkout -qb main 2>/dev/null || true

# ── Assertion suite, run once per available runtime ───────────────────────────

check_runtime() {
    RUNTIME="$1"
    echo "── $RUNTIME ──"

    rm -f .specify/feature.json
    git checkout -q main
    local json
    json=$(run_status --json)

    assert_json "finds all three prefix shapes" "d['feature_count']" "3" "$json"
    assert_json "includes timestamp feature" \
        "'20260910-123456-legacy' in [f['name'] for f in d['features']]" "True" "$json"
    assert_json "includes four-digit feature" \
        "'1000-scale' in [f['name'] for f in d['features']]" "True" "$json"
    assert_json "counts tasks" \
        "[f['tasks_completed'] for f in d['features'] if f['name']=='001-onboarding'][0]" "1" "$json"
    assert_json "lists checklist files" \
        "[f['checklist_files'] for f in d['features'] if f['name']=='001-onboarding'][0]" \
        "['ux.md']" "$json"
    assert_json "no feature context off a feature branch" "d['current_feature']" "None" "$json"
    assert_json "target_feature null with no context" "d['target_feature']" "None" "$json"
    assert_json "no from_cache field" "'from_cache' in d['features'][0]" "False" "$json"

    echo '{"feature_directory":"specs/1000-scale"}' > .specify/feature.json
    json=$(run_status --json)
    assert_json "feature.json sets current feature" "d['current_feature']" "1000-scale" "$json"
    assert_json "feature.json reported as source" "d['feature_source']" "feature.json" "$json"
    assert_json "target_feature falls back to current" "d['target_feature']" "1000-scale" "$json"
    assert_json "is_current set on the right feature" \
        "[f['name'] for f in d['features'] if f['is_current']]" "['1000-scale']" "$json"

    json=$(SPECIFY_FEATURE_DIRECTORY=specs/20260910-123456-legacy run_status --json)
    assert_json "SPECIFY_FEATURE_DIRECTORY overrides feature.json" \
        "d['current_feature']" "20260910-123456-legacy" "$json"
    assert_json "env reported as source" "d['feature_source']" "env" "$json"

    json=$(run_status --json --feature 001)
    assert_json "explicit feature wins for target" "d['target_feature']" "001-onboarding" "$json"
    assert_json "current_feature still reflects the project" "d['current_feature']" "1000-scale" "$json"

    # The command exposes --all and --verbose to users. They are the agent's to
    # interpret, and forwarding them must not turn a status query into an error.
    for stray in --all --verbose; do
        if json=$(run_status --json "$stray" 2>/dev/null); then
            assert_json "ignores a forwarded $stray" "d['feature_count']" "3" "$json"
        else
            echo "  FAIL [$RUNTIME] ignores a forwarded $stray — script exited non-zero"
            FAILURES=$((FAILURES + 1))
        fi
    done

    # Test-Path and glob matching must not accept a wildcard as a feature name.
    if run_status --json --feature '*' >/dev/null 2>&1; then
        echo "  FAIL [$RUNTIME] accepted '*' as a feature name"
        FAILURES=$((FAILURES + 1))
    else
        echo "  ok   rejects a wildcard feature name"
    fi

    rm -f .specify/feature.json
    git checkout -q 001-onboarding 2>/dev/null || git checkout -qb 001-onboarding
    json=$(run_status --json)
    assert_json "branch fallback resolves the feature" "d['current_feature']" "001-onboarding" "$json"
    assert_json "branch reported as source" "d['feature_source']" "branch" "$json"

    run_status --json > "$WORK/out-$RUNTIME.json"

    # The written status file is a committable artifact, so its rendering has to
    # match across runtimes too. Drop the line carrying the commit and timestamp.
    grep -v "spec-status:" specs/spec-status.md > "$WORK/statusfile-$RUNTIME.txt"
}

# A repo with no commits: rev-parse prints "HEAD" to stdout and exits non-zero,
# which a naive fallback concatenates into "HEADunknown".
check_empty_repo() {
    RUNTIME="$1"
    local empty="$WORK/empty-$RUNTIME" json
    rm -rf "$empty"
    mkdir -p "$empty/specs/001-fresh" "$empty/.specify"
    (cd "$empty" && git init -q . && git config user.email t@e.com && git config user.name t)
    echo "# Spec" > "$empty/specs/001-fresh/spec.md"
    json=$(cd "$empty" && run_status --json)
    assert_json "branch is sane with no commits" \
        "d['branch'] in ('main','master')" "True" "$json"
    assert_json "discovery works with no commits" "d['feature_count']" "1" "$json"
    # feature.json is the only context here; the branch is main, not a feature.
    echo '{"feature_directory":"specs/001-fresh"}' > "$empty/.specify/feature.json"
    json=$(cd "$empty" && run_status --json)
    assert_json "feature resolves with no commits" "d['current_feature']" "001-fresh" "$json"
}

RUNTIMES="bash python"
if command -v pwsh >/dev/null 2>&1; then
    RUNTIMES="$RUNTIMES powershell"
else
    echo "note: pwsh not installed, skipping the powershell runtime"
fi

for rt in $RUNTIMES; do
    check_runtime "$rt"
    check_empty_repo "$rt"
    cd "$WORK"
done

# ── Cross-runtime parity ──────────────────────────────────────────────────────

echo "── parity ──"
RUNTIME="parity"
python3 - "$WORK" $RUNTIMES <<'PY'
import json, sys, pathlib

work, runtimes = pathlib.Path(sys.argv[1]), sys.argv[2:]
loaded = {rt: json.loads((work / f"out-{rt}.json").read_text()) for rt in runtimes}
base_name, base = runtimes[0], loaded[runtimes[0]]
failures = 0

# repo_root/specs_dir/cache_file are absolute paths that can differ by symlink
# resolution (/var vs /private/var on macOS), so compare them by basename.
scalar = ["project", "has_git", "branch", "is_feature_branch", "feature_count",
          "current_feature", "feature_source", "target_feature"]

for rt in runtimes[1:]:
    other = loaded[rt]
    if set(base) != set(other):
        print(f"  FAIL {base_name} vs {rt}: key sets differ: {set(base) ^ set(other)}")
        failures += 1
    for key in scalar:
        if base.get(key) != other.get(key):
            print(f"  FAIL {base_name} vs {rt}: {key}: {base.get(key)!r} != {other.get(key)!r}")
            failures += 1
    if base["constitution"]["exists"] != other["constitution"]["exists"]:
        print(f"  FAIL {base_name} vs {rt}: constitution.exists differs")
        failures += 1

    def shape(doc):
        return {f["name"]: {k: v for k, v in f.items() if k != "path"} for f in doc["features"]}

    base_file = (work / f"statusfile-{base_name}.txt").read_text()
    other_file = (work / f"statusfile-{rt}.txt").read_text()
    if base_file != other_file:
        print(f"  FAIL {base_name} vs {rt}: spec-status.md rendering differs")
        failures += 1

    if shape(base) != shape(other):
        print(f"  FAIL {base_name} vs {rt}: feature data differs")
        print(f"        {base_name}: {shape(base)}")
        print(f"        {rt}: {shape(other)}")
        failures += 1
    if not failures:
        print(f"  ok   {base_name} and {rt} agree")

sys.exit(1 if failures else 0)
PY
PARITY=$?

echo
if [ "$FAILURES" -eq 0 ] && [ "$PARITY" -eq 0 ]; then
    echo "all checks passed"
else
    echo "$FAILURES assertion failure(s), parity exit $PARITY"
    exit 1
fi
