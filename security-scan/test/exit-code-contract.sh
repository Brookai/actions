#!/usr/bin/env bash
#
# Self-test for scan.sh's exit-code contract.
#
# The contract: every scanner declares the exit code it returns when it ran
# correctly AND found something. Anything else non-zero means the tool failed to
# run and must be reported as TOOL-ERROR, never as a finding. This matters most
# for the secret category, which bypasses `enforce` and hard-fails - before the
# contract existed, a denied image pull surfaced to the author as "you committed
# a secret".
#
# `docker` is stubbed so each scanner's exit code can be chosen. That is the
# point: the mapping is what is under test, not the scanners.
#
# Run: security-scan/test/exit-code-contract.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCAN_SH="$HERE/../scan.sh"
[ -x "$SCAN_SH" ] || { echo "scan.sh not found or not executable at $SCAN_SH"; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/src/.git" "$WORK/bin" "$WORK/tmp"
echo "FROM alpine:3.19" > "$WORK/src/Dockerfile"
echo "FROM alpine"      > "$WORK/src/Dockerfile.j2"   # not a Dockerfile; must be skipped
echo "print('hi')"      > "$WORK/src/app.py"

cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
args="$*"; tool=unknown
case "$args" in
  *checkov*)            tool=checkov ;;
  *trivy*" config "*)   tool=trivy_config ;;
  *trivy*" fs "*)       tool=trivy_fs ;;
  *trivy*" image "*)    tool=trivy_image ;;
  *trufflehog*" git "*) tool=trufflehog_git ;;
  *trufflehog*)         tool=trufflehog_fs ;;
  *gitleaks*)           tool=gitleaks ;;
  *semgrep*)            tool=semgrep ;;
  *hadolint*)           tool=hadolint ;;
  *syft*registry:*)     tool=syft_image ;;
  *syft*)               tool=syft_source ;;
esac
v="STUB_RC_${tool}"; rc="${!v:-0}"
R=""; prev=""
for a in "$@"; do
  if [ "$prev" = "-v" ]; then case "$a" in *:/reports) R="${a%:/reports}" ;; esac; fi
  prev="$a"
done
if [ "${STUB_WRITE:-1}" = "1" ] && [ -n "$R" ]; then
  case "$tool" in
    checkov)      echo '{}' > "$R/checkov.sarif" ;;
    gitleaks)     echo '{}' > "$R/gitleaks.sarif" ;;
    semgrep)      echo '{}' > "$R/semgrep.sarif" ;;
    syft_source)  echo '{}' > "$R/sbom-source.cdx.json" ;;
    syft_image)   echo '{}' > "$R/sbom.cdx.json" ;;
    trivy_config) echo '{}' > "$R/trivy-config.json" ;;
    trivy_fs)     echo '{}' > "$R/trivy-sca.json" ;;
    trivy_image)  echo '{}' > "$R/trivy-image.json" ;;
  esac
fi
exit "$rc"
STUB
chmod +x "$WORK/bin/docker"

pass=0; failed=0

# assert <description> <expected-exit> <expected-substring> [ENV=VAL ...]
assert() {
  local desc="$1" want_exit="$2" want_line="$3"; shift 3
  : > "$WORK/gh_output"
  local got_exit
  ( export PATH="$WORK/bin:$PATH" SCAN_PATH="$WORK/src" REPORT_DIR="scan-reports" \
      MODE="source" ENFORCE="false" SCAN_IMAGE="false" IMAGE_REF="" \
      GITHUB_OUTPUT="$WORK/gh_output" GITHUB_STEP_SUMMARY="$WORK/gh_summary" \
      RUNNER_TEMP="$WORK/tmp" "$@"
    bash "$SCAN_SH" > "$WORK/out.txt" 2>&1 )
  got_exit=$?
  local ok=1 why=""
  [ "$got_exit" -eq "$want_exit" ] || { ok=0; why="exit $got_exit, wanted $want_exit"; }
  if [ -n "$want_line" ] && ! grep -qF -- "$want_line" "$WORK/out.txt"; then
    ok=0; why="${why:+$why; }missing summary line: $want_line"
  fi
  if [ "$ok" -eq 1 ]; then
    printf '  ok    %s\n' "$desc"; pass=$((pass + 1))
  else
    printf '  FAIL  %s\n        %s\n' "$desc" "$why"; failed=$((failed + 1))
    sed -n '/security-scan summary/,$p' "$WORK/out.txt" | sed 's/^/        | /'
  fi
}

echo "security-scan exit-code contract"

# --- clean baseline -------------------------------------------------------
assert "all clean -> pass, no tool errors" 0 "PASS  checkov"

# --- findings are findings ------------------------------------------------
assert "trivy findings (7) -> WARN" 0 \
  "WARN  trivy-config (findings" STUB_RC_trivy_config=7
assert "trivy-sca findings (7) -> WARN" 0 \
  "WARN  trivy-sca (findings" STUB_RC_trivy_fs=7
assert "semgrep findings (1) -> WARN" 0 \
  "WARN  semgrep (findings" STUB_RC_semgrep=1
assert "hadolint findings (1) -> WARN" 0 \
  "WARN  hadolint (findings" STUB_RC_hadolint=1

# --- secrets hard-fail past enforce ---------------------------------------
assert "gitleaks leak (7) -> FAIL secret, exit 1" 1 \
  "FAIL  gitleaks (secret finding" STUB_RC_gitleaks=7
assert "trufflehog verified (183) -> FAIL secret, exit 1" 1 \
  "FAIL  trufflehog-fs (secret finding" STUB_RC_trufflehog_fs=183
assert "trufflehog git history (183) -> FAIL secret, exit 1" 1 \
  "FAIL  trufflehog-git (secret finding" STUB_RC_trufflehog_git=183

# --- tool failures are NOT findings ---------------------------------------
# These are the regressions this file exists to catch.
assert "trivy own error (1) -> TOOL-ERROR, not findings" 0 \
  "TOOL-ERROR  trivy-config (exit 1" STUB_RC_trivy_config=1
assert "gitleaks own error (1) -> TOOL-ERROR, NOT a secret" 0 \
  "TOOL-ERROR  gitleaks (exit 1" STUB_RC_gitleaks=1
assert "trufflehog own error (2) -> TOOL-ERROR, NOT a secret" 0 \
  "TOOL-ERROR  trufflehog-fs (exit 2" STUB_RC_trufflehog_fs=2
assert "docker daemon refused (125) -> TOOL-ERROR" 0 \
  "TOOL-ERROR  checkov (exit 125" STUB_RC_checkov=125
assert "syft non-zero (1) -> TOOL-ERROR (it has no findings code)" 0 \
  "TOOL-ERROR  syft-sbom-source (exit 1" STUB_RC_syft_source=1
assert "exit 0 having written no report -> TOOL-ERROR" 0 \
  "TOOL-ERROR  checkov (exit 0, wrote no checkov.sarif" STUB_WRITE=0
assert "trivy exit 0 having written no report -> TOOL-ERROR" 0 \
  "TOOL-ERROR  trivy-sca (exit 0, wrote no trivy-sca.json" STUB_WRITE=0
assert "crash sharing the findings code (checkov 1, no report) -> TOOL-ERROR" 0 \
  "TOOL-ERROR  checkov (exit 1, wrote no checkov.sarif" STUB_RC_checkov=1 STUB_WRITE=0

# --- enforce ---------------------------------------------------------------
assert "enforce=true + findings -> fail" 1 \
  "FAIL  trivy-sca (findings, enforce=true)" ENFORCE=true STUB_RC_trivy_fs=7
assert "enforce=true + tool error -> fail (coverage hole)" 1 \
  "TOOL-ERROR  trivy-sca (exit 1" ENFORCE=true STUB_RC_trivy_fs=1

# --- mode ------------------------------------------------------------------
assert "invalid mode -> exit 2 and still writes result" 2 "" MODE=nonsense
if ! grep -q '^result=fail' "$WORK/gh_output"; then
  echo "  FAIL  invalid mode must still write result=fail to GITHUB_OUTPUT"; failed=$((failed + 1))
else
  echo "  ok    invalid mode writes result=fail to GITHUB_OUTPUT"; pass=$((pass + 1))
fi
assert "mode=both is an alias of all, not an error" 0 "SKIP  image scans" MODE=both
assert "mode=iac is an alias of source" 0 "SKIP  image scans (mode=iac)" MODE=iac

# --- Dockerfile discovery --------------------------------------------------
assert "Dockerfile.j2 is not linted as a Dockerfile" 0 "PASS  hadolint"

echo
echo "$pass passed, $failed failed"
[ "$failed" -eq 0 ]
