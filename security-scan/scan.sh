#!/usr/bin/env bash
# aggregate exit codes ourselves — do NOT use -e, a single tool finding must not abort the run
set -uo pipefail

# resolve the scan path and make sure the report dir exists inside it
SRC="$(cd "$SCAN_PATH" && pwd)"
mkdir -p "$SRC/$REPORT_DIR"

# verify current version
CHECKOV_IMAGE="bridgecrew/checkov:3.2.334"
TRIVY_IMAGE="aquasecurity/trivy:0.58.1"
TRUFFLEHOG_IMAGE="trufflesecurity/trufflehog:3.88.0"
GITLEAKS_IMAGE="zricethezav/gitleaks:v8.21.2"
SEMGREP_IMAGE="semgrep/semgrep:1.99.0"
HADOLINT_IMAGE="hadolint/hadolint:v2.12.0"
SYFT_IMAGE="anchore/syft:v1.18.1"

fail=0
secret_hit=0

# --- tool functions (docker is the last statement so the function returns its exit code) ---

scan_checkov() {
  echo "==> checkov (IaC misconfig)"
  docker run --rm -v "$SRC:/src" -w /src "$CHECKOV_IMAGE" \
    -d /src --framework terraform -o sarif --output-file-path "/src/$REPORT_DIR"
}

scan_trivy_config() {
  echo "==> trivy config (IaC misconfig)"
  docker run --rm -v "$SRC:/src" -w /src "$TRIVY_IMAGE" \
    config /src --severity HIGH,CRITICAL
}

scan_trufflehog() {
  echo "==> trufflehog (verified secrets)"
  docker run --rm -v "$SRC:/src" -w /src "$TRUFFLEHOG_IMAGE" \
    filesystem /src --results=verified --fail
}

scan_gitleaks() {
  echo "==> gitleaks (secrets)"
  docker run --rm -v "$SRC:/src" -w /src "$GITLEAKS_IMAGE" \
    detect --source=/src --redact --report-format sarif --report-path="/src/$REPORT_DIR/gitleaks.sarif"
}

scan_semgrep() {
  echo "==> semgrep (SAST)"
  docker run --rm -v "$SRC:/src" -w /src "$SEMGREP_IMAGE" \
    semgrep --config=p/default --config=p/secrets --sarif --output="/src/$REPORT_DIR/semgrep.sarif" /src
}

scan_trivy_image() {
  echo "==> trivy image ($IMAGE_REF)"
  docker run --rm -v "$SRC:/src" -w /src "$TRIVY_IMAGE" \
    image --severity HIGH,CRITICAL --ignore-unfixed "$IMAGE_REF"
}

scan_hadolint() {
  echo "==> hadolint (Dockerfile lint)"
  docker run --rm -i "$HADOLINT_IMAGE" < "$SRC/Dockerfile"
}

scan_syft() {
  echo "==> syft (SBOM)"
  docker run --rm -v "$SRC:/src" -w /src "$SYFT_IMAGE" \
    "$IMAGE_REF" -o "cyclonedx-json=/src/$REPORT_DIR/sbom.cdx.json" -o "spdx-json=/src/$REPORT_DIR/sbom.spdx.json"
}

# record a tool result and update the fail/secret_hit flags
#   $1 tool name   $2 exit code   $3 category (secret|warn)
declare -a SUMMARY=()
record() {
  local name="$1" rc="$2" category="$3"
  if [ "$rc" -eq 0 ]; then
    SUMMARY+=("PASS  $name")
    return
  fi
  if [ "$category" == "secret" ]; then
    # a verified secret is never a false positive — always block, regardless of enforce
    secret_hit=1
    fail=1
    SUMMARY+=("FAIL  $name (secret finding — always blocks)")
  elif [ "$ENFORCE" == "true" ]; then
    fail=1
    SUMMARY+=("FAIL  $name (findings, enforce=true)")
  else
    SUMMARY+=("WARN  $name (findings — warn-only; set enforce=true to block)")
  fi
}

# --- IaC misconfig ---
scan_checkov;      record "checkov"      $? warn
scan_trivy_config; record "trivy-config" $? warn

# --- secrets (always hard-fail on a hit) ---
scan_trufflehog;   record "trufflehog"   $? secret
scan_gitleaks;     record "gitleaks"     $? secret

# --- SAST ---
scan_semgrep;      record "semgrep"      $? warn

# --- image scans (opt-in) ---
if [ "$SCAN_IMAGE" == "true" ] && [ -n "$IMAGE_REF" ]; then
  scan_trivy_image; record "trivy-image" $? warn
  if [ -f "$SRC/Dockerfile" ]; then
    scan_hadolint;  record "hadolint"    $? warn
  else
    SUMMARY+=("SKIP  hadolint (no Dockerfile)")
  fi
  scan_syft;        record "syft-sbom"   $? warn
else
  SUMMARY+=("SKIP  image scans (scan-image!=true or image-ref empty)")
fi

# --- summary ---
echo ""
echo "================ security-scan summary ================"
for line in "${SUMMARY[@]}"; do
  echo "  $line"
done
echo "======================================================="

# decide overall result and exit code
should_exit=0
if [ "$fail" -eq 1 ] && { [ "$secret_hit" -eq 1 ] || [ "$ENFORCE" == "true" ]; }; then
  should_exit=1
fi

if [ "$should_exit" -eq 1 ]; then
  RESULT="fail"
else
  RESULT="pass"
fi
echo "result=$RESULT" >> "$GITHUB_OUTPUT"
echo "Overall: $RESULT"

exit "$should_exit"
