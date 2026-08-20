#!/usr/bin/env bash
# aggregate exit codes ourselves — do NOT use -e, a single tool finding must not abort the run
set -uo pipefail

# resolve the scan path and make sure the report dir exists inside it
SRC="$(cd "$SCAN_PATH" && pwd)"
mkdir -p "$SRC/$REPORT_DIR"

# MODE selects which half runs. "image" exists so a post-build step can scan the
# artifact without repeating the source scans the PR-time run already did - that
# duplication is the whole reason the image scan is a step and not a second job.
MODE="${MODE:-all}"
case "$MODE" in
  all)    run_source=1; run_image=1 ;;
  source) run_source=1; run_image=0 ;;
  image)  run_source=0; run_image=1 ;;
  *) echo "::error::mode must be all, source or image (got '$MODE')"; exit 2 ;;
esac

# verify current version
CHECKOV_IMAGE="bridgecrew/checkov:3.2.334"
# GHCR, not Docker Hub: "aquasecurity/trivy" does not exist on Docker Hub, so the pull
# was denied and trivy silently never ran - it recorded WARN for "findings" it never
# looked for. Aqua publish to ghcr.io/aquasecurity/trivy (canonical) and aquasec/trivy
# (Docker Hub); GHCR keeps the aquasecurity org name and avoids Docker Hub rate limits,
# which matter here since every scanner in this file is a container pull.
TRIVY_IMAGE="ghcr.io/aquasecurity/trivy:0.58.1"
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
  # --exit-code 1 is REQUIRED. Without it trivy exits 0 even when it prints
  # failures, so record() saw success and logged PASS while HIGH/CRITICAL
  # misconfigurations sat in the output. Confirmed on ai-platform run
  # 32284064305 (2026-08-19): "Failures: 4 (HIGH: 3, CRITICAL: 1)" -> "PASS".
  docker run --rm -v "$SRC:/src" -w /src "$TRIVY_IMAGE" \
    config /src --severity HIGH,CRITICAL --exit-code 1
}

scan_trivy_fs() {
  echo "==> trivy fs (dependency CVEs / SCA)"
  # The dependency-CVE gate. Reads lockfiles and manifests out of the source
  # tree (pom.xml, package-lock.json, requirements.txt, go.mod, composer.lock,
  # build.gradle*) - no built image needed, so this runs on every PR.
  # --scanners vuln keeps it to CVEs; secrets and misconfig are already covered
  # by gitleaks/trufflehog and checkov/trivy-config, and running them twice here
  # would double-report the same findings.
  # --ignore-unfixed drops CVEs with no upstream fix, so the gate stays actionable.
  docker run --rm -v "$SRC:/src" -w /src "$TRIVY_IMAGE" \
    fs /src --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1
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
  # --error is REQUIRED for the same reason as trivy's --exit-code: semgrep scan
  # exits 0 on findings by default. ai-platform run 32284064305 reported
  # "170 findings" and still recorded PASS.
  docker run --rm -v "$SRC:/src" -w /src "$SEMGREP_IMAGE" \
    semgrep --config=p/default --config=p/secrets --error \
    --sarif --output="/src/$REPORT_DIR/semgrep.sarif" /src
}

scan_trivy_image() {
  echo "==> trivy image ($IMAGE_REF)"
  docker run --rm -v "$SRC:/src" -w /src "$TRIVY_IMAGE" \
    image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$IMAGE_REF"
}

# Dockerfiles anywhere in the tree, not just at the root - healthslate-backend
# keeps its at docker/Dockerfile, and a root-only check reads as "no Dockerfile".
find_dockerfiles() {
  find "$SRC" -type f \( -name Dockerfile -o -name 'Dockerfile.*' \) \
    -not -path '*/node_modules/*' -not -path '*/vendor/*' -not -path '*/.git/*' \
    -not -path "*/$REPORT_DIR/*" 2>/dev/null
}

scan_hadolint() {
  echo "==> hadolint (Dockerfile lint)"
  # Was gated behind scan-image, which meant it never ran anywhere - it lints a
  # Dockerfile and has never needed a built image.
  local rc=0
  while IFS= read -r df; do
    [ -n "$df" ] || continue
    echo "--- ${df#$SRC/}"
    docker run --rm -i "$HADOLINT_IMAGE" < "$df" || rc=1
  done <<< "$(find_dockerfiles)"
  return $rc
}

scan_syft_source() {
  echo "==> syft (source SBOM)"
  # syft reads a directory as happily as an image, so the source SBOM is
  # available on every PR without waiting for a build.
  docker run --rm -v "$SRC:/src" -w /src "$SYFT_IMAGE" \
    "dir:/src" -o "cyclonedx-json=/src/$REPORT_DIR/sbom-source.cdx.json" \
               -o "spdx-json=/src/$REPORT_DIR/sbom-source.spdx.json"
}

scan_syft_image() {
  echo "==> syft (image SBOM)"
  docker run --rm -v "$SRC:/src" -w /src "$SYFT_IMAGE" \
    "$IMAGE_REF" -o "cyclonedx-json=/src/$REPORT_DIR/sbom.cdx.json" \
                 -o "spdx-json=/src/$REPORT_DIR/sbom.spdx.json"
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

if [ "$run_source" -eq 1 ]; then

# --- IaC misconfig ---
scan_checkov;      record "checkov"      $? warn
scan_trivy_config; record "trivy-config" $? warn

# --- dependency CVEs (SCA) ---
scan_trivy_fs;     record "trivy-sca"    $? warn

# --- secrets (always hard-fail on a hit) ---
scan_trufflehog;   record "trufflehog"   $? secret
scan_gitleaks;     record "gitleaks"     $? secret

# --- SAST ---
scan_semgrep;      record "semgrep"      $? warn

# --- Dockerfile lint (no image required) ---
if [ -n "$(find_dockerfiles)" ]; then
  scan_hadolint;   record "hadolint"     $? warn
else
  SUMMARY+=("SKIP  hadolint (no Dockerfile found)")
fi

# --- source SBOM (no image required) ---
scan_syft_source;  record "syft-sbom-source" $? warn

else
  SUMMARY+=("SKIP  source scans (mode=$MODE)")
fi

# --- image scans: need an image that already exists, so these only run when the
# caller passes a ref (post-build in duplo-pipeline, not at PR time) ---
if [ "$run_image" -eq 1 ] && [ "$SCAN_IMAGE" == "true" ] && [ -n "$IMAGE_REF" ]; then
  scan_trivy_image; record "trivy-image"     $? warn
  scan_syft_image;  record "syft-sbom-image" $? warn
elif [ "$run_image" -eq 1 ]; then
  SUMMARY+=("SKIP  image scans (scan-image!=true or image-ref empty)")
else
  SUMMARY+=("SKIP  image scans (mode=$MODE)")
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

# render the same summary as the GitHub Actions job summary so results are
# visible on the run page without opening the step log
{
  echo "#### 🔒 security-scan — overall: $RESULT"
  echo
  echo "| status | tool |"
  echo "|---|---|"
  for line in "${SUMMARY[@]}"; do
    status="${line%%  *}"
    detail="${line#*  }"
    case "$status" in
      PASS) icon="✅" ;;
      WARN) icon="⚠️" ;;
      FAIL) icon="❌" ;;
      SKIP) icon="⏭️" ;;
      *) icon="•" ;;
    esac
    echo "| $icon $status | $detail |"
  done
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

exit "$should_exit"
