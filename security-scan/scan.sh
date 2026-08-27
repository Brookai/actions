#!/usr/bin/env bash
# aggregate exit codes ourselves — do NOT use -e, a single tool finding must not abort the run
set -uo pipefail

# MODE selects which half runs. "image" exists so a post-build step can scan the
# artifact without repeating the source scans the PR-time run already did - that
# duplication is the whole reason the image scan is a step and not a second job.
#
# iac/both are accepted as aliases of source/all. The sibling wiz-scan action
# uses the vocabulary iac|image|both and both actions get invoked in the same
# job, so a caller copying the neighbouring step's mode is a predictable
# mistake. Accepting the synonym costs nothing; a hard exit 2 costs a build.
MODE="${MODE:-all}"
case "$MODE" in
  all|both)    run_source=1; run_image=1 ;;
  source|iac)  run_source=1; run_image=0 ;;
  image)       run_source=0; run_image=1 ;;
  *)
    echo "::error::mode must be all, source or image (got '$MODE')"
    # write the declared output before bailing - callers gate on
    # steps.scan.outputs.result != 'pass', and an empty value takes the
    # wrong branch of that comparison
    echo "result=fail"   >> "${GITHUB_OUTPUT:-/dev/null}"
    echo "tool-errors=1" >> "${GITHUB_OUTPUT:-/dev/null}"
    exit 2
    ;;
esac

# resolve the scan path
SRC="$(cd "$SCAN_PATH" && pwd)"

# Reports are written OUTSIDE the scanned tree.
#
# They used to land in "$SRC/$REPORT_DIR", which put every scanner's output
# inside the directory the later scanners walk: trufflehog then read checkov's
# and trivy's SARIF, so a secret quoted in a finding snippet became a fresh
# finding of its own. Scan into a temp dir, copy into the repo at the end once
# nothing is left to walk.
REPORTS="$(mktemp -d "${RUNNER_TEMP:-/tmp}/security-scan-reports.XXXXXX")"
# Unique per invocation, written out immediately so it exists even if the scan
# later fails. It names the uploaded artifact: billy, data-platform and
# ai-platform each run several scan steps in ONE job, and upload-artifact@v4
# hard-errors on a duplicate artifact name, so a fixed name would fail the build
# of exactly the repos this is meant to protect.
REPORT_ID="${REPORTS##*.}"
echo "report-id=$REPORT_ID" >> "${GITHUB_OUTPUT:-/dev/null}"
# Shared trivy DB cache across the config/fs/image invocations. Without it each
# one runs in a fresh container and re-downloads the vulnerability DB - and the
# fs scan additionally pulls the Java DB (hundreds of MB) wherever a .jar
# exists, which on brook-backend and billy is most of the runtime. Every one of
# those downloads is also a rate-limit candidate, and a rate-limited download is
# a tool error we would rather not manufacture.
TRIVY_CACHE="$(mktemp -d "${RUNNER_TEMP:-/tmp}/trivy-cache.XXXXXX")"

# --- pinned scanner images -------------------------------------------------
#
# Pinned by DIGEST, not tag. A tag is mutable: whoever controls the upstream
# repo can move bridgecrew/checkov:3.2.334 to different content at any time,
# and these containers run as root with the repo bind-mounted, network access,
# and (for the wiz step in the same job) credentials in the job environment.
# The digest is the only pin that actually pins.
#
# To bump: docker manifest inspect <image>:<tag> and take the digest, or
#   curl -sI -H "Authorization: Bearer $(anon token)" .../manifests/<tag>
# Keep the :tag in the comment so the version stays readable.
CHECKOV_IMAGE="bridgecrew/checkov@sha256:888060aaaa6f4499fd3b00a1a03185ed760937b049d438fa6e00b3203a5d613e"          # 3.2.334
# GHCR, not Docker Hub: "aquasecurity/trivy" does not exist on Docker Hub, so the pull
# was denied and trivy silently never ran - it recorded WARN for "findings" it never
# looked for. Aqua publish to ghcr.io/aquasecurity/trivy (canonical) and aquasec/trivy
# (Docker Hub); GHCR keeps the aquasecurity org name and avoids Docker Hub rate limits,
# which matter here since every scanner in this file is a container pull.
TRIVY_IMAGE="ghcr.io/aquasecurity/trivy@sha256:ab70a02200597efa04748f210f793936eb647cbcdb0ea69cc30b226d6f5a22c7"     # 0.58.1
TRUFFLEHOG_IMAGE="trufflesecurity/trufflehog@sha256:75c79b95b2d1f9b54c85b2cba14a7b9baa37bed0835485d6541de64f0fd667bb" # 3.88.0
GITLEAKS_IMAGE="zricethezav/gitleaks@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46"        # v8.21.2
SEMGREP_IMAGE="semgrep/semgrep@sha256:ae27024c16f7848cdbfd49c24ed0b78b13f13b85fcd7b87c679aaa8b0c0dce98"              # 1.99.0
HADOLINT_IMAGE="hadolint/hadolint@sha256:30a8fd2e785ab6176eed53f74769e04f125afb2f74a6c52aef7d463583b6d45e"           # v2.12.0
SYFT_IMAGE="anchore/syft@sha256:b8c170b8e51bfc4779ec3ef4399942c57290f5ce76a9c3af564c9d00d4946a6b"                    # v1.18.1

fail=0
secret_hit=0
tool_errors=0

# Directories no scanner should walk. .git is in here because callers check out
# with fetch-depth: 0, so it holds the entire history - syft and trivy fs would
# inventory every blob ever committed. The secret scanners deliberately do read
# history; they are given it explicitly rather than by accident.
EXCLUDE_DIRS=(.git node_modules vendor)

# --- private-registry auth for the image scans -----------------------------
#
# trivy and syft run inside their own containers, so they do NOT inherit the
# runner's ECR login - without this an ECR ref fails with a 401 that reads like
# the image does not exist.
#
# The mount is the mechanism. amazon-ecr-login (inside build-image) writes a
# registry-scoped, short-lived token into the runner's docker config, and both
# scanner images run as root with HOME=/root, so /root/.docker/config.json is
# where they look. DOCKER_CONFIG is honoured because docker itself reads
# ${DOCKER_CONFIG:-$HOME/.docker}/config.json, and a runner that sets it would
# otherwise have its credentials silently left behind.
DOCKER_CFG="${DOCKER_CONFIG:-$HOME/.docker}/config.json"
REG_AUTH=()
have_docker_cfg=0
if [ -f "$DOCKER_CFG" ]; then
  # Mount a SANITIZED copy holding only the inline auths entries.
  #
  # A docker config may delegate to a credential helper instead of storing
  # credentials inline - credsStore: "desktop", or a credHelpers map. That names
  # a binary which exists on the host and NOT inside the scanner container, so
  # trivy dies before it looks at anything:
  #   FATAL init error: DB error: ... error getting credentials - err: exec:
  #   "docker-credential-desktop": executable file not found in $PATH
  # A FATAL init error is not a scan result, and mounting a config we know the
  # container cannot use buys nothing. amazon-ecr-login writes inline auths, so
  # on a GitHub runner this filter is a no-op; it stops any host with a helper
  # configured from turning the image scan into a hard error.
  if command -v python3 >/dev/null 2>&1; then
    SANITIZED="$(mktemp "${RUNNER_TEMP:-/tmp}/docker-config.XXXXXX")"
    if python3 -c '
import json, sys
try:
    cfg = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
auths = {k: v for k, v in (cfg.get("auths") or {}).items() if v.get("auth")}
if not auths:
    sys.exit(1)
json.dump({"auths": auths}, open(sys.argv[2], "w"))
' "$DOCKER_CFG" "$SANITIZED" 2>/dev/null; then
      REG_AUTH+=(-v "$SANITIZED:/root/.docker/config.json:ro")
      have_docker_cfg=1
    else
      rm -f "$SANITIZED"
      echo "note: $DOCKER_CFG carries no inline registry credentials (credential helper only) — not mounting it"
    fi
  else
    # no python3 to filter with; mount as-is and accept the helper risk
    REG_AUTH+=(-v "$DOCKER_CFG:/root/.docker/config.json:ro")
    have_docker_cfg=1
  fi
fi
# Region only - harmless, and it is what lets trivy resolve the ECR endpoint.
for v in AWS_REGION AWS_DEFAULT_REGION; do
  if [ -n "${!v:-}" ]; then REG_AUTH+=(-e "$v"); fi
done

# Credential fallback for trivy ONLY, and only when there is no docker config to
# use instead. trivy does consume AWS_* for ECR natively; syft does not - it
# resolves registry auth through go-containerregistry, so for the image SBOM the
# config mount is the only mechanism and forwarding credentials to it buys
# nothing but blast radius. Handing a full session token to a third-party
# container is strictly wider than the registry-scoped short-lived token already
# in the mounted config, so it stays a fallback rather than a belt-and-braces.
TRIVY_AWS_AUTH=()
if [ "$have_docker_cfg" -eq 0 ]; then
  for v in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN; do
    if [ -n "${!v:-}" ]; then TRIVY_AWS_AUTH+=(-e "$v"); fi
  done
fi
# ${a[@]+"${a[@]}"} so an empty array does not trip set -u

# --- tool functions --------------------------------------------------------
# Each is piped through tee so its console output survives the run as evidence.
# pipefail is set, so the pipeline still reports the scanner's exit code and not
# tee's. Without this the console-only tools (trivy, hadolint) leave a finding
# in the step log and nothing to baseline or attach to a ticket once the run
# ages out.

scan_checkov() {
  echo "==> checkov (IaC misconfig)"
  # --framework was terraform-only, so in a repo with no Terraform checkov
  # examined nothing and still logged PASS - while the k8s manifests,
  # Dockerfiles and workflow files it could have checked went unscanned by it.
  #
  # In the --output-file-path list form each entry is a FILE, not a directory
  # (the single-output form takes a directory and names the file itself). Given
  # a directory here checkov dies with IsADirectoryError - and it dies with
  # exit 1, the same code it uses for findings, so the crash reads as "checkov
  # found things". That is the exact failure mode the TOOL-ERROR state exists
  # for, which is why the report-file assertion below runs on every exit code
  # rather than only on 0.
  docker run --rm -v "$SRC:/src" -v "$REPORTS:/reports" -w /src "$CHECKOV_IMAGE" \
    -d /src --framework terraform kubernetes dockerfile github_actions secrets \
    -o cli -o sarif --output-file-path "console,/reports/checkov.sarif" 2>&1 | tee "$REPORTS/checkov.txt"
}

scan_trivy_config() {
  echo "==> trivy config (IaC misconfig)"
  # --exit-code 7, not 1. trivy returns 1 for its OWN errors - an unreachable
  # ref, a bad flag, a rate-limited DB download - so --exit-code 1 makes
  # "found misconfigurations" and "could not run" the same signal. 7 is
  # arbitrary but distinct, which is the entire point.
  # JSON, not the console table. The table cannot be itemised into the job
  # summary, and trivy 0.58's console output is buried in rego parse warnings
  # from its own built-in policy bundle. summarize.py renders the readable view
  # from this file; stderr still streams progress to the step log.
  docker run --rm -v "$SRC:/src" -v "$REPORTS:/reports" -v "$TRIVY_CACHE:/root/.cache/trivy" -w /src "$TRIVY_IMAGE" \
    config /src --severity HIGH,CRITICAL --exit-code 7 \
    --format json --output /reports/trivy-config.json 2>&1 | tee "$REPORTS/trivy-config.txt"
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
  # --skip-dirs stops it walking .git (full history, since callers use
  # fetch-depth: 0), node_modules and vendor - on the Node and PHP repos that is
  # the same transitive CVE reported many times over, plus dev-only dependencies
  # that never reach a shipped image.
  local skip=()
  for d in "${EXCLUDE_DIRS[@]}"; do skip+=(--skip-dirs "/src/$d"); done
  docker run --rm -v "$SRC:/src" -v "$REPORTS:/reports" -v "$TRIVY_CACHE:/root/.cache/trivy" -w /src "$TRIVY_IMAGE" \
    fs /src --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 7 \
    "${skip[@]}" --format json --output /reports/trivy-sca.json 2>&1 | tee "$REPORTS/trivy-sca.txt"
}

scan_trufflehog_fs() {
  echo "==> trufflehog (verified secrets — working tree)"
  # --fail makes trufflehog exit 183 on results, which is distinct from any
  # exit code it uses for its own failures. Nothing to translate.
  docker run --rm -v "$SRC:/src" -w /src "$TRUFFLEHOG_IMAGE" \
    filesystem /src --results=verified --fail 2>&1 | tee "$REPORTS/trufflehog-fs.txt"
}

scan_trufflehog_git() {
  echo "==> trufflehog (verified secrets — git history)"
  # The callers all check out with fetch-depth: 0 and the comment on that line
  # says "full history for secret detection" - but only gitleaks ever read it.
  # trufflehog filesystem walks the working tree, so a credential that was
  # committed and later deleted was invisible to the one scanner that verifies
  # its findings against the live provider. This is the invocation that reads
  # history.
  docker run --rm -v "$SRC:/src" -w /src "$TRUFFLEHOG_IMAGE" \
    git file:///src --results=verified --fail 2>&1 | tee "$REPORTS/trufflehog-git.txt"
}

scan_gitleaks() {
  echo "==> gitleaks (secrets)"
  # --exit-code 7 for the same reason as trivy: gitleaks uses 1 for leaks AND
  # for its own errors, so the default makes a failed run look like a leak -
  # and a leak hard-fails regardless of enforce, so a tool failure would surface
  # to the author as "you committed a secret".
  docker run --rm -v "$SRC:/src" -v "$REPORTS:/reports" -w /src "$GITLEAKS_IMAGE" \
    detect --source=/src --redact --exit-code 7 \
    --report-format sarif --report-path=/reports/gitleaks.sarif 2>&1 | tee "$REPORTS/gitleaks.txt"
}

scan_semgrep() {
  echo "==> semgrep (SAST)"
  # --error is REQUIRED: semgrep scan exits 0 on findings by default.
  # ai-platform run 32284064305 reported "170 findings" and still recorded PASS.
  # With --error, 1 means findings and >= 2 means semgrep itself failed
  # (2 fatal, 3 unparseable file, 4 invalid pattern, 5 bad config, 7 all rules
  # invalid, 8 unsupported language), so the two are already distinguishable.
  #
  # p/secrets runs here but is recorded warn, NOT secret. Its rules are
  # unverified pattern matches - the same class gitleaks produces a large false
  # -positive tail of - whereas the secret category hard-fails past enforce and
  # is reserved for trufflehog's provider-verified hits. Documented in the
  # README so the gating contract is not a surprise.
  docker run --rm -v "$SRC:/src" -v "$REPORTS:/reports" -w /src "$SEMGREP_IMAGE" \
    semgrep --config=p/default --config=p/secrets --error \
    --sarif --output=/reports/semgrep.sarif /src 2>&1 | tee "$REPORTS/semgrep.txt"
}

scan_trivy_image() {
  echo "==> trivy image ($IMAGE_REF)"
  # --image-src remote for the same reason syft gets an explicit registry:
  # prefix - trivy's default source order probes docker, containerd and podman
  # first, and no socket is mounted, so it spends the attempt failing to reach
  # daemons that are not there before falling through to the registry.
  docker run --rm -v "$REPORTS:/reports" -v "$TRIVY_CACHE:/root/.cache/trivy" \
    ${REG_AUTH[@]+"${REG_AUTH[@]}"} ${TRIVY_AWS_AUTH[@]+"${TRIVY_AWS_AUTH[@]}"} "$TRIVY_IMAGE" \
    image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 7 \
    --image-src remote --format json --output /reports/trivy-image.json "$IMAGE_REF" 2>&1 | tee "$REPORTS/trivy-image.txt"
}

# Dockerfiles anywhere in the tree, not just at the root - healthslate-backend
# keeps its at docker/Dockerfile, and a root-only check reads as "no Dockerfile".
#
# Dockerfile.* is deliberately narrowed: it swept in .j2, .template, .bak and
# .orig, none of which are valid Dockerfile syntax, so hadolint exited non-zero
# on a parse error and the repo sat permanently warn-ish for a file that is not
# a Dockerfile.
find_dockerfiles() {
  local prune=()
  for d in "${EXCLUDE_DIRS[@]}"; do prune+=(-not -path "*/$d/*"); done
  find "$SRC" -type f \( -name Dockerfile -o -name 'Dockerfile.*' \) \
    "${prune[@]}" 2>/dev/null \
  | while IFS= read -r f; do
      case "${f##*.}" in
        j2|jinja|jinja2|template|tmpl|bak|orig|sample|example|disabled|md) ;;
        *) echo "$f" ;;
      esac
    done
}

scan_hadolint() {
  echo "==> hadolint (Dockerfile lint)"
  # Was gated behind scan-image, which meant it never ran anywhere - it lints a
  # Dockerfile and has never needed a built image.
  local rc=0 one=0
  # tee goes INSIDE the loop on purpose. Piping the whole `while` into tee puts
  # the loop in a subshell, and rc dies with it - the function would then always
  # return 0 and every Dockerfile finding would be recorded as PASS.
  : > "$REPORTS/hadolint.txt"
  while IFS= read -r df; do
    [ -n "$df" ] || continue
    echo "--- ${df#$SRC/}" | tee -a "$REPORTS/hadolint.txt"
    # No "-" argument: this image has no entrypoint wrapper, so "-" is taken as
    # the command to exec and the container dies with 127. It reads stdin on its
    # own when given no file.
    docker run --rm -i "$HADOLINT_IMAGE" < "$df" 2>&1 | tee -a "$REPORTS/hadolint.txt"
    one=${PIPESTATUS[0]}
    # hadolint returns 1 for lint findings; anything else is hadolint (or
    # docker) failing, and that must not be laundered into "findings".
    if [ "$one" -eq 1 ]; then
      [ "$rc" -eq 0 ] && rc=1
    elif [ "$one" -ne 0 ]; then
      rc=$one
    fi
  done <<< "$(find_dockerfiles)"
  return $rc
}

scan_syft_source() {
  echo "==> syft (source SBOM)"
  # syft reads a directory as happily as an image, so the source SBOM is
  # available on every PR without waiting for a build.
  local ex=()
  for d in "${EXCLUDE_DIRS[@]}"; do ex+=(--exclude "./$d/**"); done
  docker run --rm -v "$SRC:/src" -v "$REPORTS:/reports" -w /src "$SYFT_IMAGE" \
    "dir:/src" "${ex[@]}" \
    -o "cyclonedx-json=/reports/sbom-source.cdx.json" \
    -o "spdx-json=/reports/sbom-source.spdx.json"
}

scan_syft_image() {
  echo "==> syft (image SBOM)"
  # registry: prefix is explicit on purpose - a bare ref makes syft try the local
  # docker daemon first, which never has the image because build-image pushes
  # with --push and no --load.
  docker run --rm -v "$REPORTS:/reports" ${REG_AUTH[@]+"${REG_AUTH[@]}"} "$SYFT_IMAGE" \
    "registry:$IMAGE_REF" \
    -o "cyclonedx-json=/reports/sbom.cdx.json" \
    -o "spdx-json=/reports/sbom.spdx.json"
}

# --- result recording ------------------------------------------------------
#
# THE BUG THIS REPLACES: record() mapped every non-zero exit to "findings", so a
# scanner that failed to start was indistinguishable from one that ran clean.
# With seven of eight scanners failing to pull, the summary read as five WARNs
# plus two "verified secret findings" that never happened - and because the
# secret category bypasses enforce, a registry hiccup surfaced to the author as
# "you committed a secret". Nothing in the output said otherwise.
#
# So every scanner declares the exit code it returns when it ran correctly AND
# found something. Anything else non-zero is the tool failing:
#
#   rc == 0              -> PASS
#   rc == findings_rc    -> findings   (WARN, or FAIL under enforce / secret)
#   any other non-zero   -> TOOL-ERROR
#
# The declared findings code is matched FIRST and exactly. A "high exit codes
# are always a tool error" shortcut looks right - 125 daemon refused, 126 not
# executable, 127 not found, 128+n killed by signal - and it is wrong here:
# trufflehog --fail returns 183 for a verified secret, so that shortcut
# downgraded real credential hits to "the scanner broke". Anything that is not
# the declared code is a tool error, which covers the 125+ range anyway.
#
# findings_rc of "none" means the tool has no findings exit code at all - the
# SBOM generators either work or fail - so every non-zero is a tool error.
#
# A tool error is never a secret hit. It warns under enforce=false and fails
# under enforce=true, because a scanner that did not run is a hole in coverage
# and enforce is the setting that says holes are not acceptable.
declare -a SUMMARY=()
record() {
  local name="$1" rc="$2" category="$3" findings_rc="$4" report="${5:-}"

  # A tool told to write a report that produced none did not scan, whatever it
  # returned. Checked before the exit code on purpose: it catches the bad-flag
  # case (flag rejected, tool gives up early, still exits 0) AND the crash case
  # (checkov's IsADirectoryError exits 1, indistinguishable from findings by
  # exit code alone). The report is the evidence the scan happened; no report,
  # no scan.
  if [ -n "$report" ] && [ ! -s "$REPORTS/$report" ]; then
    tool_errors=$((tool_errors + 1))
    [ "$ENFORCE" == "true" ] && fail=1
    SUMMARY+=("TOOL-ERROR  $name (exit $rc, wrote no $report — did not scan)")
    return
  fi

  if [ "$rc" -eq 0 ]; then
    SUMMARY+=("PASS  $name")
    return
  fi

  if [ "$findings_rc" == "none" ] || [ "$rc" -ne "$findings_rc" ]; then
    tool_errors=$((tool_errors + 1))
    [ "$ENFORCE" == "true" ] && fail=1
    SUMMARY+=("TOOL-ERROR  $name (exit $rc — failed to run, NOT a finding)")
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
scan_checkov;      record "checkov"      $? warn 1 "checkov.sarif"
scan_trivy_config; record "trivy-config" $? warn 7 "trivy-config.json"

# --- dependency CVEs (SCA) ---
scan_trivy_fs;     record "trivy-sca"    $? warn 7 "trivy-sca.json"

# --- secrets (always hard-fail on a hit) ---
scan_trufflehog_fs;  record "trufflehog-fs"  $? secret 183
if [ -d "$SRC/.git" ]; then
  scan_trufflehog_git; record "trufflehog-git" $? secret 183
else
  SUMMARY+=("SKIP  trufflehog-git (no .git — checkout needs fetch-depth: 0)")
fi
scan_gitleaks;     record "gitleaks"     $? secret 7 "gitleaks.sarif"

# --- SAST ---
scan_semgrep;      record "semgrep"      $? warn 1 "semgrep.sarif"

# --- Dockerfile lint (no image required) ---
if [ -n "$(find_dockerfiles)" ]; then
  scan_hadolint;   record "hadolint"     $? warn 1
else
  SUMMARY+=("SKIP  hadolint (no Dockerfile found)")
fi

# --- source SBOM (no image required) ---
scan_syft_source;  record "syft-sbom-source" $? warn none "sbom-source.cdx.json"

else
  SUMMARY+=("SKIP  source scans (mode=$MODE)")
fi

# --- image scans: need an image that already exists, so these only run when the
# caller passes a ref (post-build in duplo-pipeline, not at PR time) ---
if [ "$run_image" -eq 1 ] && [ "$SCAN_IMAGE" == "true" ] && [ -n "$IMAGE_REF" ]; then
  scan_trivy_image; record "trivy-image"     $? warn 7 "trivy-image.json"
  scan_syft_image;  record "syft-sbom-image" $? warn none "sbom.cdx.json"
elif [ "$run_image" -eq 1 ]; then
  SUMMARY+=("SKIP  image scans (scan-image!=true or image-ref empty)")
else
  SUMMARY+=("SKIP  image scans (mode=$MODE)")
fi

# --- reports back into the workspace ---------------------------------------
# Copied only now that no scanner is left to walk the tree. The action uploads
# this directory as a workflow artifact in the step after this one, so evidence
# survives the run without every caller having to remember an upload step.
mkdir -p "$SRC/$REPORT_DIR"
cp -R "$REPORTS/." "$SRC/$REPORT_DIR/" 2>/dev/null || true

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
echo "result=$RESULT"           >> "${GITHUB_OUTPUT:-/dev/null}"
echo "tool-errors=$tool_errors" >> "${GITHUB_OUTPUT:-/dev/null}"

if [ "$tool_errors" -gt 0 ]; then
  echo "Overall: $RESULT — $tool_errors scanner(s) FAILED TO RUN (see TOOL-ERROR above; these are not findings)"
  echo "::warning::$tool_errors security scanner(s) failed to run. Their coverage is missing from this result."
else
  echo "Overall: $RESULT"
fi

# render the same summary as the GitHub Actions job summary so results are
# visible on the run page without opening the step log
{
  echo "#### 🔒 security-scan — overall: $RESULT"
  if [ "$tool_errors" -gt 0 ]; then
    echo
    echo "> ⚠️ **$tool_errors scanner(s) failed to run.** Those lines are not findings — that coverage is simply missing."
  fi
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
      TOOL-ERROR) icon="🧨" ;;
      *) icon="•" ;;
    esac
    echo "| $icon $status | $detail |"
  done
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

# Itemise the findings underneath the table. The table says a scanner found
# something; on its own that still means "go read the step log", which is the
# complaint the summary was added to fix. summarize.py reads the scanners' own
# report files and prints rule + severity + file:line - never a matched value.
#
# Never allowed to affect the result: this is reporting, and a reporting bug
# must not turn into a scan verdict.
# GITHUB_ACTION_PATH is only set when this runs as a composite action; fall back
# to the script's own directory so a direct run (the self-test, or a local
# reproduction) behaves the same. Unguarded it is an unbound-variable abort
# under set -u, which would take the whole scan down at the last line.
ACTION_DIR="${GITHUB_ACTION_PATH:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
findings_total=0
if [ -x "$ACTION_DIR/summarize.py" ] && command -v python3 >/dev/null 2>&1; then
  if n="$(REPORTS="$REPORTS" python3 "$ACTION_DIR/summarize.py" "$REPORTS" 2>/dev/null)"; then
    case "$n" in (''|*[!0-9]*) : ;; (*) findings_total="$n" ;; esac
    if [ -s "$REPORTS/summary.md" ]; then
      cat "$REPORTS/summary.md" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
      # and to the step log, so the findings are readable in both places
      sed -e 's/<[^>]*>//g' -e '/^$/d' "$REPORTS/summary.md"
      cp "$REPORTS/summary.md" "$SRC/$REPORT_DIR/summary.md" 2>/dev/null || true
    fi
  else
    echo "note: could not render the findings summary (the scan result above is unaffected)"
  fi
fi
echo "findings=$findings_total" >> "${GITHUB_OUTPUT:-/dev/null}"

exit "$should_exit"
