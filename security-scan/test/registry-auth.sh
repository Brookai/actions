#!/usr/bin/env bash
#
# Self-test for how private-registry credentials reach the scanner containers.
#
# The bug this exists to catch (2026-08-28, first real ECR build across the
# fleet): the config was mounted at /root/.docker/config.json, which assumes
# every scanner image runs as root with HOME=/root. trivy does. syft does not -
# its image carries no /etc/passwd and no /root, so docker sets HOME=/ and
# go-containerregistry reads /.docker/config.json instead. syft never saw the
# credentials, did not warn, and authenticated as nobody, which the registry
# returned as a 401. trivy scanned the same image fine, so the failure looked
# like a syft bug rather than an auth-delivery bug.
#
# Two halves:
#   A. flag shape        - DOCKER_CONFIG is set and agrees with the mount.
#                          Stubbed docker, no network.
#   B. the images agree  - the REAL syft and trivy images actually READ the
#                          config we hand them. This is the half that would
#                          have caught the original bug, because it asserts
#                          image behaviour rather than our belief about it.
#                          Skipped when docker is unavailable.
#
# Run: security-scan/test/registry-auth.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCAN_SH="$HERE/../scan.sh"
[ -x "$SCAN_SH" ] || { echo "scan.sh not found or not executable at $SCAN_SH"; exit 1; }

# Keep in step with scan.sh. Pinned by digest there; same digests here so the
# live half tests what the action actually runs.
SYFT_IMAGE="$(grep -oP '^SYFT_IMAGE="\K[^"]+' "$SCAN_SH")"
TRIVY_IMAGE="$(grep -oP '^TRIVY_IMAGE="\K[^"]+' "$SCAN_SH")"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/src" "$WORK/bin" "$WORK/tmp" "$WORK/home/.docker"
echo "FROM alpine:3.19" > "$WORK/src/Dockerfile"

# A config with an inline auth, which is what amazon-ecr-login writes. The auth
# value is built at run time rather than written literally: a base64 user:pass
# blob in a tracked file is exactly what gitleaks is meant to catch, and it
# caught this one. Nothing here needs a real credential - scan.sh only checks
# that the entry is non-empty - so generate it rather than allowlist it.
FAKE_AUTH="$(printf 'AWS:not-a-real-token' | base64 | tr -d '\n')"
cat > "$WORK/home/.docker/config.json" <<CFG
{"auths":{"123456789012.dkr.ecr.us-east-1.amazonaws.com":{"auth":"$FAKE_AUTH"}}}
CFG

# docker stub: records argv per invocation, writes the report so record() is happy.
cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$ARGV_LOG"
R=""; prev=""
for a in "$@"; do
  if [ "$prev" = "-v" ]; then case "$a" in *:/reports) R="${a%:/reports}" ;; esac; fi
  prev="$a"
done
if [ -n "$R" ]; then
  case "$*" in
    *syft*registry:*)  echo '{}' > "$R/sbom.cdx.json" ;;
    *syft*)            echo '{}' > "$R/sbom-source.cdx.json" ;;
    *trivy*" image "*) echo '{}' > "$R/trivy-image.json" ;;
  esac
fi
exit 0
STUB
chmod +x "$WORK/bin/docker"

pass=0; failed=0
ok()   { printf '  ok    %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  FAIL  %s\n        %s\n' "$1" "$2"; failed=$((failed + 1)); }

# run_scan <argv-log> [ENV=VAL ...] - image mode, so the image scanners run
run_scan() {
  local log="$1"; shift
  : > "$log"
  ( export PATH="$WORK/bin:$PATH" SCAN_PATH="$WORK/src" REPORT_DIR="scan-reports" \
      MODE="image" ENFORCE="false" SCAN_IMAGE="true" \
      IMAGE_REF="123456789012.dkr.ecr.us-east-1.amazonaws.com/app:v1" \
      GITHUB_OUTPUT="$WORK/gh_output" GITHUB_STEP_SUMMARY="$WORK/gh_summary" \
      RUNNER_TEMP="$WORK/tmp" ARGV_LOG="$log" HOME="$WORK/home" "$@"
    bash "$SCAN_SH" >/dev/null 2>&1 )
}

echo "security-scan registry-auth delivery"
echo
echo "A. flag shape (stubbed docker)"

LOG="$WORK/argv.txt"
run_scan "$LOG"

syft_line="$(grep -m1 'syft.*registry:' "$LOG" || true)"
trivy_line="$(grep -m1 'trivy.* image ' "$LOG" || true)"

# 1. DOCKER_CONFIG must be passed - this is the whole fix. A mount alone is not
#    enough, because where the container looks depends on its HOME.
for pair in "syft:$syft_line" "trivy:$trivy_line"; do
  who="${pair%%:*}"; line="${pair#*:}"
  if [ -z "$line" ]; then
    bad "$who image scan ran" "no $who invocation recorded"
  elif grep -q -- '-e DOCKER_CONFIG=' <<<"$line"; then
    ok "$who receives -e DOCKER_CONFIG"
  else
    bad "$who receives -e DOCKER_CONFIG" "not passed; container falls back to \$HOME, which differs per image"
  fi
done

# 2. The directory mounted must be exactly what DOCKER_CONFIG names. A mismatch
#    is silent - the scanner authenticates as nobody and the registry 401s.
for pair in "syft:$syft_line" "trivy:$trivy_line"; do
  who="${pair%%:*}"; line="${pair#*:}"
  cfgdir="$(grep -oP -- '-e DOCKER_CONFIG=\K[^ ]+' <<<"$line" | head -1)"
  if [ -n "$cfgdir" ] && grep -qP -- "-v [^ ]+:${cfgdir}(:ro)?( |\$)" <<<"$line"; then
    ok "$who mount target matches DOCKER_CONFIG ($cfgdir)"
  else
    bad "$who mount target matches DOCKER_CONFIG" "DOCKER_CONFIG=$cfgdir has no matching -v mount"
  fi
done

# 3. The old shape must not come back.
if grep -q '/root/.docker/config.json' "$LOG"; then
  bad "no bare /root/.docker mount" "mounting into /root assumes HOME=/root, which is false for syft"
else
  ok "no bare /root/.docker mount"
fi

# 4. Credential-helper-only config: nothing mountable, so trivy gets the AWS_*
#    fallback instead. syft cannot use AWS_* and is expected to go without.
echo '{"auths":{"x.io":{}},"credsStore":"desktop"}' > "$WORK/home/.docker/config.json"
LOG2="$WORK/argv-helper.txt"
run_scan "$LOG2" AWS_ACCESS_KEY_ID=k AWS_SECRET_ACCESS_KEY=s
if grep -q 'DOCKER_CONFIG=' "$LOG2"; then
  bad "helper-only config is not mounted" "mounted a config the container cannot use"
else
  ok "helper-only config is not mounted"
fi
if grep -m1 'trivy.* image ' "$LOG2" | grep -q -- '-e AWS_ACCESS_KEY_ID'; then
  ok "trivy gets the AWS_* fallback when there is no usable config"
else
  bad "trivy gets the AWS_* fallback" "no AWS_* forwarded, so ECR is unreachable by any route"
fi

echo
echo "B. the scanner images actually read it (live)"
if ! docker info >/dev/null 2>&1; then
  echo "  skip  docker unavailable"
else
  # Hand each image a config that is valid JSON to docker but garbage to the
  # parser, at exactly the path/flags scan.sh uses. If the scanner reads it, it
  # says so by name. If it silently ignores it - the original bug - it succeeds
  # and we fail the test.
  BROKEN="$WORK/broken"; mkdir -p "$BROKEN"
  echo 'THIS IS NOT JSON' > "$BROKEN/config.json"
  CFGDIR="$(grep -oP '^REG_CFG_DIR="\K[^"]+' "$SCAN_SH")"
  [ -n "$CFGDIR" ] || CFGDIR=/tmp/.docker-scan-auth

  probe() { # <name> <image> <args...>
    local name="$1" image="$2"; shift 2
    local out
    out="$(docker run --rm -v "$BROKEN:$CFGDIR:ro" -e "DOCKER_CONFIG=$CFGDIR" \
             "$image" "$@" 2>&1 >/dev/null)"
    if grep -qF "$CFGDIR/config.json" <<<"$out"; then
      ok "$name reads the config we deliver"
    else
      bad "$name reads the config we deliver" \
          "no reference to $CFGDIR/config.json in its output — it is not reading what we mount"
    fi
  }
  probe "syft"  "$SYFT_IMAGE"  "registry:alpine:3.19" -o cyclonedx-json
  probe "trivy" "$TRIVY_IMAGE" image --image-src remote -q alpine:3.19
fi

echo
echo "  $pass passed, $failed failed"
[ "$failed" -eq 0 ]
