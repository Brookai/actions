#!/usr/bin/env bash
#
# Self-test for summarize.py.
#
# The regression that matters: a result the tool itself suppressed - SARIF
# suppressions[], written by a "# nosemgrep" or "checkov:skip=" annotation - is
# not a finding. The tool's own exit code and tally already exclude it, so
# counting it here contradicts the status row. Observed on care-nexus run
# 33128486556, where checkov reported "Failed checks: 0, Skipped checks: 2" and
# the summary rendered "checkov - 2 findings".
#
# No docker: this is pure rendering.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SUMMARIZE="$HERE/../summarize.py"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
pass=0; failed=0

check() {
  local desc="$1" want="$2" got="$3"
  if [ "$want" == "$got" ]; then printf '  ok    %s\n' "$desc"; pass=$((pass+1))
  else printf '  FAIL  %s (wanted %s, got %s)\n' "$desc" "$want" "$got"; failed=$((failed+1)); fi
}

sarif() { # $1 file  $2 json-results
  cat > "$WORK/$1" <<EOF
{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","rules":[
  {"id":"R1","defaultConfiguration":{"level":"error"}}]}},"results":[$2]}]}
EOF
}
res() { # $1 line  $2 extra
  echo "{\"ruleId\":\"R1\",\"message\":{\"text\":\"m\"},${2:-}\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"/src/a.tf\"},\"region\":{\"startLine\":$1}}}]}"
}

echo "summarize.py rendering"

# 3 results, none suppressed
sarif checkov.sarif "$(res 1),$(res 2),$(res 3)"
check "counts unsuppressed results" 3 "$(REPORTS="$WORK" python3 "$SUMMARIZE" "$WORK")"

# 3 results, 1 suppressed in source
sarif checkov.sarif "$(res 1),$(res 2 '"suppressions":[{"kind":"inSource"}],'),$(res 3)"
check "excludes an inSource-suppressed result" 2 "$(REPORTS="$WORK" python3 "$SUMMARIZE" "$WORK")"

# all suppressed -> the scanner passed, so nothing should be shown at all
sarif checkov.sarif "$(res 1 '"suppressions":[{"kind":"inSource"}],'),$(res 2 '"suppressions":[{"kind":"inSource","justification":"reviewed"}],')"
check "a fully-suppressed scanner reports zero" 0 "$(REPORTS="$WORK" python3 "$SUMMARIZE" "$WORK")"
if grep -q "checkov" "$WORK/summary.md" 2>/dev/null; then
  echo "  FAIL  a fully-suppressed scanner must not get a findings section"; failed=$((failed+1))
else
  echo "  ok    a fully-suppressed scanner gets no findings section"; pass=$((pass+1))
fi

# an empty suppressions array is not a suppression
sarif checkov.sarif "$(res 1 '"suppressions":[],')"
check "an empty suppressions[] still counts" 1 "$(REPORTS="$WORK" python3 "$SUMMARIZE" "$WORK")"

# rollup past the cap still counts everything
rm -f "$WORK/checkov.sarif"
big=""; for i in $(seq 1 40); do [ -n "$big" ] && big="$big,"; big="$big$(res "$i")"; done
sarif semgrep.sarif "$big"
check "rolls up but still counts all findings" 40 "$(REPORTS="$WORK" python3 "$SUMMARIZE" "$WORK")"
grep -q "Rolled up by rule" "$WORK/summary.md" && { echo "  ok    past the cap it rolls up"; pass=$((pass+1)); } \
  || { echo "  FAIL  expected a rollup past the cap"; failed=$((failed+1)); }

# trivy JSON, and its suppression-free path
rm -f "$WORK/semgrep.sarif"
cat > "$WORK/trivy-sca.json" <<'EOF'
{"Results":[{"Target":"go.mod","Vulnerabilities":[
 {"VulnerabilityID":"CVE-1","PkgName":"p","InstalledVersion":"1","FixedVersion":"2","Severity":"HIGH","Title":"t"}]}]}
EOF
check "reads trivy JSON" 1 "$(REPORTS="$WORK" python3 "$SUMMARIZE" "$WORK")"
grep -q "fixed in 2" "$WORK/summary.md" && { echo "  ok    CVE rows carry the fixed-in version"; pass=$((pass+1)); } \
  || { echo "  FAIL  expected the fixed-in version on a CVE row"; failed=$((failed+1)); }

echo
echo "$pass passed, $failed failed"
[ "$failed" -eq 0 ]
