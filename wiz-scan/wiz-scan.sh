#!/usr/bin/env bash
set -uo pipefail

# no-op until Wiz access lands — keeps the action safe to wire into workflows early
if [ -z "$WIZ_CLIENT_ID" ] || [ -z "$WIZ_CLIENT_SECRET" ]; then
  echo "::notice::Wiz creds not set — skipping (add WIZ_CLIENT_ID/WIZ_CLIENT_SECRET org secrets to enable)"
  echo "result=skipped" >> "$GITHUB_OUTPUT"
  exit 0
fi

# NOTE: wizcli 0.x EOL 2026-04-15 — use 1.x
# verify current version
curl -sSL -o wizcli "https://downloads.wiz.io/wizcli/$WIZCLI_VERSION/wizcli-linux-amd64"
chmod +x wizcli

./wizcli auth --id "$WIZ_CLIENT_ID" --secret "$WIZ_CLIENT_SECRET"

fail=0

if [ "$MODE" == "iac" ] || [ "$MODE" == "both" ]; then
  echo "==> wiz iac scan ($SCAN_PATH)"
  ./wizcli iac scan --path "$SCAN_PATH" || fail=1
fi

if [ "$MODE" == "image" ] || [ "$MODE" == "both" ]; then
  if [ -n "$IMAGE_REF" ]; then
    echo "==> wiz docker scan ($IMAGE_REF)"
    ./wizcli docker scan --image "$IMAGE_REF" || fail=1
  else
    echo "::notice::mode includes image but image-ref is empty — skipping image scan"
  fi
fi

# only enforce blocks the job; otherwise findings are warn-only
if [ "$fail" -eq 1 ] && [ "$ENFORCE" == "true" ]; then
  echo "result=fail" >> "$GITHUB_OUTPUT"
  echo "Overall: fail (enforce=true)"
  exit 1
fi

if [ "$fail" -eq 1 ]; then
  echo "result=fail" >> "$GITHUB_OUTPUT"
  echo "Overall: fail (warn-only — set enforce=true to block)"
else
  echo "result=pass" >> "$GITHUB_OUTPUT"
  echo "Overall: pass"
fi
exit 0
