# Security Scan GitHub Action

Runs IaC misconfig, secret, SAST, and (optionally) container image scans. Every tool runs from a **pinned docker image** — no marketplace actions — so it stays compliant under the org's verified/in-org-only action policy.

Tools:

- **IaC misconfig**: checkov, trivy config
- **Secrets**: trufflehog (verified only), gitleaks
- **SAST**: semgrep (`p/default` + `p/secrets`)
- **Image** (opt-in): trivy image, hadolint, syft SBOM

## Inputs

| Name         | Description                                                                 | Required | Default        |
| ------------ | --------------------------------------------------------------------------- | -------- | -------------- |
| `enforce`    | When `true`, non-secret HIGH/CRITICAL findings fail the job.                | No       | `false`        |
| `scan-image` | When `true` (and `image-ref` set), also scan the container image.           | No       | `false`        |
| `image-ref`  | Image reference to scan when `scan-image` is `true`.                         | No       | `""`           |
| `path`       | Path to scan for IaC, secrets, and SAST.                                     | No       | `.`            |
| `report-dir` | Directory to write scan reports into.                                       | No       | `scan-reports` |

## Outputs

| Name     | Description                          | Example |
| -------- | ------------------------------------ | ------- |
| `result` | Overall scan result (`pass`/`fail`). | `pass`  |

## Usage

```yaml
name: Security

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Security Scan
        uses: Brookai/actions/security-scan@main
        with:
          enforce: "false"       # warn-first; flip to "true" once the repo is clean
          scan-image: "true"
          image-ref: 173008660334.dkr.ecr.us-east-1.amazonaws.com/my-service:${{ github.sha }}
          path: "."
          report-dir: "scan-reports"

      - name: Upload scan reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: scan-reports
          path: scan-reports
```

## Gating behaviour

- **Secrets always block.** A verified trufflehog hit or a gitleaks leak fails the job regardless of `enforce` — a verified secret is never a false positive.
- **Everything else respects `enforce`.** checkov / trivy / semgrep / hadolint findings only fail the job when `enforce: "true"`. Otherwise they print and the step stays green (warn-only).

### Warn-first → enforce rollout

Start with `enforce: "false"` so the scan surfaces findings without blocking merges. Triage and burn down the backlog, then flip `enforce: "true"` to make new HIGH/CRITICAL findings hard failures. Secret detection is hard-fail from day one either way.

## Private-repo SARIF caveat

Reports (SARIF, SBOM) land in `report-dir` and are meant to be uploaded as **workflow artifacts** (see the `upload-artifact` step above). We deliberately do **not** upload SARIF to the GitHub Security tab: code scanning on private repos requires GitHub Advanced Security (added cost) and pulls the results into Code Security, whose action/tooling allowlisting is ambiguous under the org's verified-only policy. Keep the evidence in artifacts and review it there.
