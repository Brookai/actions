# Security Scan GitHub Action

Runs IaC misconfig, dependency-CVE, secret, SAST, Dockerfile-lint, SBOM and (optionally) container image scans. Every tool runs from a **digest-pinned docker image** — no marketplace actions — so it stays compliant under the org's verified/in-org-only action policy.

## Tools

| Scanner | What it looks at | Category | Needs a built image |
| --- | --- | --- | --- |
| checkov | IaC misconfig — terraform, kubernetes, dockerfile, github_actions, secrets | warn | no |
| trivy config | IaC misconfig | warn | no |
| trivy fs | **dependency CVEs (SCA)** — `pom.xml`, `package-lock.json`, `requirements.txt`, `go.mod`, `composer.lock`, `build.gradle*` | warn | no |
| trufflehog (filesystem) | verified secrets in the working tree | **secret** | no |
| trufflehog (git) | verified secrets in **git history** | **secret** | no |
| gitleaks | secrets, working tree + history | **secret** | no |
| semgrep | SAST (`p/default` + `p/secrets`) | warn | no |
| hadolint | every Dockerfile in the tree | warn | no |
| syft | source SBOM (CycloneDX + SPDX) | warn | no |
| trivy image | image CVEs | warn | **yes** |
| syft (image) | image SBOM | warn | **yes** |

## Inputs

| Name | Description | Required | Default |
| --- | --- | --- | --- |
| `enforce` | When `true`, non-secret findings **and scanner failures** fail the job. | No | `false` |
| `mode` | `all`, `source`, or `image`. `both`/`iac` accepted as aliases of `all`/`source`. | No | `all` |
| `scan-image` | When `true` (and `image-ref` set), also scan the built container image. | No | `false` |
| `image-ref` | Image reference to scan. Must already exist — pass `duplo-build`'s `image_uri`. | No | `""` |
| `path` | Path to scan. | No | `.` |
| `report-dir` | Directory the reports are copied into when the run finishes. | No | `scan-reports` |

## Outputs

| Name | Description | Example |
| --- | --- | --- |
| `result` | Overall scan result (`pass`/`fail`). | `pass` |
| `tool-errors` | Count of scanners that **failed to run**. Non-zero with `result=pass` means the scan was incomplete. | `0` |

## Gating behaviour

Three outcomes, not two. The distinction between the second and third is the point.

- **PASS** — the scanner ran and found nothing.
- **WARN / FAIL (findings)** — the scanner ran and found something. Respects `enforce`, except for the secret category.
- **TOOL-ERROR** — the scanner **did not run**. A denied image pull, a rate-limited database download, a bad flag, a crash. This is not a finding and is never reported as one; it warns under `enforce: "false"` and fails under `enforce: "true"`, because a scanner that did not run is a hole in coverage.

Every scanner declares the exit code it returns when it ran correctly *and* found something. Anything else non-zero is the tool failing:

| scanner | findings exit code | anything else non-zero |
| --- | --- | --- |
| checkov | 1 | tool error |
| trivy (config / fs / image) | **7** (`--exit-code 7`) | tool error — trivy uses 1 for its own errors |
| gitleaks | **7** (`--exit-code 7`) | tool error — gitleaks uses 1 for both by default |
| trufflehog | **183** (`--fail`) | tool error |
| semgrep | 1 (`--error`) | tool error — semgrep uses ≥2 for its own errors |
| hadolint | 1 | tool error |
| syft | *(none — it either works or fails)* | tool error |

Scanners that write a report are additionally checked for having written one: a tool that returns success having produced no output did not scan anything.

### Secrets

- **Verified secrets always block.** A trufflehog hit (working tree or git history) or a gitleaks leak fails the job regardless of `enforce` — a verified secret is never a false positive.
- **semgrep's `p/secrets` rules are warn-only, by design.** They are unverified pattern matches, the same class that produces gitleaks' large false-positive tail, whereas the secret category hard-fails past `enforce` and is reserved for provider-verified hits. A credential caught *only* by semgrep logs WARN and does not block.

### Warn-first → enforce rollout

Start with `enforce: "false"` so the scan surfaces findings without blocking merges. Triage and burn down the backlog, then flip `enforce: "true"`. Secret detection is hard-fail from day one either way. Note that `enforce: "true"` also makes scanner failures blocking — that is deliberate, and the reason the TOOL-ERROR state had to exist before `enforce` was worth setting anywhere.

## Usage

```yaml
name: Security

on:
  pull_request:
  push:
    branches: [main]

# Do not let the job token inherit the repository default. Seven third-party
# containers run here with the repo bind-mounted and network access; they have
# no business with write on contents, actions or checks.
permissions:
  contents: read

# ~7 container pulls dominate the runtime, so superseded runs are pure waste.
concurrency:
  group: security-scan-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # full history — both secret scanners read it

      - name: Security Scan
        id: scan
        uses: Brookai/actions/security-scan@<sha>
        with:
          enforce: "false"       # warn-first; flip to "true" once the repo is clean
          path: "."
          report-dir: "scan-reports"

      - name: Upload scan reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: scan-reports
          path: scan-reports
```

### Post-build image scan

`mode: image` skips the source scans so a post-build step does not repeat what the PR-time run already did. Run it as a **step inside the existing build job**, on the image that was just pushed:

```yaml
      - name: Scan the built image
        if: steps.build.outputs.uri != ''   # match the build step's own guard
        uses: Brookai/actions/security-scan@<sha>
        with:
          mode: image
          scan-image: "true"
          image-ref: ${{ steps.build.outputs.uri }}
          enforce: "false"
```

Two things to get right:

1. **Give the scan step the same `if:` guard as the build steps beside it.** In a repo with a `should_build` gate the build steps skip, and an unguarded scan step then runs with an empty `image-ref`, logs `SKIP image scans` and exits 0 — a green security check that scanned nothing, on every skipped build.
2. **`mode: image` does no secret scanning.** That is correct where a PR-time source scan already exists, and wrong where it does not. Land the source-scan workflow in a repo before the image scan, or the repo ends up with image CVE scanning and no secret detection at all.

## What the run page shows

The job summary carries two things: the PASS / WARN / FAIL / TOOL-ERROR table per scanner, and
underneath it **the findings themselves** — severity, rule, and `file:line`, grouped per scanner in
collapsible sections. Past 25 findings for one scanner it rolls up by rule with counts and an
example location, so a 400-CVE image report stays readable. Dependency and image CVEs carry the
fixed-in version, which is usually the only thing you need to act.

The same rendering goes to the step log, so it is readable in both places.

**Rule and location only — never the matched value.** gitleaks and semgrep both carry the matching
line in their SARIF, and a job summary is durable and widely readable. Locations are enough to act
on. Full reports are in the `scan-reports` artifact.

Rendering is done by `summarize.py` and can never change the scan result: if it fails, the scan
verdict above it is unaffected and the step notes that the summary could not be rendered.

## Reports

Scanning happens against a directory **outside** the checked-out tree, then the reports are copied into `report-dir` at the end. They used to be written inside it, which meant each scanner walked the earlier ones' output — a secret quoted in a SARIF finding snippet became a fresh finding of its own.

SARIF from checkov, gitleaks and semgrep; JSON from the three trivy scans; CycloneDX + SPDX SBOMs from syft; console transcripts alongside, so a finding survives the run rather than living in a step log that ages out.

### Private-repo SARIF caveat

Reports are meant to be uploaded as **workflow artifacts** (see the `upload-artifact` step above). We deliberately do **not** upload SARIF to the GitHub Security tab: code scanning on private repos requires GitHub Advanced Security (added cost) and pulls the results into Code Security, whose action/tooling allowlisting is ambiguous under the org's verified-only policy. Keep the evidence in artifacts and review it there.

## Registry authentication for the image scans

trivy and syft run inside their own containers, so they do not inherit the runner's ECR login. The action mounts the runner's docker config — the registry-scoped short-lived token `amazon-ecr-login` writes — into both, honouring `DOCKER_CONFIG`.

Only the inline `auths` entries are mounted. A config that delegates to a credential helper (`credsStore`, `credHelpers`) names a binary that does not exist inside the scanner container, and trivy dies with a FATAL init error before it looks at the image. `amazon-ecr-login` writes inline auths, so on a GitHub runner this filter is a no-op.

`AWS_*` credentials are forwarded to trivy only, and only when there is no docker config to use instead. syft resolves registry auth through go-containerregistry and does not consume `AWS_*` for ECR at all, so forwarding a session token to it would buy nothing but blast radius.

## Bumping a scanner

Images are pinned by digest, with the human-readable tag in a trailing comment. To bump one:

```bash
docker manifest inspect <image>:<new-tag> --verbose | jq -r '.Descriptor.digest'
```

Then update both the digest and the comment in `scan.sh`.
