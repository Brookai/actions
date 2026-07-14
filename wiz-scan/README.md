# Wiz Scan GitHub Action

Runs Wiz IaC and container image scans using the pinned `wizcli` binary (downloaded via curl — no marketplace action), so it stays compliant under the org's verified/in-org-only action policy.

## Inputs

| Name             | Description                                          | Required | Default  |
| ---------------- | ---------------------------------------------------- | -------- | -------- |
| `mode`           | What to scan — `iac`, `image`, or `both`.            | No       | `both`   |
| `image-ref`      | Image reference to scan when `mode` includes image.  | No       | `""`     |
| `path`           | Path to scan for IaC.                                | No       | `.`      |
| `enforce`        | When `true`, a Wiz policy failure fails the job.     | No       | `false`  |
| `wizcli-version` | `wizcli` version to download (1.x line).             | No       | `latest` |

## Outputs

| Name     | Description                                    | Example   |
| -------- | --------------------------------------------- | --------- |
| `result` | Overall result (`pass`, `fail`, `skipped`).   | `skipped` |

## Credentials

Needs two org secrets:

- `WIZ_CLIENT_ID`
- `WIZ_CLIENT_SECRET`

Expose them as env for the step (the action reads `env.WIZ_CLIENT_ID` / `env.WIZ_CLIENT_SECRET`). **Without them the action no-ops** — it prints a `::notice::`, sets `result=skipped`, and exits 0. That's intentional so you can wire it into workflows now and it starts scanning the moment Wiz access lands.

## Usage

```yaml
name: Wiz

on:
  pull_request:
  push:
    branches: [main]

jobs:
  wiz:
    runs-on: ubuntu-latest
    env:
      WIZ_CLIENT_ID: ${{ secrets.WIZ_CLIENT_ID }}
      WIZ_CLIENT_SECRET: ${{ secrets.WIZ_CLIENT_SECRET }}
    steps:
      - uses: actions/checkout@v4

      - name: Wiz Scan
        uses: Brookai/actions/wiz-scan@main
        with:
          mode: both
          image-ref: 173008660334.dkr.ecr.us-east-1.amazonaws.com/my-service:${{ github.sha }}
          path: "."
          enforce: "false"   # warn-first; flip to "true" to block on policy failures
```

## Pair with the Wiz Code GitHub app

This action gives you CI-side scanning. For inline **PR findings and comments**, install the Wiz Code GitHub app on the org so Wiz can annotate pull requests directly. The two are complementary — the app surfaces findings on the PR, this action gates the pipeline.
