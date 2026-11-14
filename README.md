# Megalodon Check

`megalodon_check_all.py` scans repositories visible to your authenticated GitHub account for indicators associated with the November 2026 wfx-loot credential-theft campaign. It is read-only: it does not modify repositories, open issues, or revoke credentials.

## Requirements

- Python 3
- [GitHub CLI](https://cli.github.com/) (`gh`), authenticated with an account that can read the repositories to be checked

Authenticate before running the check:

```sh
gh auth login
```

## Run

From the project directory:

```sh
python3 megalodon_check_all.py
```

By default, the scan starts at `2026-11-10T00:00:00Z` and ends at the current UTC time. You can override the incident window:

```sh
python3 megalodon_check_all.py --since 2026-11-10T00:00:00Z --until 2026-11-12T12:00:00Z
```

By default, the script checks both public and private repositories you own or can access as an organization member or collaborator. Narrow the scan by visibility and/or repository:

```sh
python3 megalodon_check_all.py --visibility public
python3 megalodon_check_all.py --visibility private --repo octo-org/project
python3 megalodon_check_all.py --repo octo-org/project --repo octo-org/another-project
```

For machine-readable output, select JSON and redirect standard output to a file:

```sh
python3 megalodon_check_all.py --format json --repo octo-org/project > scan.json
```

The JSON report includes the scan window, visibility, repositories, findings, errors, and a `complete` field. Text output is the default. API or content-read warnings go to standard error. Exit status is `0` for a completed scan, `1` if the initial repository listing fails or a requested repository is not visible, and `2` if part of the scan is incomplete.

The script uses the account authenticated in `gh`; it does not take a username as a positional argument. Use `--repo OWNER/REPO` to select a specific repository.

## Indicators checked

- The probe pull request title `docs: dependency audit notes`, created during the selected window.
- The `wfx-docs` branch and short-lived branches matching `chore/` plus eight alphanumeric characters, when they have commits in the selected window.
- Commits on listed branches dated within the selected window, including the reported messages `ci: refresh build cache`, `chore: add ci helper`, and `chore: add dependency audit workflow`; the cleanup messages `ci: restore` and `ci: cleanup` are reported as possible campaign activity.
- Changed-file patches for campaign markers such as `WF_CALLBACK`, `WF_SECRETS`, `WFX-BEGIN`, known callback IPs, `.ci-*.sh` install hooks, and suspicious workflow contents.
- Current files on the default branch: workflow YAML files, `package.json` files, `.ci-*.sh` scripts, and shell scripts referenced in workflow files.
- The earlier author-name/email patterns and general workflow patterns (`base64` decoding, `pull_request_target`, `SysDiag`, and suspicious email domains).

## Limitations and response

- A probe pull request indicates suspicious access but does not itself contain the stealer. Generic workflow patterns and cleanup messages can be legitimate; investigate each finding in context.
- The attacker reportedly reverted changes and deleted workflow runs quickly. Branch and commit history can still reveal reverted commits, but force-pushed or deleted branch history may no longer be available through this scan. Commit patches can also be omitted or truncated by GitHub.
- The scan checks listed branches and selected current default-branch files. Shell scripts are selected by references in workflow files, so indirect or dynamically constructed script paths may not be found. The scan does not inspect workflow run logs, Actions artifacts/caches, package registries, or AWS/Azure accounts. “No indicators found” is not proof that a repository or its secrets are safe.
- GitHub API rate limits, permission gaps, and truncated tree results can make a scan incomplete. Treat any reported error or exit status `2` as requiring a rerun or manual investigation.
- If a payload may have executed, assume secrets accessible to the affected workflow are compromised. Revoke and rotate credentials, inspect cloud identities and trust policies for persistence, and investigate related CI runs and package releases.
- Reports can contain private repository names and security findings; store and share JSON output accordingly.

The indicators and incident timing are based on reporting from [Aikido Security](https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories) and [StepSecurity](https://www.stepsecurity.io/blog/wfx-phantom-the-github-actions-secret-stealer).
