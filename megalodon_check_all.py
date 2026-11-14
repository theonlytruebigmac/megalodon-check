import argparse
import base64
import json
import posixpath
import re
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import quote


CAMPAIGN_START = "2026-11-10T00:00:00Z"
CAMPAIGN_PR_TITLE = "docs: dependency audit notes"
CAMPAIGN_COMMIT_MESSAGES = {
    "ci: refresh build cache",
    "chore: add ci helper",
    "chore: add dependency audit workflow",
}
CAMPAIGN_CLEANUP_MESSAGES = {"ci: restore", "ci: cleanup"}
BAD_NAMES = re.compile(
    r"build-bot|auto-ci|ci-bot|pipeline-bot|build-system", re.I
)
BAD_EMAILS = {"build-system@noreply.dev", "ci-bot@automated.dev"}
CAMPAIGN_CONTENT = re.compile(
    r"wfx-loot|wfx-|WF_(?:CALLBACK|SECRETS|VARS|CTOKEN)|WFX-BEGIN|"
    r"194\.150\.166\.244|18\.143\.168\.96|153\.75\.82\.159",
    re.I,
)
GENERIC_WORKFLOW_PATTERNS = (
    ("base64 decode", re.compile(r"base64\s+(-d|--decode)", re.I)),
    ("pull_request_target", re.compile(r"pull_request_target", re.I)),
    ("SysDiag", re.compile(r"SysDiag", re.I)),
    ("suspicious email domain", re.compile(r"noreply\.dev|automated\.dev", re.I)),
)
SHELL_SCRIPT_REFERENCE = re.compile(
    r"(?<![\w.-])(?:\.\.?/)?[\w./-]+\.sh\b",
    re.I,
)


def gh(path, **params):
    command = ["gh", "api", "--paginate", path]
    for key, value in params.items():
        command.extend(["-f", f"{key}={value}"])
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        return None, result.stderr.strip()

    output = []
    decoder = json.JSONDecoder()
    text = result.stdout
    index = 0
    try:
        while index < len(text):
            while index < len(text) and text[index].isspace():
                index += 1
            if index == len(text):
                break
            value, index = decoder.raw_decode(text, index)
            if isinstance(value, list):
                output.extend(value)
            elif isinstance(value, dict) and isinstance(value.get("items"), list):
                output.extend(value["items"])
            else:
                output.append(value)
    except json.JSONDecodeError as error:
        return None, f"Could not parse GitHub API response: {error}"
    return output, None


def add_error(errors, repo, operation, error):
    message = f"{repo}: {operation}: {error}"
    errors.append(message)
    print(f"  WARNING: {message}", file=sys.stderr)


def parse_time(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include a timezone, for example Z")
    return parsed.astimezone(timezone.utc)


def read_repo_file(repo, path, branch, errors):
    contents, error = gh(
        f"repos/{repo}/contents/{quote(path, safe='/')}",
        ref=branch,
    )
    if contents is None:
        add_error(errors, repo, f"reading {path}", error)
        return None
    if not contents or not contents[0].get("content"):
        add_error(errors, repo, f"reading {path}", "No file content returned")
        return None
    try:
        return base64.b64decode(contents[0]["content"]).decode("utf-8", "ignore")
    except (ValueError, TypeError) as error:
        add_error(errors, repo, f"decoding {path}", str(error))
        return None


def workflow_shell_references(body):
    references = set()
    for match in SHELL_SCRIPT_REFERENCE.findall(body):
        raw_path = match[2:] if match.startswith("./") else match
        path = posixpath.normpath(raw_path)
        if path.startswith("../") or path.startswith("/") or "://" in path:
            continue
        references.add(path)
    return references


def emit_report(report, output_format):
    if output_format == "json":
        print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Check accessible GitHub repositories for wfx-loot campaign indicators."
    )
    parser.add_argument(
        "--since",
        default=CAMPAIGN_START,
        help=f"UTC start time in ISO 8601 format (default: {CAMPAIGN_START})",
    )
    parser.add_argument(
        "--until",
        default=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        help="UTC end time in ISO 8601 format (default: now)",
    )
    parser.add_argument(
        "--visibility",
        choices=("all", "public", "private"),
        default="all",
        help="Repository visibility to scan (default: all)",
    )
    parser.add_argument(
        "--repo",
        action="append",
        metavar="OWNER/REPO",
        help="Scan only this accessible repository; may be repeated",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    args = parser.parse_args()
    try:
        since = parse_time(args.since)
        until = parse_time(args.until)
        if since >= until:
            parser.error("--since must be earlier than --until")
    except ValueError as error:
        parser.error(str(error))

    repos, error = gh(
        "user/repos",
        per_page=100,
        visibility=args.visibility,
        affiliation="owner,organization_member,collaborator",
    )
    if repos is None:
        message = f"Could not list repositories: {error}"
        if args.format == "json":
            emit_report(
                {
                    "campaign": "wfx-loot",
                    "since": args.since,
                    "until": args.until,
                    "visibility": args.visibility,
                    "repositories": [],
                    "errors": [message],
                    "complete": False,
                },
                args.format,
            )
        else:
            print(f"ERROR: {message}", file=sys.stderr)
        return 1

    if args.repo:
        requested_repos = {repo.casefold() for repo in args.repo}
        available_repos = {repo["full_name"].casefold() for repo in repos}
        missing_repos = sorted(requested_repos - available_repos)
        if missing_repos:
            message = (
                "Requested repository is not visible with the selected "
                f"visibility: {', '.join(missing_repos)}"
            )
            if args.format == "json":
                emit_report(
                    {
                        "campaign": "wfx-loot",
                        "since": args.since,
                        "until": args.until,
                        "visibility": args.visibility,
                        "repositories": [],
                        "errors": [message],
                        "complete": False,
                    },
                    args.format,
                )
            else:
                print(f"ERROR: {message}", file=sys.stderr)
            return 1
        repos = [
            repo for repo in repos
            if repo["full_name"].casefold() in requested_repos
        ]

    if args.format == "text":
        print(
            f"Checking {len(repos)} repositories visible to the authenticated account "
            f"(visibility={args.visibility})"
        )
    errors = []
    repository_results = []
    for repository in repos:
        name = repository["full_name"]
        private = " [private]" if repository["private"] else ""
        findings = []

        def flag(kind, detail):
            findings.append((kind, detail))

        branches, error = gh(
            f"repos/{name}/branches", per_page=100
        )
        if branches is None:
            add_error(errors, name, "listing branches", error)
            branches = []

        commit_shas = set()
        for branch in branches:
            branch_name = branch["name"]
            commits, error = gh(
                f"repos/{name}/commits",
                sha=branch_name,
                since=args.since,
                until=args.until,
                per_page=100,
            )
            if commits is None:
                add_error(errors, name, f"listing commits on {branch_name}", error)
                continue
            if commits and branch_name == "wfx-docs":
                flag("CAMPAIGN_BRANCH", branch_name)
            elif commits and re.fullmatch(r"chore/[a-z0-9]{8}", branch_name, re.I):
                flag("CAMPAIGN_BRANCH_PATTERN", branch_name)

            for commit in commits:
                sha = commit["sha"]
                if sha in commit_shas:
                    continue
                commit_shas.add(sha)
                details = commit.get("commit", {})
                message = details.get("message", "").splitlines()[0].strip()
                author = details.get("author") or {}
                committer = details.get("committer") or {}
                names = f"{author.get('name', '')} {committer.get('name', '')}"
                emails = {
                    author.get("email", "").lower(),
                    committer.get("email", "").lower(),
                }

                if message.lower() in CAMPAIGN_COMMIT_MESSAGES:
                    flag("CAMPAIGN_COMMIT", f"{sha[:8]} {message}")
                elif message.lower() in CAMPAIGN_CLEANUP_MESSAGES:
                    flag("POSSIBLE_CAMPAIGN_CLEANUP", f"{sha[:8]} {message}")
                if BAD_NAMES.search(names) or emails.intersection(BAD_EMAILS):
                    flag(
                        "BAD_AUTHOR",
                        f"{sha[:8]} {names.strip()} {sorted(emails - {''})}",
                    )

                if (
                    message.lower() not in CAMPAIGN_COMMIT_MESSAGES
                    and message.lower() not in CAMPAIGN_CLEANUP_MESSAGES
                ):
                    continue

                detail, error = gh(f"repos/{name}/commits/{sha}")
                if detail is None:
                    add_error(errors, name, f"reading commit {sha[:8]}", error)
                    continue
                for changed_file in detail[0].get("files", []):
                    path = changed_file.get("filename", "")
                    patch = changed_file.get("patch", "")
                    if CAMPAIGN_CONTENT.search(path) or CAMPAIGN_CONTENT.search(patch):
                        flag("CAMPAIGN_PAYLOAD", f"{sha[:8]} {path}")
                    if path.endswith((".yml", ".yaml")) and patch:
                        for label, pattern in GENERIC_WORKFLOW_PATTERNS:
                            if pattern.search(patch):
                                flag(
                                    "WORKFLOW_PATTERN",
                                    f"{sha[:8]} {path}: {label}",
                                )
                    if path.endswith("package.json") and re.search(
                        r'"postinstall"\s*:[^,\n]*\.ci-[^"\s]*\.sh',
                        patch,
                        re.I,
                    ):
                        flag("NPM_INSTALL_HOOK", f"{sha[:8]} {path}")

        pull_requests, error = gh(
            "search/issues",
            q=(
                f'repo:{name} is:pr "{CAMPAIGN_PR_TITLE}" '
                f"created:>={args.since[:10]}"
            ),
            per_page=100,
        )
        if pull_requests is None:
            add_error(errors, name, "searching campaign pull requests", error)
        else:
            for pull_request in pull_requests:
                if pull_request.get("title", "").strip().lower() == CAMPAIGN_PR_TITLE:
                    created_at = pull_request.get("created_at")
                    try:
                        created = parse_time(created_at)
                    except (TypeError, ValueError):
                        add_error(
                            errors,
                            name,
                            f"checking pull request #{pull_request.get('number')}",
                            "missing or invalid created_at timestamp",
                        )
                        continue
                    if not since <= created < until:
                        continue
                    flag(
                        "CAMPAIGN_PROBE_PR",
                        f"#{pull_request['number']} {pull_request.get('html_url', '')}",
                    )

        default_branch = repository.get("default_branch")
        if default_branch:
            tree, error = gh(
                f"repos/{name}/git/trees/{quote(default_branch, safe='')}",
                recursive=1,
            )
            if tree is None:
                add_error(errors, name, "listing default-branch files", error)
            elif tree:
                tree_data = tree[0]
                if tree_data.get("truncated"):
                    add_error(
                        errors,
                        name,
                        "listing default-branch files",
                        "Git tree response was truncated",
                    )
                entries = [
                    entry
                    for entry in tree_data.get("tree", [])
                    if entry.get("type") == "blob"
                ]
                file_paths = {entry.get("path", "") for entry in entries}
                workflow_paths = {
                    path
                    for path in file_paths
                    if path.startswith(".github/workflows/")
                    and path.endswith((".yml", ".yaml"))
                }
                candidate_paths = {
                    path
                    for path in file_paths
                    if path.rsplit("/", 1)[-1] == "package.json"
                    or re.fullmatch(
                        r"\.ci-[^/]+\.sh", path.rsplit("/", 1)[-1], re.I
                    )
                }
                workflow_bodies = {}
                shell_references = set()
                for path in sorted(workflow_paths):
                    body = read_repo_file(name, path, default_branch, errors)
                    if body is None:
                        continue
                    workflow_bodies[path] = body
                    shell_references.update(workflow_shell_references(body))
                for reference in shell_references:
                    candidate_paths.update(
                        path
                        for path in file_paths
                        if path == reference or path.endswith(f"/{reference}")
                    )
                candidate_paths.update(workflow_paths)

                for path in sorted(candidate_paths):
                    body = workflow_bodies.get(path)
                    if body is None:
                        body = read_repo_file(name, path, default_branch, errors)
                    if body is None:
                        continue
                    filename = path.rsplit("/", 1)[-1]
                    is_workflow = path in workflow_paths
                    if CAMPAIGN_CONTENT.search(body):
                        flag("CURRENT_CAMPAIGN_CONTENT", path)
                    if filename == "package.json" and re.search(
                        r'"postinstall"\s*:\s*[^,\n]*\.ci-[^"\s]*\.sh',
                        body,
                        re.I,
                    ):
                        flag("CURRENT_NPM_INSTALL_HOOK", path)
                    if is_workflow:
                        for label, pattern in GENERIC_WORKFLOW_PATTERNS:
                            if pattern.search(body):
                                flag("WORKFLOW_PATTERN", f"{path}: {label}")

        distinct_findings = [
            {"type": kind, "detail": detail}
            for kind, detail in dict.fromkeys(findings)
        ]
        repository_results.append(
            {
                "full_name": name,
                "private": repository["private"],
                "pushed_at": repository.get("pushed_at"),
                "branch_count": len(branches),
                "commit_count": len(commit_shas),
                "findings": distinct_findings,
            }
        )
        if args.format == "text":
            print(
                f"{name}{private}: "
                f"{'FLAGS' if distinct_findings else 'no indicators found'} "
                f"(branches={len(branches)}, commits={len(commit_shas)}, "
                f"pushed={repository.get('pushed_at')})"
            )
            for finding in distinct_findings:
                print(f"  {finding['type']}: {finding['detail']}")

    report = {
        "campaign": "wfx-loot",
        "since": args.since,
        "until": args.until,
        "visibility": args.visibility,
        "repository_filter": args.repo or [],
        "repository_count": len(repository_results),
        "complete": not errors,
        "repositories": repository_results,
        "errors": errors,
    }
    emit_report(report, args.format)
    if errors:
        if args.format == "text":
            print(
                f"Scan incomplete: {len(errors)} GitHub API or content errors occurred.",
                file=sys.stderr,
            )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
