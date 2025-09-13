#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import os
import re
import shlex
import subprocess
import sys
import threading
from pathlib import Path

try:
    import jsonschema
except Exception:
    jsonschema = None


PRINT_LOCK = threading.Lock()


def log(message: str) -> None:
    with PRINT_LOCK:
        print(message, flush=True)


def run(cmd: str, cwd: str | None = None, env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    log(f"$ {cmd}")
    completed = subprocess.run(cmd, shell=True, cwd=cwd, env=env, text=True)
    if check and completed.returncode != 0:
        raise RuntimeError(f"Command failed ({completed.returncode}): {cmd}")
    return completed


def ensure_tool_installed(tool: str) -> None:
    result = subprocess.run(f"command -v {shlex.quote(tool)} >/dev/null 2>&1", shell=True)
    if result.returncode != 0:
        raise RuntimeError(f"Required tool not found: {tool}")


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_manifest(manifest: dict, schema_path: Path) -> None:
    if jsonschema is None:
        log("jsonschema not available; skipping schema validation")
        return
    schema = load_json(schema_path)
    jsonschema.validate(manifest, schema)


def match_pattern(pattern: str, candidate: str) -> bool:
    # Supports '*' wildcard only
    regex = re.escape(pattern).replace(r"\*", ".*") + "$"
    return re.match(regex, candidate) is not None


def enforce_policies(repo: dict, policies: dict) -> None:
    protocol = repo.get("protocol")
    if protocol not in policies.get("allowedProtocols", []):
        raise ValueError(f"Protocol '{protocol}' not allowed for {repo.get('name')}")

    owner = repo.get("owner")
    if owner not in policies.get("allowedOwners", []):
        raise ValueError(f"Owner '{owner}' not allowed for {repo.get('name')}")

    allowed_repo_patterns = policies.get("allowedRepos") or []
    if allowed_repo_patterns:
        full = f"{owner}/{repo.get('repo')}"
        if not any(match_pattern(pat, full) for pat in allowed_repo_patterns):
            raise ValueError(f"Repository '{full}' not on allowlist")

    allow_unpinned = policies.get("allowUnpinned", False)
    if not allow_unpinned:
        ref = repo.get("ref")
        if not ref:
            raise ValueError(f"Repository {repo.get('name')} missing required ref pin")
        # Any of branch/tag/commit allowed as the single key
        if len(ref.keys()) != 1:
            raise ValueError(f"Repository {repo.get('name')} ref must have exactly one of branch/tag/commit")

    depth = repo.get("depth") or policies.get("defaultDepth", 1)
    max_depth = policies.get("maxDepth", 50)
    if depth > max_depth:
        raise ValueError(f"Requested depth {depth} exceeds maxDepth {max_depth} for {repo.get('name')}")


def build_env_for_auth(auth: dict, allow_missing: bool = False) -> dict:
    env = os.environ.copy()
    method = (auth or {}).get("method", "none")
    if method == "env_token":
        token_env = auth.get("tokenEnv")
        if not token_env:
            raise ValueError("auth.method=env_token requires tokenEnv")
        token_val = os.environ.get(token_env)
        if not token_val:
            if allow_missing:
                log(f"Warning: {token_env} not set; proceeding without injecting token (dry-run)")
                return env
            raise ValueError(f"Environment variable {token_env} not set")
        # GitHub token via git credential helper
        env["GIT_ASKPASS"] = ""
        env["GITHUB_TOKEN"] = token_val
        # Prefer HTTPS with token embedded only at runtime via extraheader
        env["GIT_HTTP_EXTRAHEADER"] = f"AUTHORIZATION: bearer {token_val}"
    elif method == "ssh_key":
        key_path = auth.get("sshKeyPath")
        if not key_path:
            if allow_missing:
                log("Warning: sshKeyPath not set; proceeding without SSH key (dry-run)")
                return env
            raise ValueError("auth.method=ssh_key requires sshKeyPath")
        env["GIT_SSH_COMMAND"] = f"ssh -i {shlex.quote(key_path)} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
    elif method == "none":
        pass
    else:
        raise ValueError(f"Unknown auth method: {method}")
    return env


def compute_ref_args(repo: dict) -> tuple[list[str], str | None, str | None]:
    ref = repo.get("ref")
    if not ref:
        return [], None, None
    if "commit" in ref:
        return [], ref["commit"], "commit"
    if "tag" in ref:
        return ["--branch", ref["tag"]], None, "tag"
    if "branch" in ref:
        return ["--branch", ref["branch"]], None, "branch"
    return [], None, None


def safe_mkdir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def git_clone(repo: dict, policies: dict, env: dict, dry_run: bool) -> None:
    enforce_policies(repo, policies)

    destination = Path(repo["destination"]).resolve()
    url = repo["url"]
    depth = repo.get("depth") or policies.get("defaultDepth", 1)
    filter_arg = repo.get("filter")
    lfs = bool(repo.get("lfs", False))
    submodules = repo.get("submodules") or {"enabled": False}
    sparse_paths = repo.get("sparsePaths") or []

    ref_args, commit_to_checkout, ref_type = compute_ref_args(repo)

    clone_cmd_parts = ["git", "clone"]
    # Avoid --no-tags when cloning by tag so that the tag name resolves cleanly
    if ref_type != "tag":
        clone_cmd_parts.append("--no-tags")
    clone_cmd_parts += ["--depth", str(depth)]
    if filter_arg and filter_arg != "none":
        clone_cmd_parts += ["--filter", filter_arg]
    if submodules.get("enabled"):
        clone_cmd_parts += ["--recurse-submodules"]
        # Use shallow submodules, but avoid duplicating --depth on the clone command
        if submodules.get("depth"):
            clone_cmd_parts += ["--shallow-submodules"]
    clone_cmd_parts += ref_args
    clone_cmd_parts += [url, str(destination)]

    if dry_run:
        log(f"[dry-run] Would run: {' '.join(map(shlex.quote, clone_cmd_parts))}")
        return

    safe_mkdir(destination)
    if destination.exists() and any(destination.iterdir()):
        raise RuntimeError(f"Destination already exists and is not empty: {destination}")

    run(" ".join(map(shlex.quote, clone_cmd_parts)), env=env)

    # Enable sparse checkout if requested
    if sparse_paths:
        run("git sparse-checkout init --cone", cwd=str(destination), env=env)
        run("git sparse-checkout set " + " ".join(shlex.quote(p) for p in sparse_paths), cwd=str(destination), env=env)

    # Handle LFS if requested
    if lfs:
        ensure_tool_installed("git")
        ensure_tool_installed("git-lfs")
        run("git lfs install --local", cwd=str(destination), env=env)
        run("git lfs fetch --all", cwd=str(destination), env=env)
        run("git lfs checkout", cwd=str(destination), env=env)

    # If commit is specified, checkout that commit
    if commit_to_checkout:
        run(f"git fetch --depth {depth} origin {commit_to_checkout}", cwd=str(destination), env=env)
        run(f"git checkout --detach {commit_to_checkout}", cwd=str(destination), env=env)

    # If submodules configured with a specific depth, apply via post-clone update
    if submodules.get("enabled") and submodules.get("depth"):
        sub_depth = int(submodules.get("depth"))
        run(f"git submodule update --init --recursive --depth {sub_depth}", cwd=str(destination), env=env)

    # Verify pinCommit if required
    if repo.get("verifyCommit") and repo.get("pinCommit"):
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(destination), text=True).strip()
        expected = repo["pinCommit"]
        if head != expected:
            raise RuntimeError(f"HEAD {head} does not match expected {expected} for {repo.get('name')}")


def detect_monorepo(destination: Path) -> bool:
    # Heuristic: presence of many top-level directories and a packages/ or apps/
    try:
        entries = [p for p in destination.iterdir() if p.is_dir()]
    except Exception:
        return False
    top_names = {p.name for p in entries}
    if {"packages", "apps"} & top_names:
        return True
    return len(entries) >= 8


def main() -> int:
    parser = argparse.ArgumentParser(description="Secure GitHub clone orchestrator")
    parser.add_argument("--manifest", default="/workspace/repos.manifest.json", help="Path to manifest JSON")
    parser.add_argument("--schema", default="/workspace/schema/repo-manifest.schema.json", help="Path to JSON schema")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without executing")
    args = parser.parse_args()

    ensure_tool_installed("git")

    manifest_path = Path(args.manifest)
    schema_path = Path(args.schema)

    if not manifest_path.exists():
        log(f"Manifest not found: {manifest_path}")
        return 2

    manifest = load_json(manifest_path)

    try:
        validate_manifest(manifest, schema_path)
    except Exception as e:
        log(f"Manifest validation failed: {e}")
        return 2

    policies = manifest.get("policies", {})
    auth = manifest.get("auth", {})
    env = build_env_for_auth(auth, allow_missing=args.dry_run)

    repos = manifest.get("repositories", [])
    if not repos:
        log("No repositories specified in manifest")
        return 0

    # Enforce requireSparseForMonorepo post-clone by checking destination content
    concurrency = max(1, int(policies.get("concurrency", 3)))

    def worker(repo_item: dict) -> tuple[str, str | None]:
        name = repo_item.get("name")
        try:
            git_clone(repo_item, policies, env, args.dry_run)
            if not args.dry_run and policies.get("requireSparseForMonorepo"):
                dest = Path(repo_item["destination"]).resolve()
                if detect_monorepo(dest) and not repo_item.get("sparsePaths"):
                    raise RuntimeError(f"Monorepo detected at {dest} but sparsePaths not configured for {name}")
            return name, None
        except Exception as e:
            return name, str(e)

    failures: list[tuple[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(worker, r) for r in repos]
        for future in concurrent.futures.as_completed(futures):
            name, error = future.result()
            if error:
                log(f"[FAIL] {name}: {error}")
                failures.append((name, error))
            else:
                log(f"[OK] {name}")

    if failures:
        log(f"Completed with {len(failures)} failure(s)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

