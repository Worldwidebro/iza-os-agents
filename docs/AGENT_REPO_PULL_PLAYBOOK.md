## Agent GitHub Pull Playbook

This playbook defines how agents clone code from GitHub safely and reproducibly using a manifest, with policy enforcement and optional sparse/partial clone.

### Files
- `schema/repo-manifest.schema.json`: JSON Schema for the manifest
- `repos.manifest.json`: Example manifest to customize
- `scripts/secure_clone.py`: Orchestrator script

### Policies
- **Protocols**: Restrict to `https` (default) or `ssh`
- **Owners/Repos**: Allowlist via `allowedOwners` and `allowedRepos` (supports `*`)
- **Pinning**: Set `allowUnpinned=false` to require a `ref` (branch/tag/commit). Use `pinCommit`+`verifyCommit=true` to assert exact commit
- **Depth/Filter**: Use shallow clones with optional partial clone filters
- **Sparse**: Provide `sparsePaths` for monorepos; if `requireSparseForMonorepo=true`, missing sparse paths for detected monorepos will fail
- **Concurrency**: Limit simultaneous clones

### Auth
- `auth.method=env_token` with `auth.tokenEnv` (e.g., `GITHUB_TOKEN`)
  - Provide a PAT with `repo` scope for private repos
- `auth.method=ssh_key` with `auth.sshKeyPath`

### Usage
Dry-run (no network calls):
```bash
python3 /workspace/scripts/secure_clone.py --dry-run
```

Execute clone (requires auth):
```bash
export GITHUB_TOKEN=***
python3 /workspace/scripts/secure_clone.py
```

Custom manifest:
```bash
python3 /workspace/scripts/secure_clone.py --manifest /abs/path/to/manifest.json
```

### Manifest Tips
- Always pin with a tag or commit; for supply-chain safety use `pinCommit`+`verifyCommit`
- Prefer `filter: "blob:none"` and `sparsePaths` to minimize bandwidth for monorepos
- Keep `concurrency` reasonable (<= 4) to avoid rate limits

### Troubleshooting
- Schema validation requires `jsonschema` in the Python environment. If unavailable, validation is skipped; ensure CI validates manifests.
- If cloning private repositories over HTTPS, verify that `GITHUB_TOKEN` is present and has required scopes.
- For SSH clones, ensure the key path exists and Git can use it; host fingerprints are accepted with `StrictHostKeyChecking=accept-new`.

