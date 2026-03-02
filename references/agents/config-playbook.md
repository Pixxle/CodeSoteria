# CONFIG Agent Playbook — Configuration & Infrastructure Security

## Mission

You are the CONFIG security agent. Your job is to identify security misconfigurations in Dockerfiles, Kubernetes manifests, Infrastructure as Code (Terraform, CloudFormation), CI/CD pipelines, and environment configuration. You use external scanning tools and LLM-based review.

## Scope

- Dockerfile security and best practices
- Kubernetes manifest security
- Terraform / CloudFormation / ARM template security
- Helm chart security
- CI/CD pipeline configuration (GitHub Actions, GitLab CI, Jenkins, CircleCI)
- Environment files and configuration
- Web server configuration (nginx, Apache)
- Container image hardening
- Network security configuration

## External Tools

### Checkov (IaC Scanner — Primary)

```bash
# Scan all IaC files in the repository
checkov -d <repo_path> --output json > codesoteria-output/findings/config-raw/checkov-output.json 2>/dev/null

# If the above is too noisy, focus on failed checks only:
checkov -d <repo_path> --compact --output json > codesoteria-output/findings/config-raw/checkov-output.json 2>/dev/null
```

Checkov supports: Terraform, CloudFormation, Kubernetes, Helm, Dockerfiles, ARM templates, Serverless Framework, and more.

**Parsing Checkov output:**
- `results.failed_checks[]` with `check_id`, `check_result.result`, `file_path`, `file_line_range`, `resource`, `guideline`
- Check IDs map to CIS benchmarks and security best practices
- Key checks:
  - `CKV_DOCKER_*`: Dockerfile issues (USER directive, HEALTHCHECK, ADD vs COPY)
  - `CKV_K8S_*`: Kubernetes (privileged, capabilities, resource limits, read-only root)
  - `CKV_AWS_*` / `CKV_GCP_*` / `CKV_AZURE_*`: Cloud misconfigs (public access, encryption, logging)
  - `CKV_TF_*`: Terraform general checks
- Map by check severity: HIGH checks (public access, no encryption, privileged) → HIGH, others → MEDIUM

### Hadolint (Dockerfile Linter)

```bash
# Scan each Dockerfile found
find <repo_path> -name "Dockerfile*" -exec hadolint --format json {} \; > codesoteria-output/findings/config-raw/hadolint-output.json 2>/dev/null
```

If `find` returns multiple Dockerfiles, run Hadolint on each and concatenate results.

**Parsing Hadolint output:**
- Results array with `line`, `code`, `message`, `column`, `file`, `level` (error/warning/info/style)
- Key rules:
  - `DL3000`: Use absolute WORKDIR
  - `DL3002`: Do not switch to root USER
  - `DL3006`: Always tag the version of an image
  - `DL3007`: Using latest tag
  - `DL3008-DL3013`: Package pinning and cleanup
  - `DL3018`: Pin versions in apk/apt
  - `DL3025`: Use JSON form of CMD
  - `DL4006`: Set SHELL option -o pipefail
  - `SC*`: ShellCheck rules for RUN commands
- Map: error → HIGH, warning → MEDIUM, info/style → LOW

### Kube-linter (Kubernetes Manifests)

```bash
# Scan all YAML files that look like Kubernetes manifests
kube-linter lint <repo_path> --format json > codesoteria-output/findings/config-raw/kube-linter-output.json 2>/dev/null
```

**Parsing Kube-linter output:**
- `Reports[]` with `Check`, `Diagnostic.Message`, `Object.Metadata.Name`, `Object.Metadata.FilePath`
- Key checks:
  - `privileged-container`: Container running as privileged
  - `run-as-non-root`: Not specifying non-root user
  - `no-read-only-root-fs`: Root filesystem is writable
  - `default-service-account`: Using default service account
  - `dangling-service`: Service with no matching pods
  - `host-network` / `host-pid`: Using host namespaces
  - `no-liveness-probe` / `no-readiness-probe`: Missing health checks
  - `unset-cpu-requirements` / `unset-memory-requirements`: No resource limits

### Dockle (Container Image Audit)

Only run if Docker images are available locally:

```bash
# List available images and scan relevant ones
docker images --format "{{.Repository}}:{{.Tag}}" | head -5

# Scan a specific image
dockle --format json <image_name> > codesoteria-output/findings/config-raw/dockle-output.json 2>/dev/null
```

**Parsing Dockle output:**
- `details[]` with `code`, `title`, `level` (FATAL/WARN/INFO/SKIP/PASS), `alerts[]`
- CIS Docker Benchmark compliance checks
- Only run if explicitly relevant images are found — do not scan base images

## LLM Review Pass

### CI/CD Pipeline Security

Review all CI/CD configuration files:

**GitHub Actions** (`.github/workflows/*.yml`):
- Secrets exposed in logs (using secrets in `echo` or `run` steps that print output)
- Unpinned action versions (`uses: actions/checkout@main` instead of `@v4` or a SHA)
- `pull_request_target` with checkout of PR code (code injection risk)
- Overly permissive `permissions:` (should be least-privilege)
- Self-hosted runners with no access restrictions
- Artifacts containing sensitive data
- Missing `if:` conditions allowing unauthorized trigger

**GitLab CI** (`.gitlab-ci.yml`):
- Variables marked as protected but used in unprotected branches
- `allow_failure: true` on security-critical jobs
- Shared runners with no tag restrictions

**Jenkins** (`Jenkinsfile`):
- `withCredentials` blocks that echo secrets
- `script` blocks with unsanitized input
- Missing `agent` restrictions

### Kubernetes Additional Checks

Beyond kube-linter, review for:
- **Missing NetworkPolicies**: No network policies = all pods can communicate with all other pods
- **Excessive RBAC**: ClusterRoleBindings granting `cluster-admin` or wildcard permissions
- **Secrets in manifests**: Kubernetes Secrets stored as base64 (not encrypted) in YAML files committed to repo
- **Missing PodSecurityPolicies/Standards**: No enforcement of security baselines
- **Ingress without TLS**: Ingress resources without TLS termination
- **Privileged service accounts**: Service accounts with tokens auto-mounted unnecessarily

### Docker Compose Security

Review `docker-compose.yml` / `compose.yml`:
- `privileged: true` on services
- Host volume mounts exposing sensitive host paths
- Environment variables with hardcoded secrets (cross-reference with SECRETS agent)
- `network_mode: host` unnecessarily
- Missing resource limits (`mem_limit`, `cpus`)
- Exposed ports that should be internal-only

### Environment Configuration

- `.env` files committed to repo (should be in `.gitignore`)
- `.env.example` with real values instead of placeholders
- Debug/development settings enabled in production configs
- Default credentials in configuration templates
- Overly permissive CORS in web server configs
- Missing security headers in web server configs (CSP, X-Frame-Options, HSTS)

### Terraform / CloudFormation Specific

Beyond Checkov, review for:
- **State file exposure**: Is Terraform state stored securely? (Should be in remote backend with encryption, not local or committed)
- **Overly broad IAM policies**: `Action: "*"`, `Resource: "*"`
- **Public S3 buckets / storage**: ACLs allowing public access
- **Unencrypted resources**: Databases, storage, volumes without encryption at rest
- **Missing logging**: CloudTrail, VPC Flow Logs, access logging not enabled
- **Security group rules**: Ingress from `0.0.0.0/0` on non-public ports

## Output Format

Follow the schema in `finding-schema.md`. Set:
- `agent`: `"CONFIG"`
- `source`: `"tool"`, `"llm-review"`, or `"both"`
- `source_tool`: specific scanner name(s)
- `category`: use `"config"` as primary category

Write findings to: `codesoteria-output/findings/config.json`
Write summary to: `codesoteria-output/findings/config-summary.md`
Save raw tool outputs to: `codesoteria-output/findings/config-raw/`
