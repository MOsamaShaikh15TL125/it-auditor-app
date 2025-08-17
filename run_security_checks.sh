#!/usr/bin/env bash
set -u
# run_security_checks.sh
# One-shot local runner for the CI checks. Creates a temp venv, installs pinned dev tools,
# runs the scans, and writes a remediation-report.txt summary.

WORKDIR="$(pwd)"
VENV_DIR=".venv_dev_checks"
REPORT="$WORKDIR/remediation-report.txt"
REQ="requirements-dev.txt"

echo "Running local security checks (this may take a minute)..."
echo "Report: $REPORT"
echo "Using requirements file: $REQ"
echo

# Cleanup old artifacts
rm -f "$REPORT"
rm -rf "$VENV_DIR"
mkdir -p "$VENV_DIR"

python3 -m venv "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

pip install --upgrade pip setuptools wheel >/dev/null

if [ ! -f "$REQ" ]; then
  echo "ERROR: $REQ not found. Create requirements-dev.txt with pinned versions." | tee -a "$REPORT"
  deactivate
  exit 1
fi

echo "[1/9] Installing dev tools from $REQ..."
pip install -r "$REQ" >>"$REPORT" 2>&1 || true

echo "=== REMEDIATION REPORT ===" >"$REPORT"
echo "Generated: $(date -u +"%Y-%m-%d %H:%M:%SZ")" >>"$REPORT"
echo >>"$REPORT"

# helper to run commands capturing stdout/stderr and exit code
run_and_record() {
  local label="$1"; shift
  local cmd=( "$@" )
  local outf="/tmp/${label// /_}.out"
  echo "---- $label ----" >>"$REPORT"
  echo "COMMAND: ${cmd[*]}" >>"$REPORT"
  echo "Running..." >>"$REPORT"
  "${cmd[@]}" >"$outf" 2>&1
  local rc=$?
  echo "Exit code: $rc" >>"$REPORT"
  echo >>"$REPORT"
  echo "OUTPUT (first 2000 chars):" >>"$REPORT"
  head -c 2000 "$outf" >>"$REPORT" || true
  echo >>"$REPORT"
  if [ $rc -ne 0 ]; then
    echo "ACTION: Tool '$label' returned non-zero exit code. See full output in /tmp/${label// /_}.out" >>"$REPORT"
  else
    echo "ACTION: No immediate non-zero exit code from '$label'." >>"$REPORT"
  fi
  echo >>"$REPORT"
}

# 1) pre-commit (run all files)
if command -v pre-commit >/dev/null 2>&1; then
  run_and_record "pre-commit --all-files" pre-commit run --all-files
else
  echo "pre-commit not installed in venv (install failed)" >>"$REPORT"
fi

# 2) ruff check
if command -v ruff >/dev/null 2>&1; then
  run_and_record "ruff check ." ruff check .
else
  echo "ruff not installed in venv (install failed)" >>"$REPORT"
fi

# 3) bandit
if command -v bandit >/dev/null 2>&1; then
  run_and_record "bandit -r ." bandit -r . -f json -o /tmp/bandit.json
  # produce human summary
  python - <<'PY' >>"$REPORT" 2>&1
import json,sys
try:
    data=json.load(open('/tmp/bandit.json'))
    results=data.get('results',[])
    issues=[r for r in results if r.get('issue_severity') in ('MEDIUM','HIGH')]
    if issues:
        print("Bandit: FOUND medium/high issues:")
        for i in issues:
            print(i.get('filename'), i.get('issue_severity'), i.get('issue_text')[:200])
    else:
        print("Bandit: No medium/high issues found.")
except Exception as e:
    print("Bandit: summary failed:", e)
PY
else
  echo "bandit not installed in venv (install failed)" >>"$REPORT"
fi

# 4) pip-audit
if command -v pip-audit >/dev/null 2>&1; then
  echo "Running pip-audit --format=json --> /tmp/pip_audit.json" >>"$REPORT"
  pip-audit --format=json > /tmp/pip_audit.json 2>&1 || true
  echo "pip-audit exit code captured; summarizing..." >>"$REPORT"
  python - <<'PY' >>"$REPORT" 2>&1
import json,sys
try:
    data=json.load(open('/tmp/pip_audit.json'))
    if not data:
        print("pip-audit: no vulnerable packages found.")
    else:
        print("pip-audit: Vulnerable packages found:")
        for pkg in data:
            print("-", pkg.get('name'), pkg.get('version'), "->", pkg.get('vulns')[0].get('id') if pkg.get('vulns') else 'no vuln id')
except Exception as e:
    print("pip-audit: couldn't parse output or no findings:", e)
PY
else
  echo "pip-audit not installed in venv (install failed)" >>"$REPORT"
fi

# 5) detect-secrets scan (full repo)
if command -v detect-secrets >/dev/null 2>&1; then
  run_and_record "detect-secrets scan --all-files" detect-secrets scan --all-files --json > /tmp/detect_secrets.json 2>&1 || true
  echo "Detect-secrets hint: compare results against .secrets.baseline (if present)." >>"$REPORT"
else
  echo "detect-secrets not installed in venv (install failed)" >>"$REPORT"
fi

# 6) mypy static typing
if command -v mypy >/dev/null 2>&1; then
  run_and_record "mypy --strict ." mypy --show-error-codes .
else
  echo "mypy not installed in venv (install failed)" >>"$REPORT"
fi

# 7) safety (optional extra vuln scan)
if command -v safety >/dev/null 2>&1; then
  run_and_record "safety check --json" safety check --json
else
  echo "safety not installed in venv (install failed)" >>"$REPORT"
fi

# Final summary
echo "=== SUMMARY ===" >>"$REPORT"
echo "Date: $(date -u)" >>"$REPORT"
echo "Files created in /tmp for deeper inspection (bandit.json, pip_audit.json, detect_secrets.json)" >>"$REPORT"
echo >>"$REPORT"
echo "If any tool reported issues, inspect the corresponding outputs and follow their remediation suggestions:" >>"$REPORT"
echo "- For dependency vulns: update requirements, re-run pip-audit/safety, consider pinning to fixed safe versions" >>"$REPORT"
echo "- For Bandit findings: follow the specific issue text and remediate insecure code patterns" >>"$REPORT"
echo "- For detect-secrets: run detect-secrets audit .secrets.baseline and remove/rotate any real secrets discovered" >>"$REPORT"

deactivate

echo "Done. Report at: $REPORT"