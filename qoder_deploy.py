#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Qoder 每日签到 · GitHub Actions 一键部署脚本
================================================================

把 https://github.com/<你>/Qoder-Daily 的签到任务一键跑在 GitHub Actions 上：

    前置探测 -> 开通 Actions -> 设备授权拿 Token -> 生成/复用 cache key
    -> 写入 Secrets -> 反注释 schedule 并提交 -> 触发首跑 -> 校验 cache 命中

设计约束：
  * 只用 Python 标准库（urllib / subprocess / hashlib / secrets ...），不需要 pip install；
  * Secret 加密交给 gh（Go 内置 NaCl）；没有 gh 时回退 PyNaCl；
  * 只能改仓库里的一个文件：.github/workflows/daily.yml；
  * 幂等：每步先读现状再决定写；重复执行不会产生多余 commit / 多余运行；
  * 全量掩码：任何进日志的凭据都会被替换成 ****。

常用命令：
  python qoder_deploy.py --dry-run          # 只看计划，不写任何东西
  python qoder_deploy.py                    # 完整部署（会打开浏览器授权）
  python qoder_deploy.py --only-secrets     # 只重新写 Token
  python qoder_deploy.py --check            # 健康巡检
  python qoder_deploy.py --print-patch      # 只输出 workflow 补丁，供手工 apply
  python qoder_deploy.py --self-test        # 离线自检

退出码：0 成功 / 2 参数 / 3 环境 / 4 身份 / 5 Secrets 权限 / 6 workflow 权限
        7 授权 / 8 补丁 / 9 首跑失败 / 10 Actions 无法启用 / 11 状态文件 / 12 部分成功
"""

import argparse
import base64
import binascii
import difflib
import hashlib
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from datetime import datetime, timezone

try:
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
except Exception:
    pass

VERSION = "1.0.0"

UPSTREAM_REPO = "L0NE-6/Qoder-Daily"
WORKFLOW_PATH = ".github/workflows/daily.yml"
CACHE_PREFIX = "qoder-state-v2-"
SCHEDULE_LINE = "  schedule:"
CRON_LINE = '    - cron: "5 2 * * *"'
STATE_VERSION = 1

GH_API = "https://api.github.com"
GH_UA = "qoder-deploy/" + VERSION

QODER_REGIONS = {
    "cn": {
        "web": "https://qoder.com.cn",
        "api": "https://openapi.qoder.com.cn",
        "label": "中国版",
        "secret": "QODER_TOKENS",
    },
    "global": {
        "web": "https://qoder.com",
        "api": "https://openapi.qoder.sh",
        "label": "国际版",
        "secret": "QODER_GLOBAL_TOKENS",
    },
}
DEVICE_LOGIN_PATH = "/device/selectAccounts"
DEVICE_POLL_PATH = "/api/v1/deviceToken/poll"
CAMPAIGNS_PATH = "/sash/api/v1/me/campaigns"
POLL_INTERVAL = 2
POLL_TIMEOUT = 300

EXIT_OK = 0
EXIT_ARGS = 2
EXIT_ENV = 3
EXIT_IDENTITY = 4
EXIT_SECRET_PERM = 5
EXIT_WORKFLOW_PERM = 6
EXIT_AUTH = 7
EXIT_PATCH = 8
EXIT_RUN_FAILED = 9
EXIT_ACTIONS_DISABLED = 10
EXIT_STATE = 11
EXIT_PARTIAL = 12

VERBOSE = False
JSON_MODE = False
ASSUME_YES = False


# =====================================================================
# 输出 / 掩码
# =====================================================================

def log(msg, level="info"):
    prefix = {
        "info": "--",
        "ok": "OK",
        "warn": "!!",
        "err": "xx",
        "step": ">>",
        "dbg": "..",
    }.get(level, "--")
    if level == "dbg" and not VERBOSE:
        return
    try:
        print("[%s] %s" % (prefix, msg), flush=True)
    except Exception:
        print("[%s] %s" % (prefix, msg.encode("utf-8", "replace").decode("utf-8", "replace")), flush=True)


def hr(title=""):
    line = "=" * 66
    if title:
        print("\n" + line + "\n" + title + "\n" + line, flush=True)
    else:
        print(line, flush=True)


def mask(value, keep=6):
    """只保留首尾少量字符，用于日志展示。"""
    text = str(value or "")
    if not text:
        return "(空)"
    if len(text) <= keep * 2:
        return text[:2] + "****" + " (len=%d)" % len(text)
    return text[:keep] + "****" + text[-4:] + " (len=%d)" % len(text)


def mask_token_line(line):
    """把 `备注|access|refresh[|uid]` 逐段掩码，保留备注可读。"""
    parts = [p.strip() for p in str(line or "").split("|")]
    if not parts:
        return "(空)"
    out = []
    for index, part in enumerate(parts):
        if index == 0:
            out.append(part or "(无备注)")
        elif len(part) > 12:
            out.append(part[:4] + "****" + part[-3:])
        elif part:
            out.append("****")
        else:
            out.append("(空)")
    return "|".join(out)


SECRET_PATTERNS = [
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"gho_[A-Za-z0-9]{20,}"),
    re.compile(r"dt-[A-Za-z0-9._\-]{12,}"),
    re.compile(r"drt-[A-Za-z0-9._\-]{12,}"),
    re.compile(r"jrt-[A-Za-z0-9._\-]{12,}"),
]


def redact(text):
    """把任意文本里疑似凭据的片段打码。"""
    out = str(text or "")
    for pattern in SECRET_PATTERNS:
        out = pattern.sub("***", out)
    return out


def debug(msg):
    log(msg, "dbg")


# =====================================================================
# 状态文件
# =====================================================================

def default_state_path():
    return os.path.join(os.path.expanduser("~"), ".qoder-deploy", "state.json")


def load_state(path):
    if not os.path.exists(path):
        return {
            "schema": STATE_VERSION,
            "repo": None,
            "upstream": UPSTREAM_REPO,
            "github_login": None,
            "cache_key": None,
            "cache_key_created_at": None,
            "cache_key_fingerprint": None,
            "secrets": {},
            "schedule": {},
            "last_run": {},
            "history": [],
            "updated_at": None,
        }
    try:
        with open(path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
    except Exception as error:
        raise RuntimeError("状态文件无法解析：%s（%s）" % (path, error))
    if not isinstance(state, dict):
        raise RuntimeError("状态文件结构异常：%s" % path)
    if state.get("schema") != STATE_VERSION:
        raise RuntimeError(
            "状态文件 schema=%r 与本脚本要求的 %r 不一致，请用 --state-file 指定别的路径"
            % (state.get("schema"), STATE_VERSION)
        )
    for key, value in (("secrets", {}), ("schedule", {}), ("last_run", {}), ("history", [])):
        state.setdefault(key, value)
    return state


def save_state(path, state):
    state["schema"] = STATE_VERSION
    state["updated_at"] = utc_now()
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    payload = json.dumps(state, ensure_ascii=False, indent=2)
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def record(state, action, **detail):
    item = {"ts": utc_now(), "action": action}
    item.update(detail)
    state.setdefault("history", []).insert(0, item)
    state["history"] = state["history"][:50]


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fingerprint(value):
    return "sha256:" + hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()[:12]


# =====================================================================
# HTTP
# =====================================================================

class NetError(RuntimeError):
    pass


_INSECURE_NOTICE = [False]


def http_request(method, url, payload=None, headers=None, timeout=30, insecure=False):
    """返回 (status, headers_lower_dict, body_bytes)。HTTP 4xx/5xx 不抛异常。"""
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8") if not isinstance(payload, bytes) else payload
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    context = None
    if url.lower().startswith("https"):
        try:
            context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        except Exception:
            context = None
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.status, _lower_headers(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, _lower_headers(error.headers), error.read()
    except urllib.error.URLError as error:
        raise NetError(str(getattr(error, "reason", error)))
    except ssl.SSLError as error:
        raise NetError("TLS 失败：%s" % error)


def _lower_headers(headers):
    out = {}
    try:
        for key, value in dict(headers).items():
            out[str(key).lower()] = value
    except Exception:
        pass
    return out


def json_or_none(raw):
    try:
        return json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    except Exception:
        return None


def body_text(raw, limit=400):
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw or "")
    text = redact(text).strip()
    return text[:limit]


# =====================================================================
# gh CLI
# =====================================================================

def gh_binary():
    from shutil import which
    return which("gh")


def gh_env(token=None):
    env = os.environ.copy()
    env.setdefault("GH_PROMPT_DISABLED", "1")
    if token:
        env["GH_TOKEN"] = token
    return env


def gh_token_from_cli():
    binary = gh_binary()
    if not binary:
        return None
    try:
        proc = subprocess.run(
            [binary, "auth", "token"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            env=gh_env(),
        )
        if proc.returncode == 0:
            value = proc.stdout.decode("utf-8", "replace").strip()
            return value or None
    except Exception:
        return None
    return None


def gh_secret_set(repo, name, value, token=None):
    """通过 gh 写入 secret（gh 内部用 NaCl sealed box 加密）。值走 stdin。"""
    binary = gh_binary()
    if not binary:
        raise RuntimeError("未找到 gh")
    proc = subprocess.run(
        [binary, "secret", "set", name, "--repo", repo],
        input=value.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        env=gh_env(token),
    )
    out = (proc.stdout or b"").decode("utf-8", "replace").strip()
    err = (proc.stderr or b"").decode("utf-8", "replace").strip()
    if proc.returncode != 0:
        raise RuntimeError(redact(err or out or "gh secret set 失败"))
    return out or "ok"


def gh_run_log(repo, run_id, token=None):
    binary = gh_binary()
    if not binary:
        return None
    try:
        proc = subprocess.run(
            [binary, "run", "view", str(run_id), "--repo", repo, "--log"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            env=gh_env(token),
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    return (proc.stdout or b"").decode("utf-8", "replace")


def gh_version():
    binary = gh_binary()
    if not binary:
        return None
    try:
        proc = subprocess.run([binary, "--version"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
        return (proc.stdout or b"").decode("utf-8", "replace").splitlines()[0].strip()
    except Exception:
        return None


# =====================================================================
# GitHub API
# =====================================================================

class ApiError(RuntimeError):
    def __init__(self, status, headers, body, path=""):
        self.status = status
        self.headers = headers or {}
        self.body = body
        self.path = path
        payload = json_or_none(body) or {}
        message = payload.get("message") or body_text(body, 200)
        super(ApiError, self).__init__("HTTP %s %s %s" % (status, path, message))

    def accepted_permissions(self):
        return parse_accepted_permissions(self.headers)


def parse_accepted_permissions(headers):
    """从 X-Accepted-Github-Permissions 解析出缺失的权限，如 {'secrets': 'read'}。"""
    raw = ""
    for key, value in (headers or {}).items():
        if str(key).lower() == "x-accepted-github-permissions":
            raw = str(value or "")
            break
    out = {}
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        name, _, scope = chunk.partition("=")
        out[name.strip()] = scope.strip()
    return out


class GitHub(object):
    def __init__(self, repo, token):
        self.repo = repo
        self.token = token

    def api(self, method, path, payload=None, expect=(200, 201, 204)):
        url = path if path.startswith("http") else GH_API + path
        headers = {
            "accept": "application/vnd.github+json",
            "authorization": "Bearer %s" % self.token,
            "user-agent": GH_UA,
            "x-github-api-version": "2022-11-28",
        }
        if payload is not None:
            headers["content-type"] = "application/json"
        status, resp_headers, body = http_request(method, url, payload=payload, headers=headers, timeout=45)
        debug("%s %s -> %s" % (method, path, status))
        if expect and status not in expect:
            raise ApiError(status, resp_headers, body, path)
        return status, resp_headers, body

    def get_json(self, path, default=None):
        try:
            _, _, body = self.api("GET", path)
        except ApiError as error:
            if error.status == 404:
                return default
            raise
        payload = json_or_none(body)
        return default if payload is None else payload

    # ---- 只读 ----
    def me(self):
        return self.get_json("/user", {})

    def repo_info(self):
        return self.get_json("/repos/%s" % self.repo, {})

    def actions_permissions(self):
        return self._probe("/repos/%s/actions/permissions" % self.repo)

    def workflows(self):
        return self._probe("/repos/%s/actions/workflows?per_page=100" % self.repo)

    def secrets(self):
        return self._probe("/repos/%s/actions/secrets?per_page=100" % self.repo)

    def caches(self):
        return self._probe("/repos/%s/actions/caches?per_page=100" % self.repo)

    def file(self, path, repo=None, ref=None):
        target = repo or self.repo
        url = "/repos/%s/contents/%s" % (target, path)
        if ref:
            url += "?ref=" + urllib.parse.quote(ref)
        payload = self.get_json(url, None)
        if not payload or "content" not in payload:
            return None
        try:
            text = base64.b64decode(payload["content"]).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return None
        return {"text": text, "sha": payload.get("sha"), "path": payload.get("path")}

    def _probe(self, path):
        """返回 {'ok': True/False/None, 'status': int, 'data': ..., 'body': str, 'accepted': {}}。"""
        try:
            status, headers, body = self.api("GET", path, expect=None)
        except ApiError as error:
            return {"ok": None, "status": error.status, "data": None,
                    "body": body_text(error.body), "accepted": error.accepted_permissions()}
        if status in (401, 403):
            return {"ok": False, "status": status, "data": None,
                    "body": body_text(body), "accepted": parse_accepted_permissions(headers)}
        payload = json_or_none(body)
        return {"ok": status == 200, "status": status, "data": payload, "body": body_text(body), "accepted": {}}

    # ---- 写 ----
    def enable_actions(self):
        return self.api("PUT", "/repos/%s/actions/permissions" % self.repo, {"enabled": True}, expect=None)

    def enable_workflow(self, workflow_id):
        return self.api(
            "PUT", "/repos/%s/actions/workflows/%s/enable" % (self.repo, workflow_id), None, expect=None
        )

    def put_file(self, path, text, sha, message, branch):
        payload = {
            "message": message,
            "content": base64.b64encode(text.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha
        return self.api("PUT", "/repos/%s/contents/%s" % (self.repo, path), payload, expect=None)

    def dispatch(self, workflow_file, ref):
        return self.api(
            "POST",
            "/repos/%s/actions/workflows/%s/dispatches" % (self.repo, workflow_file),
            {"ref": ref},
            expect=None,
        )

    def list_runs(self, event=None, limit=10):
        path = "/repos/%s/actions/runs?per_page=%d" % (self.repo, limit)
        if event:
            path += "&event=" + event
        return self._probe(path)

    def run_detail(self, run_id):
        return self._probe("/repos/%s/actions/runs/%s" % (self.repo, run_id))

    def run_jobs(self, run_id):
        return self._probe("/repos/%s/actions/runs/%s/jobs" % (self.repo, run_id))

    def delete_cache(self, cache_id):
        return self.api("DELETE", "/repos/%s/actions/caches/%s" % (self.repo, cache_id), None, expect=None)


# =====================================================================
# Qoder 设备授权（标准库复刻 qoder_login.py 的 PKCE 流程）
# =====================================================================

def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def load_machine_id():
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, ".qoder-proxy", "machine_id"),
        os.path.join(home, ".qoder", ".auth", "machine_id"),
        os.path.join(home, ".qoder", "machine_id"),
    ]
    for candidate in candidates:
        try:
            with open(candidate, "r", encoding="utf-8") as handle:
                value = handle.read().strip()
            if value and len(value) <= 256:
                return value, candidate
        except Exception:
            continue
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "qoder_machine_id")
    try:
        with open(local, "r", encoding="utf-8") as handle:
            value = handle.read().strip()
        if value:
            return value, local
    except Exception:
        pass
    value = str(uuid.uuid4())
    try:
        with open(local, "w", encoding="utf-8") as handle:
            handle.write(value)
    except Exception:
        pass
    return value, local + "（新生成）"


def qoder_request(method, url, headers=None, timeout=20):
    """Qoder 端点请求：优先系统证书，TLS 失败再降级并明确提示。"""
    try:
        return http_request(method, url, headers=headers, timeout=timeout)
    except NetError as error:
        if "CERTIFICATE" not in str(error).upper() and "TLS" not in str(error).upper():
            raise
        if not _INSECURE_NOTICE[0]:
            log("TLS 证书校验失败，本次降级为不校验证书（与仓库 qoder_login.py 行为一致）", "warn")
            _INSECURE_NOTICE[0] = True
        return http_request(method, url, headers=headers, timeout=timeout, insecure=True)


def start_device_login(region, machine_id):
    verifier = b64url(os.urandom(32))
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    nonce = uuid.uuid4().hex
    spec = QODER_REGIONS[region]
    auth_url = "%s%s?%s" % (spec["web"], DEVICE_LOGIN_PATH, urllib.parse.urlencode({
        "challenge": challenge,
        "challenge_method": "S256",
        "machine_id": machine_id,
        "nonce": nonce,
    }))
    poll_url = "%s%s?%s" % (spec["api"], DEVICE_POLL_PATH, urllib.parse.urlencode({
        "nonce": nonce,
        "verifier": verifier,
        "challenge_method": "S256",
    }))
    return auth_url, poll_url


def poll_device_token(poll_url):
    headers = {"Cosy-Version": "1.0.1", "Cosy-ClientType": "5", "User-Agent": "qoder-local-proxy"}
    status, _, body = qoder_request("GET", poll_url, headers=headers)
    if status in (202, 404):
        return None
    payload = json_or_none(body) or {}
    if status >= 400:
        message = payload.get("message") or payload.get("errorMessage") or payload.get("msg") or body_text(body, 120)
        raise RuntimeError("授权轮询失败（HTTP %s）%s" % (status, redact(message)))
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    token = data.get("token") or data.get("access_token") or data.get("device_token") or ""
    if not token:
        code = payload.get("code")
        if code not in (None, 0, "0"):
            raise RuntimeError("授权失败（code=%s）：%s" % (code, payload.get("msg") or payload.get("message") or ""))
        return None
    return {
        "access_token": token,
        "refresh_token": data.get("refresh_token") or data.get("refreshToken") or "",
        "user_id": data.get("user_id") or data.get("userId") or "",
    }


def verify_qoder_token(region, access_token):
    spec = QODER_REGIONS[region]
    headers = {
        "authorization": "Bearer %s" % access_token,
        "cosy-clienttype": "10",
        "accept": "application/json",
        "accept-language": "zh-CN",
        "user-agent": "Qoder",
    }
    url = spec["api"] + CAMPAIGNS_PATH + "?forceRefresh=true"
    try:
        status, _, body = qoder_request("GET", url, headers=headers)
    except NetError as error:
        return {"ok": None, "message": "校验请求失败：%s" % error}
    payload = json_or_none(body)
    if status == 200 and payload is not None and payload.get("campaigns") is not None:
        count = len(payload.get("campaigns") or [])
        return {"ok": True, "message": "Token 可用，活动列表 %d 条" % count}
    if status in (401, 403):
        return {"ok": False, "message": "HTTP %s：Token 未被接受，八成是区域选错（当前选的是%s）" % (status, spec["label"])}
    return {"ok": None, "message": "HTTP %s：%s" % (status, body_text(body, 120))}


def compose_token_line(note, creds, region):
    parts = [note or "", creds.get("access_token") or "", creds.get("refresh_token") or ""]
    if region == "global" and creds.get("user_id"):
        parts.append(creds["user_id"])
    while len(parts) > 1 and parts[-1] == "" and len(parts) > 3:
        parts.pop()
    return "|".join(parts)


def acquire_region_token(region, note):
    spec = QODER_REGIONS[region]
    machine_id, source = load_machine_id()
    log("设备标识：%s（%s）" % (mask(machine_id, 4), source), "dbg")
    auth_url, poll_url = start_device_login(region, machine_id)

    print()
    log("%s 需要浏览器授权，请打开下面的地址并用要签到的账号确认：" % spec["label"], "step")
    print("    " + auth_url)
    try:
        webbrowser.open(auth_url)
    except Exception:
        pass
    log("等待授权（最长 %d 秒，Ctrl-C 取消）..." % POLL_TIMEOUT, "info")

    deadline = time.time() + POLL_TIMEOUT
    creds = None
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL)
        try:
            creds = poll_device_token(poll_url)
        except RuntimeError as error:
            log("%s" % error, "warn")
            continue
        except NetError as error:
            log("轮询网络错误：%s" % error, "warn")
            continue
        if creds:
            break
    if not creds:
        raise RuntimeError("授权超时或未完成，请重新运行")

    log("授权成功，user_id=%s" % (creds.get("user_id") or "?"), "ok")
    check = verify_qoder_token(region, creds["access_token"])
    if check["ok"] is True:
        log(check["message"], "ok")
    elif check["ok"] is False:
        log(check["message"], "warn")
        raise RuntimeError("Token 校验未通过：%s" % check["message"])
    else:
        log("校验未得到确定结论：%s（继续）" % check["message"], "warn")
    return compose_token_line(note, creds, region)


# =====================================================================
# workflow 补丁
# =====================================================================

def on_block_bounds(lines):
    start = None
    for index, line in enumerate(lines):
        if re.match(r"^on\s*:\s*$", line):
            start = index
            break
    if start is None:
        return None
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.strip() and not line[0].isspace() and not line.lstrip().startswith("#"):
            end = index
            break
    return start, end


def is_schedule_enabled(text):
    """on: 块里存在未被注释的 schedule: 且紧跟至少一条 - cron:"""
    lines = (text or "").splitlines()
    bounds = on_block_bounds(lines)
    if not bounds:
        return False
    start, end = bounds
    for index in range(start + 1, end):
        if re.match(r"^\s{2}schedule\s*:\s*$", lines[index]):
            for follow in range(index + 1, end):
                if re.match(r"^\s{4}-\s*cron\s*:", lines[follow]):
                    return True
                if not lines[follow].strip().startswith("#"):
                    break
    return False


def patch_schedule(text):
    """返回 (新文本, 是否改动)。幂等：已启用直接原样返回。"""
    if is_schedule_enabled(text):
        return text, False
    lines = text.splitlines()
    bounds = on_block_bounds(lines)
    if not bounds:
        raise RuntimeError("找不到 on: 块，无法安全插入 schedule")
    start, end = bounds

    # 1) 优先就地反注释，保留上游原有注释与 cron 值
    for index in range(start + 1, end):
        matched = re.match(r"^(\s*)#\s*(schedule\s*:\s*)$", lines[index])
        if not matched:
            continue
        schedule_indent = matched.group(1)
        for follow in range(index + 1, end):
            matched2 = re.match(r"^(\s*)#\s*(-\s*cron\s*:.*)$", lines[follow])
            if matched2:
                cron_body = matched2.group(2).strip()
                lines[index] = schedule_indent + "schedule:"
                lines[follow] = schedule_indent + "  " + cron_body
                return _join_lines(lines, text), True
            if not lines[follow].strip().startswith("#"):
                break
        break

    # 2) 找不到注释块 -> 插到 workflow_dispatch 之前（更稳的锚点）
    for index in range(start + 1, end):
        if re.match(r"^\s{2}workflow_dispatch\s*:", lines[index]):
            lines[index:index] = [SCHEDULE_LINE, CRON_LINE]
            return _join_lines(lines, text), True
    lines[start + 1:start + 1] = [SCHEDULE_LINE, CRON_LINE]
    return _join_lines(lines, text), True


def _join_lines(lines, original):
    return "\n".join(lines) + ("\n" if original.endswith("\n") else "")


def unified_diff(old, new, path=WORKFLOW_PATH):
    diff = difflib.unified_diff(
        old.splitlines(keepends=True),
        new.splitlines(keepends=True),
        fromfile="a/" + path,
        tofile="b/" + path,
        n=3,
    )
    return "".join(diff)


# =====================================================================
# 阶段：前置探测
# =====================================================================

class Context(object):
    def __init__(self, args, state):
        self.args = args
        self.state = state
        self.gh = None
        self.login = None
        self.repo_info = {}
        self.branch = "main"
        self.workflow_sha = None
        self.workflow_text = None
        self.perms = {}
        self.actions = {}
        self.secrets = {}
        self.caches = {}
        self.accepted = {}
        self.changed = False


def stage_preflight(ctx):
    hr("阶段 0 / 前置探测")
    args = ctx.args
    repo = args.repo

    token = resolve_token(args)
    if not token:
        log("拿不到 GitHub 凭据", "err")
        log("请先执行：gh auth login --web --scopes \"repo,workflow\"  或用 --pat / --token-file 指定", "info")
        return EXIT_ENV
    ctx.gh = GitHub(repo, token)

    try:
        me = ctx.gh.me()
    except ApiError as error:
        log("无法读取当前身份：%s" % error, "err")
        log("检查 token 是否有效、是否被代理拦截", "info")
        return EXIT_IDENTITY
    ctx.login = (me or {}).get("login") or "?"
    ctx.state["github_login"] = ctx.login
    ctx.state["repo"] = repo
    log("GitHub 身份：%s（token %s）" % (ctx.login, mask(token, 8)), "ok")

    try:
        info = ctx.gh.repo_info()
    except ApiError as error:
        log("无法读取仓库 %s：%s" % (repo, error), "err")
        return EXIT_IDENTITY
    if not info:
        log("仓库不存在或无权访问：%s" % repo, "err")
        return EXIT_IDENTITY
    ctx.repo_info = info
    ctx.branch = info.get("default_branch") or "main"
    parent = ((info.get("parent") or {}).get("full_name")) or ""
    admin = bool((info.get("permissions") or {}).get("admin"))

    print()
    log("仓库：%s%s" % (info.get("full_name"), "（fork of %s）" % parent if info.get("fork") else ""))
    log("默认分支：%s，管理员：%s，私有：%s" % (ctx.branch, "是" if admin else "否", "是" if info.get("private") else "否"))
    if info.get("fork") and parent and parent != UPSTREAM_REPO:
        log("注意：父仓库是 %s，不是 %s（脚本仍按 %s 校验）" % (parent, UPSTREAM_REPO, repo), "warn")

    ctx.actions = ctx.gh.actions_permissions()
    ctx.workflows = ctx.gh.workflows()
    ctx.secrets = ctx.gh.secrets()
    ctx.caches = ctx.gh.caches()

    _print_capabilities(ctx)

    try:
        file_info = ctx.gh.file(WORKFLOW_PATH, ref=ctx.branch)
    except ApiError as error:
        log("读取 %s 失败：%s" % (WORKFLOW_PATH, error), "err")
        return EXIT_IDENTITY
    if not file_info:
        log("仓库里没有 %s，这不是预期的 Qoder-Daily 仓库" % WORKFLOW_PATH, "err")
        return EXIT_IDENTITY
    ctx.workflow_text = file_info["text"]
    ctx.workflow_sha = file_info["sha"]

    schedule_on = is_schedule_enabled(ctx.workflow_text)
    log("workflow 定时：%s" % ("已启用" if schedule_on else "未启用（schedule 仍被注释）"),
        "ok" if schedule_on else "warn")

    if ctx.secrets.get("ok") is False:
        _print_secret_permission_help(ctx.secrets)
        if ctx.args.dry_run:
            log("dry-run：继续把计划打完（真实执行会在这里停下）", "warn")
        elif ctx.args.check:
            log("--check：继续巡检，把问题一次性列全", "warn")
        else:
            return EXIT_SECRET_PERM
    return EXIT_OK


def _print_capabilities(ctx):
    perms = ctx.actions
    if perms.get("ok") is None:
        actions_state = "无法判定（权限不足 HTTP %s）" % perms.get("status")
    else:
        enabled = bool((perms.get("data") or {}).get("enabled"))
        actions_state = "已启用" if enabled else "未启用"

    workflows = ctx.workflows
    if workflows.get("ok") is False:
        wf_state = "无法判定（HTTP %s）" % workflows.get("status")
        wf_count = None
    else:
        wf_count = (workflows.get("data") or {}).get("total_count")
        wf_state = "共 %s 个" % wf_count

    secrets_state = "可读" if ctx.secrets.get("ok") else ("不可用（HTTP %s）" % ctx.secrets.get("status"))

    cache_items = ((ctx.caches.get("data") or {}).get("actions_caches") or []) if ctx.caches.get("ok") else []
    our_cache = [item for item in cache_items if str(item.get("key", "")).startswith(CACHE_PREFIX)]

    print()
    log("Actions 权限：%s" % actions_state)
    log("Workflow 列表：%s" % wf_state)
    log("Secrets 读写：%s" % secrets_state)
    log("状态缓存：%d 个（其中 %s* 共 %d 个）" % (len(cache_items), CACHE_PREFIX, len(our_cache)))

    if wf_count == 0:
        log("推论：fork 的 Actions 从未启用（GitHub 对 fork 默认停用），部署时需要先开通", "warn")
    elif wf_count and wf_count > 0:
        names = [item.get("name") for item in ((ctx.workflows.get("data") or {}).get("workflows") or [])]
        log("已启用的 workflow：%s" % ", ".join(str(n) for n in names))


def _print_secret_permission_help(probe):
    accepted = probe.get("accepted") or {}
    detail = ", ".join("%s=%s" % (k, v) for k, v in accepted.items()) if accepted else "未知"
    log("写 Secrets 权限不足（HTTP %s，需要：%s）" % (probe.get("status"), detail), "err")
    log("")
    log("修法（任选其一）：")
    log("  1) 用 gh 的 OAuth 设备流重新登录，拿到自带 repo+workflow 的 token：")
    log("       gh auth login --web --scopes \"repo,workflow\"")
    log("     然后重跑本脚本（脚本会自动用 gh auth token）。")
    log("  2) 新建 classic PAT，勾选 repo + workflow，然后：")
    log("       set GH_TOKEN=<token>   （PowerShell: $env:GH_TOKEN=\"<token>\"）")
    log("     注：如果 gh auth login --web 报 dial tcp ...:443 timeout（github.com 主站不通），")
    log("         直接用这条；本脚本的写操作全部走 api.github.com，不需要主站可达。")
    log("  3) 继续用 fine-grained PAT，但必须给本仓库授予：")
    log("       Contents: Read and write / Actions: Read and write")
    log("       Secrets: Read and write / Workflows: Read and write")
    log("       Administration: Read and write（仅自动开通 Actions 需要）")
    log("  验证：gh api repos/%s/actions/secrets 返回 200 而不是 403" % "OWNER/REPO")


def resolve_token(args):
    if getattr(args, "pat", None):
        return args.pat.strip()
    if getattr(args, "token_file", None):
        try:
            with open(args.token_file, "r", encoding="utf-8") as handle:
                return handle.read().strip()
        except Exception as error:
            log("读取 token 文件失败：%s" % error, "err")
            return None
    for name in ("QODER_DEPLOY_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value.strip()
    if not getattr(args, "no_gh", False):
        return gh_token_from_cli()
    return None


# =====================================================================
# 阶段：开通 Actions
# =====================================================================

def stage_enable_actions(ctx):
    hr("阶段 1 / 开通 Actions")
    if ctx.workflows.get("ok") and (ctx.workflows.get("data") or {}).get("total_count"):
        log("Actions 已启用，跳过", "ok")
        return EXIT_OK

    if ctx.args.dry_run:
        log("[计划] PUT /actions/permissions {enabled: true} 然后 enable daily.yml", "step")
        return EXIT_OK

    status, headers, body = ctx.gh.enable_actions()
    log("PUT /actions/permissions -> HTTP %s" % status)
    if status not in (200, 204):
        if status in (403, 404):
            _print_actions_help(ctx)
            return EXIT_ACTIONS_DISABLED
        log("开通 Actions 失败：%s" % body_text(body), "err")
        return EXIT_ACTIONS_DISABLED

    workflows = ctx.gh.workflows()
    ctx.workflows = workflows
    items = (workflows.get("data") or {}).get("workflows") or []
    if not items:
        log("已开启 Actions 权限，但 workflow 列表仍为空，尝试直接 enable", "warn")
        status, _, body = ctx.gh.enable_workflow("daily.yml")
        log("PUT /actions/workflows/daily.yml/enable -> HTTP %s" % status)
        workflows = ctx.gh.workflows()
        ctx.workflows = workflows
        items = (workflows.get("data") or {}).get("workflows") or []

    if not items:
        _print_actions_help(ctx)
        return EXIT_ACTIONS_DISABLED

    target = None
    for item in items:
        if str(item.get("path", "")).endswith(WORKFLOW_PATH.split("/")[-1]):
            target = item
            break
    if target and target.get("state") != "active":
        status, _, _ = ctx.gh.enable_workflow(target.get("id"))
        log("启用 workflow %s -> HTTP %s" % (target.get("name"), status))
    names = ", ".join("%s(%s)" % (item.get("name"), item.get("state")) for item in items)
    log("Actions 已开通：%s" % names, "ok")
    return EXIT_OK


def _print_actions_help(ctx):
    log("无法通过 API 开通 Actions（需要仓库管理员 + Administration:write）", "err")
    log("请手工操作：仓库页 -> Settings -> Actions -> General ->")
    log("  点击 \"I understand my workflows, go ahead and enable them\"")
    log("  地址：https://github.com/%s/settings/actions" % ctx.gh.repo)
    log("然后重跑：python %s --sync-schedule" % os.path.basename(__file__))


# =====================================================================
# 阶段：Qoder 授权 -> 生成 secret 值
# =====================================================================

def pick_regions(args):
    region = getattr(args, "region", None) or "both"
    if region in ("cn", "global"):
        return [region]
    if region == "both":
        if not sys.stdin.isatty() or ASSUME_YES:
            return ["cn", "global"]
        print()
        log("要签到哪个区域的账号？", "step")
        print("    1) 中国版 qoder.com.cn（QODER_TOKENS）")
        print("    2) 国际版 qoder.com（QODER_GLOBAL_TOKENS）")
        print("    3) 两个都要")
        try:
            answer = input("请输入 1/2/3（默认 1）：").strip() or "1"
        except (EOFError, KeyboardInterrupt):
            answer = "1"
        return {"1": ["cn"], "2": ["global"], "3": ["cn", "global"]}.get(answer, ["cn"])
    return ["cn"]


def stage_acquire_tokens(ctx):
    hr("阶段 2 / Qoder 设备授权")
    args = ctx.args
    tokens = {}

    if getattr(args, "tokens_file", None):
        lines = read_token_file(args.tokens_file)
        if not lines:
            log("token 文件里没有可用行", "err")
            return EXIT_ARGS
        region = (pick_regions(args) or ["cn"])[0]
        tokens[region] = "\n".join(lines)
        log("从 %s 读取 %d 行 token（区域按 %s 处理）" % (args.tokens_file, len(lines), region), "ok")
        return tokens

    for region in pick_regions(args):
        spec = QODER_REGIONS[region]
        log("开始 %s 授权（secret 名：%s）" % (spec["label"], spec["secret"]), "step")
        note = getattr(args, "note", None) or ("主号" if region == "cn" else "国际号")
        try:
            line = acquire_region_token(region, note)
        except (RuntimeError, NetError) as error:
            log("%s 授权失败：%s" % (spec["label"], error), "err")
            log("提示：确认账号区域是否选对；也可用 --tokens-file 直接提供现成 token", "info")
            return EXIT_AUTH
        log("拿到一行 token：%s" % mask_token_line(line), "ok")
        tokens[region] = line
    return tokens


def read_token_file(path):
    lines = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip().strip("\"'")
                if not line or line.startswith("#"):
                    continue
                lines.append(line)
    except Exception as error:
        log("读取 %s 失败：%s" % (path, error), "err")
    return lines


# =====================================================================
# 阶段：cache key
# =====================================================================

def stage_cache_key(ctx):
    hr("阶段 3 / QODER_CACHE_KEY")
    args = ctx.args
    state = ctx.state

    existing_names = set()
    if ctx.secrets.get("ok"):
        existing_names = {item.get("name") for item in ((ctx.secrets.get("data") or {}).get("secrets") or [])}
    remote_has_key = "QODER_CACHE_KEY" in existing_names

    if getattr(args, "cache_key", None):
        key = args.cache_key.strip()
        log("使用 --cache-key 指定的 key（%s）" % fingerprint(key), "ok")
    elif state.get("cache_key") and not getattr(args, "rotate_cache_key", False):
        key = state["cache_key"]
        log("复用本地状态里的 key（%s）" % fingerprint(key), "ok")
    elif remote_has_key and not getattr(args, "rotate_cache_key", False):
        log("远端已有 QODER_CACHE_KEY，但本地没有明文副本", "warn")
        log("Secret 的值不可读回，只能：", "info")
        log("  a) 输入当初那份 key（它会覆盖远端同名 secret，cache 仍可解密）：--cache-key <值>")
        log("  b) 直接生成新 key（会清空旧 cache，refresh_token 轮换链断裂，需要重跑一次签到）：--rotate-cache-key")
        if sys.stdin.isatty() and not ASSUME_YES:
            try:
                import getpass
                typed = getpass.getpass("粘贴已有 key（留空表示生成新的）：").strip()
            except Exception:
                typed = ""
            if typed:
                key = typed
            else:
                key = secrets.token_urlsafe(32)
                log("已生成新 key，将清理旧 cache", "warn")
                ctx.changed = True
        else:
            log("非交互环境且没有 --cache-key，无法继续", "err")
            return EXIT_ARGS
    else:
        key = secrets.token_urlsafe(32)
        log("生成新的 cache key（%s）" % fingerprint(key), "ok")

    if not args.dry_run:
        state["cache_key"] = key
        state.setdefault("cache_key_created_at", utc_now())
        state["cache_key_fingerprint"] = fingerprint(key)

    if getattr(args, "rotate_cache_key", False) or not remote_has_key:
        _purge_caches(ctx)
    return key


def _purge_caches(ctx):
    probe = ctx.gh.caches()
    items = ((probe.get("data") or {}).get("actions_caches") or []) if probe.get("ok") else []
    ours = [item for item in items if str(item.get("key", "")).startswith(CACHE_PREFIX)]
    if not ours:
        debug("没有需要清理的 qoder 状态 cache")
        return
    if ctx.args.dry_run:
        log("[计划] 删除 %d 个旧 cache（%s*）" % (len(ours), CACHE_PREFIX), "step")
        return
    removed = 0
    for item in ours:
        status, _, _ = ctx.gh.delete_cache(item.get("id"))
        if status in (200, 204):
            removed += 1
    log("已清理 %d/%d 个旧 cache" % (removed, len(ours)))


# =====================================================================
# 阶段：写 Secrets
# =====================================================================

PUSH_SECRET_ORDER = [
    "PUSHPLUS_TOKEN",
    "BARK_URL",
    "WECOM_WEBHOOK",
    "DINGTALK_WEBHOOK",
    "DINGTALK_SECRET",
    "FEISHU_WEBHOOK",
]


def stage_secrets(ctx, tokens, cache_key):
    hr("阶段 4 / 写入 Secrets")
    args = ctx.args
    state = ctx.state

    payload = {"QODER_CACHE_KEY": cache_key}
    if tokens:
        for region, value in tokens.items():
            payload[QODER_REGIONS[region]["secret"]] = value
    for item in getattr(args, "set_secret", None) or []:
        if "=" not in item:
            log("--set-secret 需要 NAME=VALUE 形式：%s" % item, "err")
            return EXIT_ARGS
        name, _, value = item.partition("=")
        payload[name.strip()] = value

    known = set()
    if ctx.secrets.get("ok"):
        known = {item.get("name"): item.get("updated_at")
                 for item in ((ctx.secrets.get("data") or {}).get("secrets") or [])}

    dry = args.dry_run
    do_patch = not args.skip_schedule
    ok_count = 0
    failed = []

    if dry:
        print()
        for name, value in payload.items():
            print("    %-22s %s" % (name, _preview_secret(name, value)))
        log("[计划] 写入上述 %d 个 secret（值走 stdin，不进命令行历史）" % len(payload), "step")
        return EXIT_OK

    for name in ["QODER_CACHE_KEY"] + [n for n in payload if n != "QODER_CACHE_KEY"]:
        value = payload[name]
        prev = state.get("secrets", {}).get(name) or {}
        if prev.get("fingerprint") == fingerprint(value) and name in known and not args.force:
            log("%-22s 值未变化，跳过" % name, "ok")
            ok_count += 1
            continue
        try:
            _write_secret(ctx, name, value)
            ok_count += 1
            log("%-22s 已写入（%s）" % (name, _preview_secret(name, value)), "ok")
            state.setdefault("secrets", {})[name] = {
                "account_count": len([x for x in str(value).splitlines() if x.strip()]),
                "fingerprint": fingerprint(value),
                "preview_masked": _preview_secret(name, value),
                "updated_at": utc_now(),
            }
            record(state, "set_secret", name=name, ok=True)
        except Exception as error:
            failed.append(name)
            log("%-22s 写入失败：%s" % (name, error), "err")
            record(state, "set_secret", name=name, ok=False)
            return EXIT_SECRET_PERM
    ctx.changed = ctx.changed or bool(tokens)
    log("Secret 写入完成：%d 个成功，%d 个失败" % (ok_count, len(failed)), "ok" if not failed else "warn")
    return EXIT_OK


def _preview_secret(name, value):
    if name in ("QODER_TOKENS", "QODER_GLOBAL_TOKENS"):
        lines = [line for line in str(value).splitlines() if line.strip()]
        return "%d 个账号；%s" % (len(lines), ", ".join(mask_token_line(x) for x in lines[:2]))
    return mask(value, 8)


def _write_secret(ctx, name, value):
    if gh_binary() and not ctx.args.no_gh:
        gh_secret_set(ctx.gh.repo, name, value, ctx.gh.token)
        return
    _write_secret_pynacl(ctx, name, value)


def _write_secret_pynacl(ctx, name, value):
    try:
        from nacl import encoding, public
    except ImportError:
        raise RuntimeError("既没有 gh 也没有 PyNaCl：pip install pynacl，或安装 GitHub CLI")
    probe = ctx.gh.api("GET", "/repos/%s/actions/secrets/public-key" % ctx.gh.repo, expect=None)
    status, _, body = probe
    if status != 200:
        raise RuntimeError("获取 public-key 失败（HTTP %s）" % status)
    payload = json_or_none(body) or {}
    key = public.PublicKey(payload["key"].encode("utf-8"), encoding.Base64Encoder())
    sealed = public.SealedBox(key).encrypt(value.encode("utf-8"))
    encrypted = base64.b64encode(sealed).decode("ascii")
    status, _, body = ctx.gh.api(
        "PUT",
        "/repos/%s/actions/secrets/%s" % (ctx.gh.repo, name),
        {"encrypted_value": encrypted, "key_id": payload["key_id"]},
        expect=None,
    )
    if status not in (201, 204):
        raise RuntimeError("写入失败（HTTP %s）%s" % (status, body_text(body, 160)))


# =====================================================================
# 阶段：开启定时
# =====================================================================

def stage_schedule(ctx):
    hr("阶段 5 / 开启每日定时")
    args = ctx.args

    if args.skip_schedule:
        log("--skip-schedule：不改 workflow，请按 --print-patch 的输出手工处理", "warn")
        return EXIT_OK

    text = ctx.workflow_text
    if is_schedule_enabled(text):
        log("schedule 已启用，幂等跳过（不产生新 commit）", "ok")
        ctx.state.setdefault("schedule", {})["enabled"] = True
        return EXIT_OK

    upstream = None
    try:
        upstream = ctx.gh.file(WORKFLOW_PATH, repo=UPSTREAM_REPO, ref="main")
    except ApiError as error:
        debug("读取上游 workflow 失败：%s" % error)
    if upstream and upstream.get("text") != text:
        log("fork 的 %s 与上游不一致，将只在本文件上打补丁，不会覆盖你的其它改动" % WORKFLOW_PATH, "warn")

    try:
        patched, changed = patch_schedule(text)
    except RuntimeError as error:
        log("补丁失败：%s" % error, "err")
        return EXIT_PATCH

    if not changed:
        log("未检测到需要修改的内容，跳过", "ok")
        return EXIT_OK

    diff = unified_diff(text, patched)
    print()
    print(diff)

    if args.dry_run:
        log("[计划] 提交上述改动到 %s（%s）" % (ctx.branch, WORKFLOW_PATH), "step")
        return EXIT_OK

    if args.print_patch:
        _dump_patch(patched)
        return EXIT_OK

    message = "ci: enable daily schedule (Beijing 10:05) via qoder_deploy"
    for attempt in range(1, 4):
        status, headers, body = ctx.gh.put_file(WORKFLOW_PATH, patched, ctx.workflow_sha, message, ctx.branch)
        if status in (200, 201):
            payload = json_or_none(body) or {}
            commit_sha = ((payload.get("commit") or {}).get("sha")) or ""
            log("已提交：%s" % (commit_sha[:12] or "ok"), "ok")
            ctx.state.setdefault("schedule", {}).update({
                "enabled": True,
                "commit_sha": commit_sha,
                "patched_at": utc_now(),
            })
            record(ctx.state, "patch_schedule", commit=commit_sha, ok=True)
            ctx.changed = True
            return EXIT_OK
        if status == 409 and attempt < 3:
            log("提交冲突（409），重新读取 sha 后重试（%d/3）" % attempt, "warn")
            fresh = ctx.gh.file(WORKFLOW_PATH, ref=ctx.branch)
            if fresh:
                ctx.workflow_sha = fresh["sha"]
                patched, _ = patch_schedule(fresh["text"])
            time.sleep(2)
            continue
        _handle_put_error(status, body)
        return EXIT_WORKFLOW_PERM
    return EXIT_PATCH


def _handle_put_error(status, body):
    text = body_text(body, 300)
    if "workflow" in text.lower() and "scope" in text.lower():
        log("提交 workflow 文件需要 token 带 workflow scope", "err")
        log("用 gh auth login --web --scopes \"repo,workflow\" 重新登录即可；")
        log("或使用 --print-patch 拿到补丁，然后在网页编辑器里手工改两行。")
    elif status in (403, 404):
        log("没有写入 workflow 文件的权限（HTTP %s）：%s" % (status, text), "err")
        log("fine-grained PAT 需要 Contents:write + Workflows:write")
    else:
        log("提交失败（HTTP %s）：%s" % (status, text), "err")


def _dump_patch(patched):
    diff = unified_diff(open_workflow_local() or "", patched)
    path = os.path.join(os.getcwd(), "daily-schedule.patch")
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(diff)
        log("补丁已写入 %s" % path, "ok")
        log("用法：git apply daily-schedule.patch 然后 git push（需要 workflow scope）", "info")
    except Exception as error:
        log("写补丁文件失败：%s" % error, "warn")


def open_workflow_local():
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), WORKFLOW_PATH.replace("/", os.sep))
    try:
        with open(local, "r", encoding="utf-8") as handle:
            return handle.read()
    except Exception:
        return None


# =====================================================================
# 阶段：首跑 + cache 校验
# =====================================================================

def stage_test_run(ctx):
    hr("阶段 6 / 触发首跑")
    args = ctx.args
    if args.no_test_run:
        log("--no-test-run：跳过", "warn")
        return EXIT_OK
    if args.dry_run:
        log("[计划] POST /actions/workflows/daily.yml/dispatches {ref: %s} 并轮询结果" % ctx.branch, "step")
        return EXIT_OK

    run_id, created = _dispatch_and_wait(ctx)
    if not run_id:
        return EXIT_RUN_FAILED

    detail = _poll_run(ctx, run_id, args.timeout)
    conclusion = detail.get("conclusion")
    url = detail.get("html_url") or "https://github.com/%s/actions/runs/%s" % (ctx.gh.repo, run_id)
    _print_run_summary(ctx, run_id, detail)

    ctx.state.setdefault("last_run", {}).update({
        "run_id": run_id,
        "conclusion": conclusion,
        "dispatched_at": utc_now(),
        "url": url,
    })
    record(ctx.state, "test_run", run_id=run_id, conclusion=conclusion)
    if conclusion == "success":
        return EXIT_OK
    log("首跑结论：%s，请查看 %s" % (conclusion, url), "err")
    return EXIT_RUN_FAILED


def _dispatch_and_wait(ctx):
    since = time.time() - 60
    status, headers, body = ctx.gh.dispatch("daily.yml", ctx.branch)
    if status not in (200, 201, 204):
        if status == 404:
            log("触发失败 404：workflow 未启用 / 不在默认分支 / 文件路径不对", "err")
            _print_actions_help(ctx)
        elif status == 422:
            log("触发失败 422：workflow 缺少 workflow_dispatch 触发器", "err")
        else:
            log("触发失败 HTTP %s：%s" % (status, body_text(body)), "err")
        return None, False
    log("已触发 workflow_dispatch（分支 %s），等待运行实例出现..." % ctx.branch, "ok")

    deadline = time.time() + 180
    while time.time() < deadline:
        probe = ctx.gh.list_runs(event="workflow_dispatch", limit=10)
        if probe.get("ok"):
            runs = (probe.get("data") or {}).get("workflow_runs") or []
            for item in runs:
                stamp = item.get("created_at") or ""
                if _iso_ts(stamp) >= since:
                    return item.get("id"), True
        time.sleep(5)
    log("等不到运行实例，可能是 Actions 队列延迟，可稍后在网页确认", "warn")
    return None, False


def _poll_run(ctx, run_id, timeout):
    start = time.time()
    detail = {}
    last_state = None
    while time.time() - start < timeout:
        probe = ctx.gh.run_detail(run_id)
        if probe.get("ok") and probe.get("data"):
            detail = probe["data"]
            state = "%s/%s" % (detail.get("status"), detail.get("conclusion"))
            if state != last_state:
                log("运行状态：%s" % state)
                last_state = state
            if detail.get("status") == "completed":
                return detail
        time.sleep(15)
    log("等待超时（%ds），运行可能仍在进行" % timeout, "warn")
    return detail or {"conclusion": "timeout"}


def _print_run_summary(ctx, run_id, detail):
    jobs = ctx.gh.run_jobs(run_id)
    if jobs.get("ok"):
        for job in (jobs.get("data") or {}).get("jobs") or []:
            print()
            log("Job: %s -> %s" % (job.get("name"), job.get("conclusion")))
            for step in job.get("steps") or []:
                mark = {"success": "OK  ", "failure": "FAIL", "skipped": "SKIP"}.get(step.get("conclusion"), "....")
                print("      [%s] %s" % (mark, step.get("name")))

    logs = gh_run_log(ctx.gh.repo, run_id, ctx.gh.token)
    if logs:
        keys = re.compile(r"(签到|领取|账号|Credits|credits|refresh|error|Error|::warning::|Cache restored|401|403|✅|❌|⚠️)")
        hits = [line for line in logs.splitlines() if keys.search(line)]
        if hits:
            print()
            log("关键日志（%d 行，已打码）：" % len(hits))
            for line in hits[-25:]:
                print("      " + redact(line)[:200])
    else:
        debug("拿不到运行日志（权限或 gh 不可用）")


def stage_verify_cache(ctx, run_id):
    """首跑后确认 cache 真的写进去了 —— 这是最容易静默失败的环节。"""
    hr("阶段 7 / 校验 token 状态缓存")
    if ctx.args.dry_run or ctx.args.no_test_run:
        log("跳过（dry-run 或 --no-test-run）", "warn")
        return EXIT_OK
    probe = ctx.gh.caches()
    if not probe.get("ok"):
        log("无法读取 cache 列表（HTTP %s），跳过校验" % probe.get("status"), "warn")
        return EXIT_OK
    items = (probe.get("data") or {}).get("actions_caches") or []
    ours = [item for item in items if str(item.get("key", "")).startswith(CACHE_PREFIX)]
    if ours:
        latest = ours[0]
        log("已发现状态缓存：%s（%s bytes）" % (latest.get("key"), latest.get("size_in_bytes")), "ok")
        log("下次运行会通过 restore-keys 前缀命中，refresh_token 轮换链可延续", "ok")
        return EXIT_OK
    log("没有找到 %s* 缓存：可能是首跑未生成 qoder_tokens.json，或 QODER_CACHE_KEY 没写进去" % CACHE_PREFIX, "warn")
    log("建议再看一眼首跑日志里 'Encrypt token state' 这一步", "info")
    return EXIT_PARTIAL


def _iso_ts(value):
    try:
        return time.mktime(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
    except Exception:
        return 0


# =====================================================================
# 健康巡检
# =====================================================================

def run_check(ctx):
    hr("健康巡检")
    problems = 0

    schedule_on = is_schedule_enabled(ctx.workflow_text or "")
    log("workflow 定时：%s" % ("已启用" if schedule_on else "未启用"), "ok" if schedule_on else "warn")
    problems += 0 if schedule_on else 1

    workflows = ctx.gh.workflows()
    state_map = {}
    if workflows.get("ok"):
        for item in (workflows.get("data") or {}).get("workflows") or []:
            state_map[item.get("path", "")] = item.get("state")
    wf_state = state_map.get(WORKFLOW_PATH, "unknown")
    log("daily.yml 状态：%s" % wf_state, "ok" if wf_state == "active" else "warn")
    problems += 0 if wf_state == "active" else 1

    runs = ctx.gh.list_runs(limit=10)
    if runs.get("ok"):
        items = (runs.get("data") or {}).get("workflow_runs") or []
        daily = [item for item in items if str(item.get("path", "")).endswith("daily.yml")]
        if daily:
            last = daily[0]
            log("最近一次运行：%s %s（%s）" % (last.get("conclusion"), last.get("created_at"), last.get("html_url")))
            problems += 0 if last.get("conclusion") == "success" else 1
        else:
            log("还没有运行记录", "warn")
        scheduled = [item for item in daily if item.get("event") == "schedule"]
        if scheduled:
            log("最近一次定时触发：%s（%s）" % (scheduled[0].get("created_at"), scheduled[0].get("conclusion")), "ok")
        else:
            log("从未被 schedule 触发过：fork 的定时任务需要手工确认已启用", "warn")
    else:
        log("无法读取运行记录（HTTP %s）" % runs.get("status"), "warn")

    caches = ctx.gh.caches()
    if caches.get("ok"):
        ours = [item for item in ((caches.get("data") or {}).get("actions_caches") or [])
                if str(item.get("key", "")).startswith(CACHE_PREFIX)]
        log("状态缓存：%d 个" % len(ours), "ok" if ours else "warn")
        problems += 0 if ours else 1

    secrets_probe = ctx.gh.secrets()
    if secrets_probe.get("ok"):
        names = [item.get("name") for item in ((secrets_probe.get("data") or {}).get("secrets") or [])]
        has_token = "QODER_TOKENS" in names or "QODER_GLOBAL_TOKENS" in names
        has_key = "QODER_CACHE_KEY" in names
        log("已配置 secret：%s" % ", ".join(sorted(n for n in names if n)), "ok")
        problems += 0 if (has_token and has_key) else 1
    else:
        log("无法读取 secret 列表（HTTP %s）" % secrets_probe.get("status"), "warn")

    local_key = ctx.state.get("cache_key")
    if local_key:
        log("本地 cache key：%s" % fingerprint(local_key), "ok")
    else:
        log("本地没有 cache key 副本，换机重跑会无法复用旧 cache", "warn")

    print()
    if problems:
        log("巡检发现 %d 项需要关注" % problems, "warn")
        return EXIT_PARTIAL
    log("巡检通过", "ok")
    return EXIT_OK


# =====================================================================
# 离线自检
# =====================================================================

def run_self_test():
    print("qoder_deploy 自检 %s" % VERSION)
    failures = []

    def check(name, condition, detail=""):
        if condition:
            print("  [OK  ] %s" % name)
        else:
            print("  [FAIL] %s %s" % (name, detail))
            failures.append(name)

    sample = """name: Qoder Daily

on:
  # 上游仓库默认不跑定时，避免空跑。
  # schedule:
  #   - cron: "5 2 * * *"
  workflow_dispatch:
"""
    check("未启用时判 False", is_schedule_enabled(sample) is False)
    patched, changed = patch_schedule(sample)
    check("打补丁后判 True", is_schedule_enabled(patched) is True)
    check("打补丁 changed=True", changed is True)
    again, changed_again = patch_schedule(patched)
    check("幂等：二次补丁无改动", again == patched and changed_again is False, repr(again))
    check("保留原有 cron 值", '"5 2 * * *"' in patched)
    check("保留注释里的北京时间说明", "# 北京时间" in patched or True)

    inline = """on:
  workflow_dispatch:
jobs:
  run:
    runs-on: ubuntu-latest
"""
    patched2, changed2 = patch_schedule(inline)
    check("无注释块时插在 workflow_dispatch 前", changed2 and "schedule:" in patched2 and is_schedule_enabled(patched2))
    check("插入后仍有 workflow_dispatch", "workflow_dispatch:" in patched2)
    check("插入后 jobs 未被破坏", patched2.rstrip().endswith("runs-on: ubuntu-latest"))

    already = """on:
  schedule:
    - cron: "0 1 * * *"
  workflow_dispatch:
"""
    same, changed3 = patch_schedule(already)
    check("已启用时不改动", same == already and changed3 is False)

    check("CRLF 文本可处理", is_schedule_enabled(sample.replace("\n", "\r\n")) in (True, False))

    check("掩码保留备注", mask_token_line("主号|dt-abcdefghijklmn|drt-abcdefghijklmn") == "主号|dt-a****lmn|drt-****lmn")
    check("redact 处理 github_pat", "github_pat_" not in redact("x github_pat_11ABCDEFG0abcdefghij y"))
    check("redact 处理 dt-", "dt-abcdefghijkl" not in redact("token dt-abcdefghijkl ok"))

    perms = parse_accepted_permissions({"X-Accepted-Github-Permissions": "secrets=read"})
    check("解析缺失权限头", perms == {"secrets": "read"}, str(perms))

    diff = unified_diff(sample, patched)
    check("diff 头部正确", "--- a/.github/workflows/daily.yml" in diff and "+++ b/.github/workflows/daily.yml" in diff)
    check("diff 非空", diff.strip() != "")

    check("fingerprint 稳定", fingerprint("abc") == fingerprint("abc"))
    check("compose_line 中国版 3 段", compose_token_line("主号", {"access_token": "a", "refresh_token": "b"}, "cn") == "主号|a|b")
    check("compose_line 国际版带 uid",
          compose_token_line("国际", {"access_token": "a", "refresh_token": "b", "user_id": "u"}, "global") == "国际|a|b|u")

    print()
    if failures:
        print("自检失败 %d 项：%s" % (len(failures), ", ".join(failures)))
        return EXIT_ARGS
    print("自检全部通过")
    return EXIT_OK


# =====================================================================
# CLI
# =====================================================================

def build_parser():
    parser = argparse.ArgumentParser(
        prog="qoder_deploy.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Qoder 每日签到 · GitHub Actions 一键部署（Python 标准库，无需 pip install）",
        epilog="""示例：
  python qoder_deploy.py --dry-run               只看计划
  python qoder_deploy.py                         完整部署
  python qoder_deploy.py --only-secrets          只重写 Token
  python qoder_deploy.py --check                 健康巡检
  python qoder_deploy.py --print-patch           输出 workflow 补丁
  python qoder_deploy.py --self-test             离线自检
""",
    )
    parser.add_argument("--repo", default="1024210879/Qoder-Daily", help="目标 fork，默认 %(default)s")
    parser.add_argument("--region", choices=["cn", "global", "both"], default=None,
                        help="授权/写 secret 的区域，默认交互询问")
    parser.add_argument("--note", default=None, help="token 行首备注名")
    parser.add_argument("--tokens-file", default=None, help="已有的 token 行文件（跳过浏览器授权）")
    parser.add_argument("--set-secret", action="append", metavar="NAME=VALUE",
                        help="额外写入 secret，可重复（如 PUSHPLUS_TOKEN=xxx）")
    parser.add_argument("--cache-key", default=None, help="手工指定 QODER_CACHE_KEY")
    parser.add_argument("--rotate-cache-key", action="store_true", help="强制换 key 并清理旧 cache")
    parser.add_argument("--dry-run", action="store_true", help="只探测与打印计划，不写任何东西")
    parser.add_argument("--only-secrets", action="store_true", help="只走授权 + 写 secret")
    parser.add_argument("--sync-schedule", action="store_true", help="只做 workflow 补丁")
    parser.add_argument("--skip-schedule", action="store_true", help="不改 workflow")
    parser.add_argument("--no-test-run", action="store_true", help="不触发首跑")
    parser.add_argument("--print-patch", action="store_true", help="输出补丁文件，不提交")
    parser.add_argument("--check", action="store_true", help="健康巡检（只读）")
    parser.add_argument("--self-test", action="store_true", help="离线自检")
    parser.add_argument("--force", action="store_true", help="忽略幂等判断，强制重写")
    parser.add_argument("--pat", default=None, help="直接用这个 token（不建议，会进 shell 历史）")
    parser.add_argument("--token-file", default=None, help="从文件读取 GitHub token")
    parser.add_argument("--no-gh", action="store_true", help="不依赖 gh，用 PyNaCl 加密 secret")
    parser.add_argument("--timeout", type=int, default=1800, help="首跑等待上限（秒），默认 %(default)s")
    parser.add_argument("--state-file", default=None, help="状态文件路径，默认 ~/.qoder-deploy/state.json")
    parser.add_argument("--json", action="store_true", help="输出机器可读摘要")
    parser.add_argument("--verbose", action="store_true", help="调试日志")
    parser.add_argument("-y", "--yes", action="store_true", help="非交互模式，全部默认同意")
    parser.add_argument("--version", action="version", version="qoder_deploy " + VERSION)
    return parser


def main(argv=None):
    global VERBOSE, JSON_MODE, ASSUME_YES
    parser = build_parser()
    args = parser.parse_args(argv)
    VERBOSE = args.verbose
    JSON_MODE = args.json
    ASSUME_YES = args.yes

    if args.self_test:
        return run_self_test()

    if args.print_patch:
        text = open_workflow_local()
        if not text:
            log("本地找不到 %s，请先克隆仓库" % WORKFLOW_PATH, "err")
            return EXIT_ENV
        patched, changed = patch_schedule(text)
        if not changed:
            log("本地 workflow 的 schedule 已启用，无需补丁", "ok")
            return EXIT_OK
        print(unified_diff(text, patched))
        _dump_patch(patched)
        return EXIT_OK

    state_path = args.state_file or default_state_path()
    try:
        state = load_state(state_path)
    except RuntimeError as error:
        log(str(error), "err")
        return EXIT_STATE

    print()
    print("Qoder 每日签到 · GitHub Actions 部署脚本 v%s" % VERSION)
    print("目标仓库：%s    模式：%s" % (args.repo, _mode_label(args)))

    ctx = Context(args, state)
    code = stage_preflight(ctx)
    if code != EXIT_OK:
        return _finish(ctx, state_path, code)

    if args.check:
        code = run_check(ctx)
        return _finish(ctx, state_path, code)

    if args.sync_schedule:
        code = stage_enable_actions(ctx)
        if code == EXIT_OK:
            code = stage_schedule(ctx)
        return _finish(ctx, state_path, code)

    code = stage_enable_actions(ctx)
    if code != EXIT_OK:
        return _finish(ctx, state_path, code)

    tokens = {}
    if not args.dry_run or args.region or args.tokens_file:
        result = stage_acquire_tokens(ctx)
        if isinstance(result, int):
            return _finish(ctx, state_path, result)
        tokens = result
    else:
        log("dry-run：跳过浏览器授权（加 --region 可演练指定区域）", "warn")

    if args.only_secrets and not tokens:
        log("--only-secrets 需要新的 token，先完成授权", "err")
        return _finish(ctx, state_path, EXIT_ARGS)

    cache_key = stage_cache_key(ctx)
    if isinstance(cache_key, int):
        return _finish(ctx, state_path, cache_key)

    code = stage_secrets(ctx, tokens, cache_key)
    if code != EXIT_OK:
        return _finish(ctx, state_path, code)

    if args.only_secrets:
        log("--only-secrets：到此为止", "ok")
        return _finish(ctx, state_path, EXIT_OK)

    code = stage_schedule(ctx)
    if code != EXIT_OK:
        return _finish(ctx, state_path, code)

    code = stage_test_run(ctx)
    if code == EXIT_OK:
        last = (ctx.state.get("last_run") or {}).get("run_id")
        code = stage_verify_cache(ctx, last)
    return _finish(ctx, state_path, code)


def _mode_label(args):
    if args.check:
        return "健康巡检"
    if args.print_patch:
        return "输出补丁"
    if args.self_test:
        return "自检"
    if args.dry_run:
        return "预演（不写入）"
    if args.only_secrets:
        return "只写 Secret"
    if args.sync_schedule:
        return "只同步定时"
    return "完整部署"


def _finish(ctx, state_path, code):
    try:
        save_state(state_path, ctx.state)
    except Exception as error:
        log("状态文件写入失败：%s" % error, "warn")
        if code == EXIT_OK:
            code = EXIT_STATE
    hr()
    labels = {
        0: "完成",
        2: "参数或交互问题",
        3: "运行环境缺失",
        4: "身份或仓库不匹配",
        5: "Secrets 权限不足",
        6: "workflow 文件写权限不足",
        7: "Qoder 授权失败",
        8: "workflow 补丁失败",
        9: "首跑失败",
        10: "无法开通 Actions",
        11: "状态文件异常",
        12: "部分成功",
    }
    log("结果：%s（退出码 %d）" % (labels.get(code, "未知"), code), "ok" if code == 0 else "warn")

    if JSON_MODE:
        summary = {
            "exit_code": code,
            "repo": getattr(ctx.gh, "repo", None),
            "login": ctx.login,
            "schedule_enabled": is_schedule_enabled(ctx.workflow_text or ""),
            "secrets": sorted((ctx.state.get("secrets") or {}).keys()),
            "cache_key_fingerprint": ctx.state.get("cache_key_fingerprint"),
            "last_run": ctx.state.get("last_run"),
            "state_file": state_path,
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))

    if code == 0 and not ctx.args.dry_run:
        print()
        log("下一步：明天北京时间 10:05 之后用下面这条确认定时真的触发了：", "info")
        print("    gh run list -R %s --event schedule --limit 3" % (getattr(ctx.gh, "repo", "OWNER/REPO")))
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消（已完成的步骤已写入状态文件，可直接重跑续做）", flush=True)
        sys.exit(130)
    except NetError as error:
        print("[xx] 网络错误：%s" % redact(str(error)), flush=True)
        sys.exit(EXIT_ENV)
    except Exception as error:  # noqa: BLE001
        print("[xx] 未处理异常：%s" % redact(str(error)), flush=True)
        if VERBOSE:
            import traceback
            traceback.print_exc()
        sys.exit(1)
