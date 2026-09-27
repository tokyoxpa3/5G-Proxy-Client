# -*- coding: utf-8 -*-
"""把 fdroiddata MR 分支的 metadata 更新到本 repo 目前的最新發佈版本。

用途：每次發新 tag 之後，F-Droid 的「New app」MR（或已上架的 metadata）需要把
Builds 條目與 CurrentVersion/CurrentVersionCode 指到新版本，否則 F-Droid 建出來
的還是舊版。這支腳本把這件事自動化，避免手抄版本號／commit 抄錯。

設計要點：
- versionName/versionCode 一律從 app/build.gradle 讀，不從 tag 名稱猜
  （tag 是 v1.6.2，但 F-Droid 的 changelog 檔名用的是 versionCode 15）。
- commit 取 `git rev-list -n1 v<versionName>`，也就是 **tag 實際指向的 commit** ——
  這是本 repo 既有 MR 的慣例（見 MR 上的 "pin build commit to vX.Y.Z tag commit
  for reproducible build"），不是隨便挑一個 master 上的 commit。
- 只做「就地取代」既有 YAML 的欄位，不重新生成整份檔案 —— 這樣 F-Droid 審閱者
  在 MR 上做過的任何調整都不會被覆蓋掉。
- Token 從 repo 外讀（D:\\workspace\\AndroidApp\\test\\gitlab_token.txt），不進版控。

用法：
    C:/dev/Python311/python.exe tools/update_fdroiddata.py --dry-run
    C:/dev/Python311/python.exe tools/update_fdroiddata.py
"""
import argparse
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

REPO_ROOT = Path(__file__).resolve().parent.parent
TOKEN_FILE = Path(r"D:\workspace\AndroidApp\test\gitlab_token.txt")

PROJECT = "85291843"          # tokyoxpa3/fdroiddata fork
BRANCH = "com.tokyoxpa3.socksclient"
PKG = "com.tokyoxpa3.socksclient"
METADATA_PATH = f"metadata/{PKG}.yml"
MR_IID = 47395


def read_token() -> str:
    if not TOKEN_FILE.exists():
        sys.exit(f"找不到 token 檔：{TOKEN_FILE}")
    return TOKEN_FILE.read_text(encoding="utf-8").strip()


def api_json(path: str, token: str, method: str = "GET", payload=None):
    url = f"https://gitlab.com/api/v4/{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"PRIVATE-TOKEN": token}
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read().decode("utf-8")
    return json.loads(body) if body.strip() else {}


def api_raw(path: str, token: str) -> str:
    req = urllib.request.Request(
        f"https://gitlab.com/api/v4/{path}", headers={"PRIVATE-TOKEN": token}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8")


def read_version() -> tuple:
    """從 app/build.gradle 讀 versionName/versionCode（唯一真相）。"""
    text = (REPO_ROOT / "app" / "build.gradle").read_text(encoding="utf-8")
    code = re.search(r"versionCode\s+(\d+)", text)
    name = re.search(r'versionName\s+"([^"]+)"', text)
    if not code or not name:
        sys.exit("app/build.gradle 裡找不到 versionCode / versionName")
    return name.group(1), int(code.group(1))


def tag_commit(version_name: str) -> str:
    tag = f"v{version_name}"
    out = subprocess.run(
        ["git", "rev-list", "-n1", tag], cwd=REPO_ROOT, capture_output=True, text=True
    )
    if out.returncode != 0:
        sys.exit(f"解析 tag {tag} 失敗（tag 還沒推上去？）：{out.stderr.strip()}")
    return out.stdout.strip()


def patch_yaml(yml: str, version_name: str, version_code: int, commit: str) -> str:
    """就地取代 Builds 的第一個條目與 CurrentVersion*；其餘原樣保留。"""
    builds = re.search(
        r"(Builds:\n  - versionName: )[^\n]*\n(    versionCode: )[^\n]*\n(    commit: )[^\n]*",
        yml,
    )
    if not builds:
        sys.exit("YAML 裡找不到預期的 Builds 條目結構，請人工檢查")
    yml = (
        yml[: builds.start()]
        + f"{builds.group(1)}{version_name}\n"
        + f"{builds.group(2)}{version_code}\n"
        + f"{builds.group(3)}{commit}"
        + yml[builds.end():]
    )

    yml, n1 = re.subn(r"(?m)^CurrentVersion: .*$", f"CurrentVersion: {version_name}", yml)
    yml, n2 = re.subn(r"(?m)^CurrentVersionCode: .*$", f"CurrentVersionCode: {version_code}", yml)
    if n1 != 1 or n2 != 1:
        sys.exit(f"CurrentVersion/CurrentVersionCode 取代次數異常（{n1}/{n2}）")
    return yml


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="只印出結果，不送出 commit")
    args = ap.parse_args()

    token = read_token()
    version_name, version_code = read_version()
    commit = tag_commit(version_name)

    quoted = urllib.parse.quote(METADATA_PATH, safe="")
    ref = urllib.parse.quote(BRANCH, safe="")
    yml = api_raw(f"projects/{PROJECT}/repository/files/{quoted}/raw?ref={ref}", token)
    updated = patch_yaml(yml, version_name, version_code, commit)

    print(f"versionName : {version_name}")
    print(f"versionCode : {version_code}")
    print(f"commit      : {commit}  (tag v{version_name})")
    print(f"MR          : !{MR_IID}  branch {BRANCH}")
    print("--- diff ---")
    for a, b in zip(yml.splitlines(), updated.splitlines()):
        if a != b:
            print(f"- {a}")
            print(f"+ {b}")

    if updated == yml:
        print("已是最新，無需變更。")
        return
    if args.dry_run:
        print("(dry-run，未送出)")
        return

    result = api_json(
        f"projects/{PROJECT}/repository/commits",
        token,
        method="POST",
        payload={
            "branch": BRANCH,
            "commit_message": (
                f"{PKG}: bump to {version_name} (versionCode {version_code}); "
                f"pin build commit to v{version_name} tag commit"
            ),
            "actions": [{"action": "update", "file_path": METADATA_PATH, "content": updated}],
        },
    )
    print("committed:", result.get("short_id"), "|", result.get("title"))
    print("web_url  :", result.get("web_url"))


if __name__ == "__main__":
    main()
