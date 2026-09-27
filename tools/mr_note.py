# -*- coding: utf-8 -*-
"""Post an update note on fdroiddata MR !47395 (5G Proxy Client)."""
import json
import sys
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

TOKEN = Path(r"D:\workspace\AndroidApp\test\gitlab_token.txt").read_text(encoding="utf-8").strip()

BODY = """Updated to **v1.6.2** (versionCode 15, commit `1e9442183fecccf0c17087f84ea13970b2731fed`, the commit the `v1.6.2` tag points to), keeping a single latest build entry as before.

What changed since the version you last built:

- **Fix (the significant one):** with UDP-in-TCP enabled, Google search and other QUIC/HTTP-3 sites were extremely slow. The client's UDP-in-TCP frame reader treated a *full receive buffer* as a protocol violation and tore the connection down. A QUIC connection's first flight is ~13 KB (10 packets, initial congestion window) while the buffer was 8 KB, so essentially every QUIC session was destroyed one RTT after it was created and immediately rebuilt. A full buffer is now back-pressure, the buffer no longer shrinks as traffic flows, and its size went 8 KB → 32 KB.
- Every UDP-in-TCP disconnect now logs a reason (peer closed / local send-recv error / epoll error) instead of failing silently — this is what made the bug hard to find in the first place.

Measured on a real device, same load before/after: 25 connection teardowns → 0; session rebuilds 47.7% → 0%.

Tag & signed APK: https://github.com/tokyoxpa3/5G-Proxy-Client/releases/tag/v1.6.2

The matching `fastlane/metadata/android/{en-US,zh-TW}/changelogs/15.txt` is present in the tag, so the F-Droid changelog tab will be populated."""

payload = {"body": BODY}
req = urllib.request.Request(
    "https://gitlab.com/api/v4/projects/fdroid%2Ffdroiddata/merge_requests/47395/notes",
    data=json.dumps(payload).encode("utf-8"),
    headers={"PRIVATE-TOKEN": TOKEN, "Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=60) as resp:
    r = json.loads(resp.read().decode("utf-8"))
    print("note id:", r.get("id"), "| created:", r.get("created_at"))
