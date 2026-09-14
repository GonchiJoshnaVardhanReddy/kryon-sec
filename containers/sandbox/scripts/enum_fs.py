#!/usr/bin/env python3
"""Post-exploit filesystem enumeration (baked into the sandbox image).

argv: /opt/kryonsec/enum_fs.py <target>

EVIDENCE COLLECTION ONLY. Walks the sandbox-visible filesystem (bounded
depth and entry count) and reports: setuid/setgid binaries, world-writable
directories, credential-shaped filenames, and the mounted-filesystems
table. The <target> argument is engagement CONTEXT for the record.

Read-only: this script never writes, chmods, or deletes anything.
"""

import json
import os
import stat
import sys

MAX_ENTRIES = 20000
MAX_DEPTH = 6
SKIP_DIRS = {"/proc", "/sys", "/dev", "/run"}

CRED_NAMES = (
    "id_rsa", "id_ed25519", "authorized_keys", "known_hosts",
    ".env", "credentials", "creds", "secret", ".npmrc", ".netrc",
    ".git-credentials", "shadow", "passwd", ".htpasswd",
)


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    setuid, setgid, writable, creds = [], [], [], []
    entries = 0

    for root, dirs, files in os.walk("/", topdown=True):
        depth = root.rstrip("/").count("/")
        if depth >= MAX_DEPTH:
            dirs[:] = []
        # SKIP_DIRS holds absolute paths; /proc, /sys, /dev, /run exist only
        # at the root, where os.path.join("/", d) produces exactly these.
        # (No prefix matching: a dir named e.g. "processor" is legitimate.)
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in SKIP_DIRS]
        for name in files:
            entries += 1
            if entries > MAX_ENTRIES:
                break
            path = os.path.join(root, name)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                if st.st_mode & stat.S_ISUID:
                    setuid.append(path)
                if st.st_mode & stat.S_ISGID:
                    setgid.append(path)
                low = name.lower()
                if any(c in low for c in CRED_NAMES):
                    creds.append(path)
            elif stat.S_ISDIR(st.st_mode):
                if st.st_mode & stat.S_IWOTH and path not in writable:
                    writable.append(path)
        if entries > MAX_ENTRIES:
            break

    mounts = []
    with open("/proc/mounts", "r", errors="replace") as f:
        for line in f.read(16384).splitlines():
            parts = line.split()
            if len(parts) >= 3:
                mounts.append({"device": parts[0], "mountpoint": parts[1],
                               "fstype": parts[2]})

    print(json.dumps({
        "probe": "enum_fs",
        "target_context": target,
        "entries_scanned": entries,
        "setuid_binaries": setuid[:200],
        "setgid_binaries": setgid[:200],
        "world_writable_dirs": writable[:200],
        "credential_shaped_files": creds[:200],
        "mounts": mounts,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
