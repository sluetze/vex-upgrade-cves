# Use cases

The tool always needs two package inventories in **NEVRA** (or compatible) form:

| Input | Meaning |
| --- | --- |
| `--current` | Package set **before** the change |
| `--future` | Package set **after** the change (or the set you plan to move to) |

It reports CVEs that are **not** fixed by CURRENT but **are** fixed by FUTURE (per Red Hat VEX `fixed` NVRs).

**NEVRA** = `Name-Epoch:Version-Release.Arch`, for example:

```text
kernel-0:6.12.0-55.107.1.el10_0.x86_64
```

Preferred capture command:

```bash
rpm -qa --qf '%{NEVRA}\n'
# or from a repo:
dnf repoquery --qf '%{NEVRA}' --available
```

Shared run (after you have `current.txt` / `future.txt`):

```bash
python3 vex_upgrade_cves.py \
  --current current.txt \
  --future future.txt \
  --archive ./vex-archive.tar.zst \
  -o result.json
```

Use `-o result.csv` for spreadsheets. First run downloads the VEX archive (~900MB) unless you pass `--vex-dir`.

---

## 1. Host before/after `dnf update` (document what was fixed)

**Goal:** You updated a host and want an audit trail of CVEs closed by that update.

**Steps:**

```bash
# BEFORE update
rpm -qa --qf '%{NEVRA}\n' | sort > current.txt

sudo dnf update -y
# reboot if needed (kernel, etc.)

# AFTER update
rpm -qa --qf '%{NEVRA}\n' | sort > future.txt

python3 vex_upgrade_cves.py \
  --current current.txt \
  --future future.txt \
  -o host-update-cves.json
```

**Tips:**

- Keep `current.txt` with the change ticket / change window.
- If you forgot the pre-update snapshot, restore from backup, Satellite host package profile, or an older sosreport `installed-rpms`.
- Result rows are CVE + package pairs that became fixed.

---

## 2. Repository before/after sync (document what the mirror gained)

**Goal:** You refreshed a local/Satellite/Pulp mirror (or content view) and want to know which CVEs newly have fixing builds in that repository content — independent of any one host.

**Steps:**

```bash
# Point dnf at the repo(s) under test (repoids as configured on the builder host)
REPOS='--repoid=rhel-9-for-x86_64-baseos-rpms --repoid=rhel-9-for-x86_64-appstream-rpms'

# BEFORE sync / promote
dnf -q repoquery $REPOS --available --qf '%{NEVRA}' | sort -u > current.txt

# Sync or promote new content into the mirror / content view, then refresh metadata
sudo dnf clean all && sudo dnf makecache

# AFTER sync / promote
dnf -q repoquery $REPOS --available --qf '%{NEVRA}' | sort -u > future.txt

python3 vex_upgrade_cves.py \
  --current current.txt \
  --future future.txt \
  -o repo-sync-cves.json
```

**Tips:**

- This answers “what can this repo fix now that it could not before?”, not “what did host X install?”.
- Use the same repoids and arches for both snapshots.
- For Satellite: export/package list from the content view version before and after promote, still as NEVRA lines.

---

## 3. Host vs “what `dnf update` would install” (preview without applying)

**Goal:** Host is on CURRENT (`rpm -qa`). You want CVEs that would become fixed **if** you ran `dnf update` against a given repository — without applying the update yet.

**Idea:** `--current` = installed set. `--future` = installed set with available upgrades substituted.

```bash
# Installed (CURRENT)
rpm -qa --qf '%{NEVRA}\n' | sort > current.txt

# Available upgrades from enabled repos (or pin repoids)
dnf -q repoquery --upgrades --qf '%{NEVRA}' | sort -u > upgrades.txt

# Build FUTURE = CURRENT, but replace any package that has an upgrade
python3 - <<'PY'
from pathlib import Path
import re

NEVRA = re.compile(
    r"^(?P<name>.+)-(?P<epoch>\d+):(?P<version>[^-]+)-(?P<release>[^-]+)\.(?P<arch>[^.]+)$"
)
NVRA = re.compile(
    r"^(?P<name>.+)-(?P<version>[^-]+)-(?P<release>[^-]+)\.(?P<arch>[^.]+)$"
)

def parse(line: str):
    line = line.strip()
    if not line:
        return None
    m = NEVRA.match(line) or NVRA.match(line)
    if not m:
        return None
    g = m.groupdict()
    name = g["name"]
    # strip epoch glued into name for rare forms; NEVRA path already has epoch
    return name, line

def load(path):
    by_name = {}
    for line in Path(path).read_text().splitlines():
        p = parse(line)
        if not p:
            continue
        name, nevra = p
        by_name[name] = nevra  # last wins; lists should be unique per name
    return by_name

current = load("current.txt")
upgrades = load("upgrades.txt")
future = dict(current)
future.update(upgrades)  # upgrades override same name

Path("future.txt").write_text("\n".join(sorted(future.values())) + "\n")
print(f"current={len(current)} upgrades={len(upgrades)} future={len(future)}")
PY

python3 vex_upgrade_cves.py \
  --current current.txt \
  --future future.txt \
  -o would-fix-on-dnf-update.json
```

**Tips:**

- Enable only the repos you would really use for the update (same as production).
- This is a **preview**. Exact transaction can still differ (obsoletes, modular filters, excludes, `dnf versionlock`).
- For a single repo: add `--repoid=...` to the `dnf repoquery --upgrades` line.

---

## Input format checklist

| Source | Good for | Command / shape |
| --- | --- | --- |
| Installed RPMs | Use cases 1 & 3 | `rpm -qa --qf '%{NEVRA}\n'` |
| Repo contents | Use case 2 | `dnf repoquery --available --qf '%{NEVRA}'` |
| Pending upgrades | Use case 3 | `dnf repoquery --upgrades --qf '%{NEVRA}'` |
| `dnf list` / `yum list` tables | — | **Not** parsed; convert to NEVRA first |

---

## Reading the result

Each row means: for this `package`, CURRENT EVR is below the VEX `fixed_evr`, FUTURE EVR is at or above it.

| Field | Meaning |
| --- | --- |
| `cve` | CVE closed by moving to FUTURE |
| `package` | RPM name |
| `current_evr` / `future_evr` | From your lists |
| `fixed_evr` | Fix NVR from VEX |
| `product_stream` | RHEL/product stream id in VEX |

Default `--product-prefix rhel-` limits fixes to RHEL product ids. Pass `--product-prefix ''` to include all products in the archive.
