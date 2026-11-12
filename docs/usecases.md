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

## 4. Satellite content view version A → B

**Goal:** Document CVEs fixed when promoting or comparing two **Content View** versions (or Library → CV, or CV → Composite).

**Idea:** Treat each CV version’s RPM set as an inventory. Same math as use case 2; source is Satellite instead of a generic mirror.

### Option A — `dnf` against published CV repos

On a build host that can reach Satellite’s content URLs (or after attaching activation keys for each version):

```bash
# CURRENT = older content view version (example repoids — use yours)
dnf -q repoquery \
  --repoid=Company_CV_RHEL9_BaseOS_1 \
  --repoid=Company_CV_RHEL9_AppStream_1 \
  --available --qf '%{NEVRA}' | sort -u > current.txt

# FUTURE = newer content view version
dnf -q repoquery \
  --repoid=Company_CV_RHEL9_BaseOS_2 \
  --repoid=Company_CV_RHEL9_AppStream_2 \
  --available --qf '%{NEVRA}' | sort -u > future.txt

python3 vex_upgrade_cves.py \
  --current current.txt \
  --future future.txt \
  -o cv-1-to-2-cves.json
```

### Option B — Hammer / API export

Export package NEVRAs for two content view version IDs, then run the tool:

```bash
# Illustrative — adjust org, CV name, version IDs to your Satellite
ORG=Example
CV=RHEL9-Base
VER_OLD=1.0
VER_NEW=1.1

# Example hammer listing (field names vary by Satellite version; ensure NEVRA-like output)
hammer --csv package list --organization "$ORG" \
  --content-view "$CV" --content-view-version "$VER_OLD" \
  | tail -n +2 > current.raw

hammer --csv package list --organization "$ORG" \
  --content-view "$CV" --content-view-version "$VER_NEW" \
  | tail -n +2 > future.raw
```

Normalize hammer CSV columns to one NEVRA per line (name, epoch, version, release, arch), then:

```bash
python3 vex_upgrade_cves.py \
  --current current.txt \
  --future future.txt \
  -o satellite-cv-promote-cves.json
```

**Tips:**

- Compare the **same** repos/arches in both versions (BaseOS+AppStream, same major).
- Library sync alone ≠ CV promote: hosts only see what the CV version publishes.
- Pair with use case 6 to gate promotion in automation.

---

## 5. EUS / AUS (and similar) streams only

**Goal:** Limit analysis to Extended Update Support, Advanced Update Support, or another pinned stream so GA/mainline fixes do not pollute the report.

VEX `product_id` / `product_stream` values look like:

```text
rhel-8.8.0.z.eus::baseos
rhel-8.4.0.z.aus::baseos
rhel-9.4.0.z.eus
```

### Pin repositories (inventory side)

Only query the EUS/AUS repoids your hosts actually use:

```bash
# Example RHEL 9.4 EUS
REPOS='--repoid=rhel-9-for-x86_64-baseos-eus-rpms --repoid=rhel-9-for-x86_64-appstream-eus-rpms'

dnf -q repoquery $REPOS --available --qf '%{NEVRA}' | sort -u > future.txt
rpm -qa --qf '%{NEVRA}\n' | sort > current.txt   # EUS-subscribed host
```

### Pin VEX product ids (tool side)

`--product-prefix` is a **prefix match** on VEX `product_id`:

```bash
# All RHEL (default)
--product-prefix 'rhel-'

# Narrow examples (pick what matches your stream ids in VEX)
--product-prefix 'rhel-8.8.0.z.eus'
--product-prefix 'rhel-9.4.0.z.eus'
--product-prefix 'rhel-8.4.0.z.aus'
```

```bash
python3 vex_upgrade_cves.py \
  --current current.txt \
  --future future.txt \
  --product-prefix 'rhel-9.4.0.z.eus' \
  -o eus-9.4-cves.json
```

**Tips:**

- Dist-tag gate already prefers matching `.el8_8` / `.el9_4`-style releases; wrong-stream NVRs are less likely to match, but **prefix** is the hard filter.
- Peek streams present in a result:  
  `jq -r '.[].product_stream' eus-9.4-cves.json | sort -u`
- If prefix is too narrow and the result is empty, list a few `product_id` values from VEX for your CVE and adjust the prefix.
- AUS/EUS/TUS/LL naming differs by major; confirm ids against one VEX file under `vex-feed/`.

---

## 6. CI gate (fail if required CVEs are not fixed by FUTURE)

**Goal:** In automation (CV promote, image rebuild, nightly repo sync), fail the pipeline unless FUTURE closes an expected set of CVEs — especially Critical/Important.

**What the tool outputs:** CVEs **newly fixed** by CURRENT→FUTURE (plus `severity` from VEX). It does **not** list every CVE that still affects FUTURE. Gates below work with that model.

### Pattern A — must-close CVE allowlist

Maintain `required-cves.txt` (one CVE id per line). Fail if any required id is missing from the result:

```bash
python3 vex_upgrade_cves.py \
  --current current.txt \
  --future future.txt \
  --archive ./vex-archive.tar.zst \
  -o result.json

python3 - <<'PY'
import json, sys
from pathlib import Path

required = {
    l.strip()
    for l in Path("required-cves.txt").read_text().splitlines()
    if l.strip() and not l.startswith("#")
}
rows = json.loads(Path("result.json").read_text())
fixed = {r["cve"] for r in rows}
missing = sorted(required - fixed)
if missing:
    print("Missing required CVE fixes in FUTURE:", ", ".join(missing))
    sys.exit(1)
print(f"OK: all {len(required)} required CVEs fixed by FUTURE")
PY
```

### Pattern B — require Critical (or Important) fixes when promoting

Useful after a security sync: fail if **no** Critical rows appear (or fewer than N):

```bash
python3 vex_upgrade_cves.py \
  --current cv-old.txt \
  --future cv-new.txt \
  -o result.json

python3 - <<'PY'
import json, sys
from pathlib import Path

MIN_CRITICAL = 1  # set to 0 to disable
rows = json.loads(Path("result.json").read_text())
critical = sorted({r["cve"] for r in rows if (r.get("severity") or "").lower() == "critical"})
important = sorted({r["cve"] for r in rows if (r.get("severity") or "").lower() == "important"})
print(f"Critical fixed: {len(critical)}  Important fixed: {len(important)}")
if len(critical) < MIN_CRITICAL:
    print(f"CI gate failed: need >= {MIN_CRITICAL} Critical CVE(s) fixed")
    sys.exit(1)
PY
```

### Pattern C — GitHub Actions sketch

```yaml
# .github/workflows/vex-cv-gate.yml (sketch)
jobs:
  vex-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - name: Fetch package lists
        run: |
          # Produce current.txt / future.txt from Satellite export or cached artifacts
          cp artifacts/cv-old-nevra.txt current.txt
          cp artifacts/cv-new-nevra.txt future.txt
      - name: Run VEX compare
        run: |
          python3 vex_upgrade_cves.py \
            --current current.txt \
            --future future.txt \
            --archive "${{ runner.temp }}/vex-archive.tar.zst" \
            -o result.json
      - name: Enforce required CVEs
        run: |
          python3 scripts/check_required_cves.py required-cves.txt result.json
      - uses: actions/upload-artifact@v4
        with:
          name: vex-result
          path: result.json
```

**Tips:**

- Cache `vex-archive.tar.zst` in CI (large download).
- Combine with use case 4: CURRENT/FUTURE = two Satellite CV versions.
- Combine with use case 5: add `--product-prefix 'rhel-9.4.0.z.eus'` in the CI job.
- Policy list (`required-cves.txt`) should be CVEs you already know affect CURRENT (scanner, previous VEX run, RHSA tracker). Missing from the result can also mean “already fixed in CURRENT” — keep the allowlist tight.

---

## Input format checklist

| Source | Good for | Command / shape |
| --- | --- | --- |
| Installed RPMs | Use cases 1, 3, 5 | `rpm -qa --qf '%{NEVRA}\n'` |
| Repo contents | Use cases 2, 4, 5 | `dnf repoquery --available --qf '%{NEVRA}'` |
| Pending upgrades | Use case 3 | `dnf repoquery --upgrades --qf '%{NEVRA}'` |
| Satellite CV export | Use cases 4, 6 | hammer/API → NEVRA lines |
| `dnf list` / `yum list` tables | — | **Not** parsed; convert to NEVRA first |

---

## Reading the result

Each row means: for this `package`, CURRENT EVR is below the VEX `fixed_evr`, FUTURE EVR is at or above it.

| Field | Meaning |
| --- | --- |
| `cve` | CVE closed by moving to FUTURE |
| `package` | RPM name |
| `severity` | VEX aggregate severity (Critical, Important, …) |
| `current_evr` / `future_evr` | From your lists |
| `fixed_evr` | Fix NVR from VEX |
| `product_stream` | RHEL/product stream id in VEX |

Default `--product-prefix rhel-` limits fixes to RHEL product ids. Pass `--product-prefix ''` to include all products in the archive. Use a narrower prefix for EUS/AUS (use case 5).
