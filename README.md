# vex_upgrade_cves

Compare two RPM package inventories against the Red Hat **vex-feed** archive and list CVEs that become fixed when moving from **CURRENT → FUTURE**.

## Setup

```bash
pip install -r requirements.txt
# optional, better EVR compare on RHEL/Fedora:
# dnf install python3-rpm
```

## Quick start

```bash
rpm -qa --qf '%{NEVRA}\n' > current.txt
# future.txt = post-change inventory (see docs/usecases.md)
python3 vex_upgrade_cves.py \
  --current current.txt \
  --future future.txt \
  --archive ./vex-archive.tar.zst \
  -o result.json
```

First run downloads ~900MB from:

`https://security.access.redhat.com/data/csaf/v2/vex-feed/vex-archive.tar.zst`

Or use an already extracted tree:

```bash
python3 vex_upgrade_cves.py \
  --current current.txt --future future.txt \
  --vex-dir /path/to/vex-feed \
  -o result.csv
```

`--product-prefix rhel-` (default) keeps only RHEL product_ids. Use `''` for all products.

## Use cases

Step-by-step guides:

**[docs/usecases.md](docs/usecases.md)**

1. **Host before/after update** — `rpm -qa` → update → `rpm -qa`, document CVEs fixed  
2. **Repository before/after sync** — `dnf repoquery` snapshots around a mirror/content-view update  
3. **Preview `dnf update`** — installed host vs would-be set after upgrades from a repo (no apply)  
7. **Satellite content view A→B** — compare two CV versions  
8. **EUS/AUS streams** — pin repoids + `--product-prefix`  
9. **CI gate** — fail if required / Critical CVEs are not fixed by FUTURE

## Result

Each row = CVE + package fixed by FUTURE but not by CURRENT:

- `severity` — VEX aggregate severity  
- `current_evr` / `future_evr` — from your lists  
- `fixed_evr` — first fixed NVR from VEX `product_status.fixed`  
- `product_stream` / `product_id` — VEX relationship ids  

## Notes

- Prefer **NEVRA** lines (`Name-Epoch:Version-Release.Arch`). See [docs/usecases.md](docs/usecases.md).
- VEX **known_affected** entries have no NVR; this tool only uses **fixed** versioned refs.
- Dist-tag gate (`.el8` / `.el9` / `.el10`) avoids applying wrong-stream fixes.
