# vex_upgrade_cves

Compare two `rpm -qa` lists against the Red Hat **vex-feed** archive and list CVEs that become fixed when moving from CURRENT → FUTURE.

## Setup

```bash
pip install -r requirements.txt
# optional, better EVR compare on RHEL/Fedora:
# dnf install python3-rpm
```

## Usage

```bash
rpm -qa --qf '%{NEVRA}\n' > current.txt
# future.txt = target NVRs (image, mirror, planned upgrade set)
python3 vex_upgrade_cves.py \
  --current current.txt \
  --future future.txt \
  --archive ./vex-archive.tar.zst \
  -o result.json
```

First run downloads ~900MB from:

`https://security.access.redhat.com/data/csaf/v2/vex-feed/vex-archive.tar.zst`

Faster (no archive): point at already extracted / year tree:

```bash
python3 vex_upgrade_cves.py \
  --current current.txt --future future.txt \
  --vex-dir /path/to/vex-feed/2026 \
  -o result.csv
```

`--product-prefix rhel-` (default) keeps only RHEL product_ids. Use `''` for all products.

## Result

Each row = CVE + package fixed by FUTURE but not by CURRENT:

- `current_evr` / `future_evr` — from your lists  
- `fixed_evr` — first fixed NVR from VEX `product_status.fixed`  
- `product_stream` / `product_id` — VEX relationship ids  

## Notes

- VEX **known_affected** entries have no NVR; this tool only uses **fixed** versioned refs.
- Dist-tag gate (`.el8` / `.el9` / `.el10`) avoids applying wrong-stream fixes.
