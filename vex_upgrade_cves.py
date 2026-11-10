#!/usr/bin/env python3
"""Compare CURRENT vs FUTURE RPM lists against Red Hat VEX-feed archive.

Reports CVEs that are NOT fixed in CURRENT but ARE fixed in FUTURE
(i.e. the upgrade/remediation closes them).

Package lists: output of `rpm -qa` or `rpm -qa --qf '%{NEVRA}\\n'`.

Example:
  rpm -qa --qf '%{NEVRA}\\n' > current.txt
  # future.txt = planned NVRs / target image rpm -qa
  ./vex_upgrade_cves.py --current current.txt --future future.txt -o result.json
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import tarfile
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

VEX_ARCHIVE_URL = (
    "https://security.access.redhat.com/data/csaf/v2/vex-feed/vex-archive.tar.zst"
)
ARCHIVE_LATEST_URL = (
    "https://security.access.redhat.com/data/csaf/v2/vex-feed/archive_latest.txt"
)

# product_reference examples:
#   kernel-0:6.12.0-55.107.1.el10_0.src
#   kernel/kernel-0:6.12.0-55.107.1.el10_0
#   openssl/openssl-1:3.0.7-18.el9_2
VERSIONED_RPM_RE = re.compile(
    r"^(?:(?P<path>[^/]+)/)?(?P<name>[^/]+?)-(?P<epoch>\d+):(?P<version>[^-]+)-(?P<release>\S+)$"
)
NEVRA_RE = re.compile(
    r"^(?P<name>.+)-(?P<version>[^-]+)-(?P<release>[^-]+)\.(?P<arch>[^.]+)$"
)
# name-epoch:version-release.arch  OR  epoch:name-version-release.arch rare
NEVRA_EPOCH_RE = re.compile(
    r"^(?P<name>.+)-(?P<epoch>\d+):(?P<version>[^-]+)-(?P<release>[^-]+)\.(?P<arch>[^.]+)$"
)


@dataclass(frozen=True)
class Evr:
    epoch: str
    version: str
    release: str

    def __str__(self) -> str:
        return f"{self.epoch}:{self.version}-{self.release}"


@dataclass
class Rpm:
    name: str
    evr: Evr
    arch: str = ""
    raw: str = ""


@dataclass(frozen=True)
class Fix:
    cve: str
    pkg_name: str
    evr: Evr
    product_stream: str
    product_id: str


# --- RPM version compare (RPM-compatible enough for EVR) -----------------

def _rpm_cmp_segment(a: str, b: str) -> int:
    """Compare one EVR segment per rpmvercmp rules."""
    if a == b:
        return 0
    ia = ib = 0
    na, nb = len(a), len(b)
    while ia < na or ib < nb:
        while ia < na and not a[ia].isalnum():
            ia += 1
        while ib < nb and not b[ib].isalnum():
            ib += 1
        if ia >= na or ib >= nb:
            break
        ja, jb = ia, ib
        if a[ia].isdigit():
            while ja < na and a[ja].isdigit():
                ja += 1
            while jb < nb and b[jb].isdigit():
                jb += 1
            # numeric: strip leading zeros
            sa = a[ia:ja].lstrip("0") or "0"
            sb = b[ib:jb].lstrip("0") or "0"
            if len(sa) != len(sb):
                return 1 if len(sa) > len(sb) else -1
            if sa != sb:
                return 1 if sa > sb else -1
        else:
            while ja < na and a[ja].isalpha():
                ja += 1
            while jb < nb and b[jb].isalpha():
                jb += 1
            sa, sb = a[ia:ja], b[ib:jb]
            if sa != sb:
                return 1 if sa > sb else -1
        ia, ib = ja, jb
    if ia >= na and ib >= nb:
        return 0
    # tilde / leftover: shorter non-empty remaining with digits wins differently;
    # approximate: remaining content means greater unless starts with tilde
    if ia < na and a[ia] == "~":
        return -1
    if ib < nb and b[ib] == "~":
        return 1
    if ia >= na:
        return -1
    if ib >= nb:
        return 1
    return 0


def evr_cmp(a: Evr, b: Evr) -> int:
    try:
        import rpm  # type: ignore

        return rpm.labelCompare(
            (str(a.epoch), a.version, a.release),
            (str(b.epoch), b.version, b.release),
        )
    except Exception:
        for x, y in (
            (str(int(a.epoch or "0")), str(int(b.epoch or "0"))),
            (a.version, b.version),
            (a.release, b.release),
        ):
            c = _rpm_cmp_segment(x, y)
            if c:
                return c
        return 0


def is_fixed(installed: Evr, fix: Evr) -> bool:
    return evr_cmp(installed, fix) >= 0


# --- parsers -------------------------------------------------------------

def parse_rpm_line(line: str) -> Rpm | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # drop (none) epoch noise from some queries
    line = line.replace("(none):", "0:")

    m = NEVRA_EPOCH_RE.match(line)
    if m:
        return Rpm(
            name=m.group("name"),
            evr=Evr(m.group("epoch"), m.group("version"), m.group("release")),
            arch=m.group("arch"),
            raw=line,
        )
    m = NEVRA_RE.match(line)
    if m:
        return Rpm(
            name=m.group("name"),
            evr=Evr("0", m.group("version"), m.group("release")),
            arch=m.group("arch"),
            raw=line,
        )
    # name\tepoch:version-release  or  name epoch:version-release
    if "\t" in line or " " in line:
        parts = re.split(r"[\t ]+", line, maxsplit=1)
        if len(parts) == 2 and ":" in parts[1]:
            name, rest = parts
            em = re.match(r"^(?:(\d+):)?([^-]+)-(.+)$", rest)
            if em:
                return Rpm(
                    name=name,
                    evr=Evr(em.group(1) or "0", em.group(2), em.group(3)),
                    raw=line,
                )
    return None


def load_rpm_list(path: Path) -> dict[str, Rpm]:
    """Map package name -> highest EVR seen (multi-arch: keep max)."""
    out: dict[str, Rpm] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        rpm = parse_rpm_line(line)
        if not rpm:
            continue
        prev = out.get(rpm.name)
        if prev is None or evr_cmp(rpm.evr, prev.evr) > 0:
            out[rpm.name] = rpm
    return out


def parse_fixed_ref(product_reference: str) -> tuple[str, Evr] | None:
    m = VERSIONED_RPM_RE.match(product_reference)
    if not m:
        return None
    name = m.group("name")
    if name.endswith(".src") or product_reference.endswith(".src"):
        # prefer binary; still record src under base name without .src
        if name.endswith(".src"):
            name = name[: -len(".src")]
        rel = m.group("release")
        if rel.endswith(".src"):
            rel = rel[: -len(".src")]
        return name, Evr(m.group("epoch"), m.group("version"), rel)
    return name, Evr(m.group("epoch"), m.group("version"), m.group("release"))


# --- VEX archive ---------------------------------------------------------

def download_archive(dest: Path, url: str = VEX_ARCHIVE_URL) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 0:
        print(f"Using existing archive: {dest}", file=sys.stderr)
        return dest
    print(f"Downloading {url}", file=sys.stderr)
    print(f"  -> {dest}", file=sys.stderr)
    req = urllib.request.Request(url, headers={"User-Agent": "vex-upgrade-cves/1.0"})
    with urllib.request.urlopen(req, timeout=600) as resp, open(dest, "wb") as out:
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
            print(".", end="", file=sys.stderr, flush=True)
    print(file=sys.stderr)
    return dest


def open_tar_zst(path: Path) -> tarfile.TarFile:
    try:
        import zstandard as zstd  # type: ignore
    except ImportError as e:
        raise SystemExit(
            "Need zstandard: pip install zstandard\n"
            "Or: dnf install python3-zstandard"
        ) from e

    fh = open(path, "rb")
    dctx = zstd.ZstdDecompressor()
    stream = dctx.stream_reader(fh)
    return tarfile.open(fileobj=stream, mode="r|")


def iter_vex_docs(archive: Path) -> Iterator[dict]:
    tar = open_tar_zst(archive)
    try:
        for member in tar:
            if not member.isfile() or not member.name.endswith(".json"):
                continue
            if "cve-" not in member.name.lower():
                continue
            f = tar.extractfile(member)
            if f is None:
                continue
            try:
                yield json.loads(f.read().decode("utf-8"))
            except Exception as exc:
                print(f"skip {member.name}: {exc}", file=sys.stderr)
    finally:
        tar.close()


def iter_vex_docs_from_dir(root: Path) -> Iterator[dict]:
    for path in sorted(root.rglob("cve-*.json")):
        try:
            yield json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"skip {path}: {exc}", file=sys.stderr)


def extract_fixes(doc: dict, product_prefix: str | None) -> list[Fix]:
    tracking = (doc.get("document") or {}).get("tracking") or {}
    cve = tracking.get("id") or ""
    if not cve.startswith("CVE-"):
        # fallback from filename-ish title
        return []

    vulns = doc.get("vulnerabilities") or []
    if not vulns:
        return []
    status = (vulns[0].get("product_status") or {}).get("fixed") or []
    fixed_ids = set(status)

    rels = (doc.get("product_tree") or {}).get("relationships") or []
    by_id = {
        r.get("full_product_name", {}).get("product_id"): r
        for r in rels
        if r.get("full_product_name", {}).get("product_id")
    }

    fixes: list[Fix] = []
    for pid in fixed_ids:
        if product_prefix and not pid.startswith(product_prefix):
            continue
        rel = by_id.get(pid)
        if not rel:
            continue
        pref = rel.get("product_reference") or ""
        parsed = parse_fixed_ref(pref)
        if not parsed:
            continue
        name, evr = parsed
        fixes.append(
            Fix(
                cve=cve,
                pkg_name=name,
                evr=evr,
                product_stream=rel.get("relates_to_product_reference") or "",
                product_id=pid,
            )
        )
    return fixes


def compatible_release(installed_rel: str, fix_rel: str) -> bool:
    """Rough dist-tag gate so el8 fix not applied to el9 install."""
    def tags(rel: str) -> set[str]:
        return set(re.findall(r"\.el\d+(?:_\d+)?", rel))

    it, ft = tags(installed_rel), tags(fix_rel)
    if not it or not ft:
        return True
    # el10_0 compatible with el10; el8_10 with el8_10 / el8
    for a in it:
        major = re.match(r"(\.el\d+)", a)
        if not major:
            continue
        for b in ft:
            if b.startswith(major.group(1)):
                return True
    return False


def choose_fix(pkg: Rpm, fixes: Iterable[Fix]) -> Fix | None:
    """Lowest fixed EVR that applies to this installed package (compatible dist)."""
    candidates = [
        f
        for f in fixes
        if f.pkg_name == pkg.name and compatible_release(pkg.evr.release, f.evr.release)
    ]
    if not candidates:
        return None
    best = candidates[0]
    for f in candidates[1:]:
        if evr_cmp(f.evr, best.evr) < 0:
            best = f
    return best


def analyze(
    current: dict[str, Rpm],
    future: dict[str, Rpm],
    fixes_by_pkg: dict[str, list[Fix]],
) -> list[dict]:
    results = []
    # only packages present in both, or in future with a name we know from current
    names = set(current) | set(future)
    cves_done: set[tuple[str, str]] = set()

    for name in sorted(names):
        cur = current.get(name)
        fut = future.get(name)
        if not fut:
            continue
        pkg_fixes = fixes_by_pkg.get(name) or []
        if not pkg_fixes:
            continue

        # group by CVE, pick a representative fix EVR per CVE
        by_cve: dict[str, list[Fix]] = defaultdict(list)
        for fx in pkg_fixes:
            by_cve[fx.cve].append(fx)

        for cve, flist in by_cve.items():
            fix = choose_fix(fut if fut else cur, flist)  # type: ignore[arg-type]
            if fix is None and cur:
                fix = choose_fix(cur, flist)
            if fix is None:
                continue

            cur_ok = is_fixed(cur.evr, fix.evr) if cur else False
            fut_ok = is_fixed(fut.evr, fix.evr)

            # fixed by FUTURE = was vulnerable (or missing) now, fixed after upgrade
            if fut_ok and not cur_ok:
                key = (cve, name)
                if key in cves_done:
                    continue
                cves_done.add(key)
                results.append(
                    {
                        "cve": cve,
                        "package": name,
                        "current_evr": str(cur.evr) if cur else None,
                        "future_evr": str(fut.evr),
                        "fixed_evr": str(fix.evr),
                        "product_stream": fix.product_stream,
                        "product_id": fix.product_id,
                    }
                )
    results.sort(key=lambda r: (r["cve"], r["package"]))
    return results


def write_results(path: Path, rows: list[dict]) -> None:
    if path.suffix.lower() == ".csv":
        if not rows:
            path.write_text(
                "cve,package,current_evr,future_evr,fixed_evr,product_stream,product_id\n",
                encoding="utf-8",
            )
            return
        with path.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
    else:
        path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


def build_fix_index(
    docs: Iterable[dict], product_prefix: str | None
) -> dict[str, list[Fix]]:
    by_pkg: dict[str, list[Fix]] = defaultdict(list)
    n_docs = n_fixes = 0
    for doc in docs:
        n_docs += 1
        if n_docs % 500 == 0:
            print(f"  scanned {n_docs} VEX docs...", file=sys.stderr)
        for fx in extract_fixes(doc, product_prefix):
            by_pkg[fx.pkg_name].append(fx)
            n_fixes += 1
    print(f"Indexed {n_fixes} fixed package entries from {n_docs} docs", file=sys.stderr)
    return by_pkg


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--current", type=Path, required=True, help="rpm -qa list (today)")
    ap.add_argument("--future", type=Path, required=True, help="rpm -qa list (target)")
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("vex_upgrade_result.json"),
        help="Result JSON or CSV",
    )
    ap.add_argument(
        "--archive",
        type=Path,
        default=Path("vex-archive.tar.zst"),
        help="Local path for VEX archive (downloaded if missing)",
    )
    ap.add_argument(
        "--vex-dir",
        type=Path,
        help="Skip archive; read cve-*.json from this directory tree",
    )
    ap.add_argument(
        "--download",
        action="store_true",
        help="Force re-download of vex-archive.tar.zst",
    )
    ap.add_argument(
        "--product-prefix",
        default="rhel-",
        help="Only use fixed product_ids with this prefix ('' = all)",
    )
    args = ap.parse_args()

    current = load_rpm_list(args.current)
    future = load_rpm_list(args.future)
    print(f"CURRENT packages: {len(current)}  FUTURE packages: {len(future)}", file=sys.stderr)

    prefix = args.product_prefix or None

    if args.vex_dir:
        docs = iter_vex_docs_from_dir(args.vex_dir)
    else:
        if args.download and args.archive.exists():
            args.archive.unlink()
        download_archive(args.archive)
        docs = iter_vex_docs(args.archive)

    fixes_by_pkg = build_fix_index(docs, prefix)
    rows = analyze(current, future, fixes_by_pkg)
    write_results(args.output, rows)
    print(f"Wrote {len(rows)} CVE/package rows -> {args.output}", file=sys.stderr)

    # also print unique CVE count
    unique = sorted({r["cve"] for r in rows})
    print(f"Unique CVEs fixed by FUTURE: {len(unique)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
