#!/usr/bin/env python3
"""Regenerate ForgeProxy's built-in CWE catalogue from MITRE's CWE REST API.

    python3 tools/update_cwe.py                     # ask https://cwe-api.mitre.org/api/v1/
    python3 tools/update_cwe.py --from-dir <dir>    # or read the API's JSON from files

Writes assets/cwe/catalog.json, the file the app embeds. Only the CWEs the scanner can
actually report are kept -- the numbers in the IssueDef constants of src/scan.rs -- each with
MITRE's official name, description and potential mitigations. Add a check with a new CWE,
run this again, and its explanation comes with it; the test suite fails until you do.

--from-dir reads a folder laid out like the json_repo folder of MITRE's REST API repository
(https://github.com/CWE-CAPEC/REST-API-wg): cwev.json for the version and W/<id>.json for
each weakness, the same JSON the API returns. Useful where the API cannot be reached.

Standard library only, so it runs anywhere Python 3.8+ does.
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

API = "https://cwe-api.mitre.org/api/v1"
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "cwe" / "catalog.json"
SCAN_RS = ROOT / "src" / "scan.rs"
# enough to say what to do; the full list is one click away on MITRE's page
MAX_MITIGATIONS = 4


def scanner_cwes():
    """The CWE numbers of every `pub const NAME: IssueDef = (89, ...)` in src/scan.rs."""
    found = {int(n) for n in re.findall(r"^pub const \w+: IssueDef = \((\d+),", SCAN_RS.read_text(), re.M)}
    if not found:
        sys.exit(f"no IssueDef constants found in {SCAN_RS}")
    return found


def get_json(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "ForgeProxy-update_cwe"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            sys.exit(f"{url}: 404 -- one of the numbers in src/scan.rs is not a current CWE weakness")
        raise
    except urllib.error.URLError as e:
        sys.exit(f"could not reach {API} ({e.reason}); try --from-dir with a copy of MITRE's json_repo")


def from_api(ids):
    version = get_json(f"{API}/cwe/version")
    weaknesses = get_json(f"{API}/cwe/weakness/{','.join(str(i) for i in sorted(ids))}")["Weaknesses"]
    return version, weaknesses


def from_dir(folder, ids):
    folder = Path(folder)
    version = json.loads((folder / "cwev.json").read_text(encoding="utf-8"))
    weaknesses = []
    for i in sorted(ids):
        path = folder / "W" / f"{i}.json"
        if not path.exists():
            sys.exit(f"{path} is missing -- CWE-{i} is not a current weakness in that copy")
        data = json.loads(path.read_text(encoding="utf-8"))
        # a file may hold the bare entry or the API's {"Weaknesses": [...]} wrapper
        weaknesses.extend(data["Weaknesses"] if "Weaknesses" in data else [data])
    return version, weaknesses


def clean(text):
    """MITRE's text without its bibliography markers ([REF-1482]) and with whitespace collapsed.

    Since CWE 4.21 the API also leaves the roles of the entry's alternate terms at the end of
    some descriptions -- "(Roles: Attack-Focused, Common-Name)" -- which mean nothing on their own.
    """
    text = re.sub(r"\s*\[REF-\d+\]", "", text or "")
    text = re.sub(r"\s*\(Roles:[^)]*\)", "", text)
    return re.sub(r"\s+", " ", text).strip()


def common_name(w):
    """The name people actually use ("SQL Injection", "SSRF"), from the alternate terms MITRE
    marks Common-Name. Releases before 4.21 put it in the title instead and have none here."""
    for t in w.get("AlternateTerms") or []:
        roles = t.get("Roles") or []
        if isinstance(roles, str):
            roles = [r.strip() for r in roles.split(",")]
        if "Common-Name" in roles and "Discouraged" not in roles and t.get("Term"):
            return clean(t["Term"])
    return None


def entry(w):
    mitigations = []
    for m in w.get("PotentialMitigations") or []:
        desc = clean(m.get("Description"))
        if desc and desc not in mitigations:
            mitigations.append(desc)
    name = clean(w.get("Name"))
    common = common_name(w)
    if common and common.lower() not in name.lower():
        name = f"{name} ('{common}')"
    return {
        "id": int(w["ID"]),
        "name": name,
        "description": clean(w.get("Description")),
        "mitigations": mitigations[:MAX_MITIGATIONS],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--from-dir", help="read the API's JSON from this folder instead of the network")
    args = ap.parse_args()

    ids = scanner_cwes()
    version, weaknesses = from_dir(args.from_dir, ids) if args.from_dir else from_api(ids)
    entries = sorted((entry(w) for w in weaknesses if w.get("Status") != "Deprecated"), key=lambda e: e["id"])
    missing = ids - {e["id"] for e in entries}
    if missing:
        sys.exit(f"MITRE has no current weakness for CWE {sorted(missing)}; check the numbers in src/scan.rs")

    head = {
        "version": str(version.get("ContentVersion", "unknown")),
        "date": str(version.get("ContentDate", "")).strip(),
        "notice": "Common Weakness Enumeration (CWE) content is Copyright (c) The MITRE Corporation, "
                  "used under the CWE Terms of Use (assets/cwe/LICENSE). CWE is a trademark of The MITRE Corporation.",
    }
    # one weakness per line keeps diffs readable when MITRE publishes a new release
    lines = ",\n".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) for e in entries)
    body = json.dumps(head, ensure_ascii=False)[:-1] + ',"weaknesses":[\n' + lines + "\n]}\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(body, encoding="utf-8")
    print(f"CWE {head['version']} ({head['date']}): {len(entries)} weaknesses -> {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
