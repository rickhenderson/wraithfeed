"""Regenerate validate/data/attack_techniques.json from MISP's mitre-attack-pattern galaxy.

The file is committed so a fresh clone validates technique ids without a MISP
instance. Run this after updating MISP's galaxies (needs MISP_URL / MISP_KEY):

    venv/bin/python scripts/update_attack_techniques.py

Every technique id the galaxy knows is kept with a status: "current",
"revoked" (superseded in a later ATT&CK release, e.g. T1562.001) or
"deprecated" (content merged elsewhere). Tactics (TAxxxx) are left out.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import date
from pathlib import Path

import requests
from dotenv import load_dotenv

OUT = Path(__file__).resolve().parent.parent / "validate/data/attack_techniques.json"
GALAXY_TYPE = "mitre-attack-pattern"
_VALUE_RE = re.compile(r"^(.*) - (T\d{4}(?:\.\d{3})?)$")


def _status(cluster: dict) -> str:
    if (cluster.get("description") or "").startswith("This object is deprecated"):
        return "deprecated"
    relations = {r.get("referenced_galaxy_cluster_type") for r in cluster.get("GalaxyClusterRelation", [])}
    return "revoked" if "revoked-by" in relations else "current"


def main() -> int:
    load_dotenv()
    url, key = os.environ.get("MISP_URL"), os.environ.get("MISP_KEY")
    if not url or not key:
        print("MISP_URL and MISP_KEY must be set", file=sys.stderr)
        return 1
    verify = os.environ.get("MISP_VERIFY_CERT", "true").strip().lower() not in ("false", "0", "no")
    headers = {"Authorization": key, "Accept": "application/json"}
    base = url.rstrip("/")

    galaxies = requests.get(f"{base}/galaxies/index", headers=headers, verify=verify, timeout=60)
    galaxies.raise_for_status()
    galaxy = next(g["Galaxy"] for g in galaxies.json() if g["Galaxy"]["type"] == GALAXY_TYPE)
    # restSearch (unlike /index) includes each cluster's relations, which is where "revoked-by" lives.
    resp = requests.post(
        f"{base}/galaxy_clusters/restSearch",
        json={"galaxy_id": int(galaxy["id"]), "limit": 5000, "page": 1},
        headers={**headers, "Content-Type": "application/json"},
        verify=verify,
        timeout=600,
    )
    resp.raise_for_status()

    techniques: dict[str, dict] = {}
    for item in resp.json()["response"]:
        c = item["GalaxyCluster"]
        m = _VALUE_RE.match(c["value"])
        if m:
            techniques[m.group(2)] = {"name": m.group(1), "status": _status(c)}
    if sum(t["status"] == "current" for t in techniques.values()) < 500:
        print(f"too few current techniques ({len(techniques)} total); refusing to overwrite {OUT}", file=sys.stderr)
        return 1

    OUT.write_text(json.dumps(
        {
            "source": f"MISP galaxy {GALAXY_TYPE} (MITRE ATT&CK), galaxy version {galaxy.get('version')}",
            "retrieved": date.today().isoformat(),
            "techniques": dict(sorted(techniques.items())),
        },
        indent=1,
    ) + "\n")
    print(f"wrote {len(techniques)} techniques to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
