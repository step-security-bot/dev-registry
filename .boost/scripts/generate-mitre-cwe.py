"""
Usage:
  python3 .boost/scripts/generate-mitre-cwe.py > scanners/boostsecurityio/mitre-cwe/rules.yaml
  python3 .boost/scripts/normalize-mapping.py
"""

from urllib.request import urlretrieve
import os
import zipfile
import yaml
import defusedxml.ElementTree as ET
from collections import defaultdict
import re
import json
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
CWE_ZIP_FILE = "cwec_latest.xml.zip"
XMLNS = "http://cwe.mitre.org/cwe-6"
TOP_10_2021_CWE_ID = "1344"
DEFAULT_GROUP = "top10-insecure-design"

extra_cwe_categories = {"stored-secrets": {"200", "798"}}
hardened_denylist = {"1004", "400", "601", "704", "1275", "706", "693", "1333"}
baseline_list = {
    "20",
    "22",
    "74",
    "78",
    "79",
    "89",
    "90",
    "94",
    "95",
    "96",
    "116",
    "287",
    "295",
    "311",
    "319",
    "320",
    "326",
    "327",
    "328",
    "352",
    "489",
    "502",
    "522",
    "611",
    "798",
    "918",
    "943",
}

group_by_category = {
    "1345": "top10-broken-access-control",
    "1346": "top10-crypto-failures",
    "1347": "top10-injection",
    "1348": "top10-insecure-design",
    "1349": "top10-security-misconfiguration",
    "1352": "top10-vulnerable-components",
    "1353": "top10-id-authn-failures",
    "1354": "top10-software-data-integrity-failures",
    "1355": "top10-security-logging-monitoring-failures",
    "1356": "top10-server-side-request-forgery",
}

group_overrides = {
    "710": "top10-insecure-design",
    "664": "top10-insecure-design",
    "691": "top10-insecure-design",
    "682": "top10-insecure-design",
    "435": "top10-insecure-design",
    "707": "top10-injection",
    "703": "top10-insecure-design",
    "697": "top10-insecure-design",
    "1038": "top10-insecure-design",
}


class CWE:
    def __init__(self):
        self.weaknesses = {}
        self.boost_categories = set()

    def call(self):
        self.download_zip()
        self.parse_xml()
        self.parse_boost_categories()
        self.parse_weaknesses()
        self.assign_boost_groups()
        self.assign_top_10_groups()
        self.assign_cwe_groups()
        self.propagate_groups()
        self.build_rules_db()

    def download_zip(self):
        if not os.path.exists(CWE_ZIP_FILE):
            urlretrieve(
                f"https://cwe.mitre.org/data/xml/{CWE_ZIP_FILE}",
                SCRIPT_DIR / CWE_ZIP_FILE,
            )

    def parse_xml(self):
        archive = zipfile.ZipFile(SCRIPT_DIR / CWE_ZIP_FILE, "r")
        with archive.open(f"cwec_v4.11.xml") as f:
            self.xml = ET.parse(f)

    def findall(self, query, root=None):
        root = root or self.xml
        return root.findall(query, namespaces={"": XMLNS})

    def find(self, query, root=None):
        root = root or self.xml
        return root.find(query, namespaces={"": XMLNS})

    def parse_boost_categories(self):
        with open(SCRIPT_DIR / "categories.json") as f:
            categories = json.load(f)

        for category in categories:
            self.boost_categories.add(category["name"])

    def assign_top_10_groups(self):
        member_cwes = [
            member.get("CWE_ID")
            for member in self.findall(
                f'./Views/View[@ID="{TOP_10_2021_CWE_ID}"]/Members/Has_Member'
            )
        ]

        categories = [
            self.find(f'./Categories/Category[@ID="{cwe}"]') for cwe in member_cwes
        ]

        for cat in categories:
            assert cat.get("ID") in group_by_category

            for member in self.findall(f"./Relationships/Has_Member", cat):
                if member.get("CWE_ID") not in self.weaknesses:
                    continue

                self.weaknesses[member.get("CWE_ID")]["group"] = group_by_category[
                    cat.get("ID")
                ]

    def parse_weaknesses(self):
        for cwe in self.findall(f".//Weakness"):
            if cwe.get("Status") == "Deprecated":
                continue

            related_cwes = self.findall(f".//Related_Weakness", cwe)
            description = self.find(f"./Description", cwe).text
            weakness = {
                "name": cwe.get("Name"),
                "description": description,
                "parents_cwe": set(),
            }

            for related_cwe in related_cwes:
                nature = related_cwe.get("Nature")
                ordinal = related_cwe.get("Ordinal")
                view = related_cwe.get("View_ID")

                if view == "1000" and nature == "ChildOf" and ordinal == "Primary":
                    weakness["parents_cwe"].add(related_cwe.get("CWE_ID"))

            self.weaknesses[cwe.get("ID")] = weakness

    def assign_boost_groups(self):
        cwe_groups = {}

        with open(SCRIPT_DIR / "groups.yaml") as f:
            groups = yaml.safe_load(f).get("groups", [])

        for group_name, group in groups.items():
            for cat in group.get("categories", []):
                _, cwe_id = cat.split("-")

                cwe_groups[cwe_id] = group_name

        for cwe, group in cwe_groups.items():
            if cwe not in self.weaknesses:
                # not a weakness, probably a category
                continue

            self.weaknesses[cwe]["group"] = group

    def propagate_groups(self):
        for cwe, weakness in self.weaknesses.items():
            if "group" in weakness:
                continue

            for _, pcwe_id in sorted(self.cwe_parents(cwe), reverse=True):
                pcwe = self.weaknesses[pcwe_id]

                if "group" in pcwe:
                    weakness["group"] = pcwe["group"]
                    break

    def assign_cwe_groups(self):
        for cwe, group in group_overrides.items():
            self.weaknesses[cwe]["group"] = group

    def build_rules_db(self):
        rules = {}

        for cwe, weakness in self.weaknesses.items():
            categories = ["ALL"]
            name = f"CWE-{cwe}"
            description = re.sub("\s+", " ", weakness["description"])

            if f"cwe-{cwe}" in self.boost_categories:
                categories.append(f"cwe-{cwe}")

            for category, cwes in extra_cwe_categories.items():
                if cwe in cwes:
                    categories.append(category)

            if cwe in baseline_list:
                categories.append("boost-baseline")

            if cwe not in hardened_denylist:
                categories.append("boost-hardened")

            rules[name] = {
                "name": name,
                "pretty_name": f"{name}: {weakness['name']}",
                "description": description,
                "categories": categories,
                "group": weakness.get("group", DEFAULT_GROUP),
                "ref": f"https://cwe.mitre.org/data/definitions/{cwe}.html",
            }

        print(yaml.dump({"rules": rules}))

    def cwe_parents(self, cwe, n=5):
        weakness = self.weaknesses[cwe]
        parents = weakness["parents_cwe"]

        if n == 0:
            return {}

        if len(weakness["parents_cwe"]) == 0:
            return {}

        parents = {(n, pcwe) for pcwe in weakness["parents_cwe"]}

        return parents.union(*[self.cwe_parents(pcwe, n - 1) for (_, pcwe) in parents])


if __name__ == "__main__":
    CWE().call()
