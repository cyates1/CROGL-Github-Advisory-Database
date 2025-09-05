import requests
import csv
import os
import zipfile

# basic config
TOKEN = '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'
HEADERS = {"Authorization": "Bearer " + TOKEN}
GRAPHQL_URL = 'https://api.github.com/graphql'
CISA_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
OUTPUT_DIR = 'advisory_exports'

# GraphQL query to get advisories
GRAPHQL_QUERY = """
query($cursor: String) {
  securityAdvisories(first: 100, after: $cursor) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      identifiers {
        type
        value
      }
      references {
        url
      }
    }
  }
}
"""

def get_cisa_kev():
    resp = requests.get(CISA_URL)
    kev_set = set()
    if resp.ok:
        data = resp.json()
        for item in data.get("vulnerabilities", []):
            kev_set.add(item.get("cveID", "").upper())
    return kev_set

def get_github_advisories():
    advisories = []
    cursor = None
    while True:
        payload = {"query": GRAPHQL_QUERY, "variables": {"cursor": cursor}}
        response = requests.post(GRAPHQL_URL, headers=HEADERS, json=payload)
        result = response.json()
        nodes = result["data"]["securityAdvisories"]["nodes"]
        advisories.extend(nodes)

        page = result["data"]["securityAdvisories"]["pageInfo"]
        if not page["hasNextPage"]:
            break
        cursor = page["endCursor"]
    return advisories

def extract_cve_id(advisory):
    for ident in advisory["identifiers"]:
        if ident["type"] == "CVE":
            return ident["value"]
    return ""

def write_csvs(advisories, kev_list):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    fields = ["GHSA_ID", "CVE", "SEVERITY", "SUMMARY", "PUBLISHED", "UPDATED", "KEV", "REFERENCES"]
    files = {}

    for level in ["LOW", "MODERATE", "HIGH", "CRITICAL"]:
        f = open(os.path.join(OUTPUT_DIR, f"{level.lower()}.csv"), "w", newline="", encoding="utf-8")
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        files[level] = (f, writer)

    for item in advisories:
        cve = extract_cve_id(item)
        kev = "1" if cve in kev_list else ""
        row = {
            "GHSA_ID": item["ghsaId"],
            "CVE": cve,
            "SEVERITY": item["severity"],
            "SUMMARY": item["summary"],
            "PUBLISHED": item["publishedAt"],
            "UPDATED": item["updatedAt"],
            "KEV": kev,
            "REFERENCES": ", ".join(ref["url"] for ref in item["references"])
        }
        if item["severity"] in files:
            files[item["severity"]][1].writerow(row)

    for f, _ in files.values():
        f.close()

def zip_csvs():
    for level in ["low", "moderate", "high", "critical"]:
        zip_path = os.path.join(OUTPUT_DIR, f"{level}.zip")
        csv_path = os.path.join(OUTPUT_DIR, f"{level}.csv")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(csv_path, arcname=f"{level}.csv")

def main():
    kev = get_cisa_kev()
    advisories = get_github_advisories()
    write_csvs(advisories, kev)
    zip_csvs()
    print("Done. Files saved to", OUTPUT_DIR)

if __name__ == "__main__":
    main()
