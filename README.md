# CROGL-Github-Advisory-Database

This script pulls public security advisories from GitHub's Advisory Database using their GraphQL API and cross-references them with the CISA Known Exploited Vulnerabilities (KEV) catalog. It outputs the data into categorized CSV files by severity level and zips each one for easier sharing or archiving.

## What It Does

- Fetches GitHub advisories (GHSA) in batches using GitHub's GraphQL API.
- Fetches CISA KEV catalog from the public JSON feed.
- Compares advisories against the KEV catalog using CVE identifiers.
- Outputs CSV files for each severity level:
  - `low.csv`
  - `moderate.csv`
  - `high.csv`
  - `critical.csv`
- Adds a column for whether a vulnerability is in the KEV list.
- Zips each CSV file into a matching `.zip` file.

## Output

All files are saved to the `advisory_exports` directory:

advisory_exports/
├── low.csv
├── moderate.csv
├── high.csv
├── critical.csv
├── low.zip
├── moderate.zip
├── high.zip
├── critical.zip

Each CSV includes the following columns:

- GHSA_ID
- CVE
- Severity
- Summary
- Published Date
- Updated Date
- KEV (1 if present in CISA KEV, empty if not)
- References (comma-separated URLs)

## Requirements

- Python 3.6+
- `requests` module

Install dependencies if needed:

pip install requests

Usage

Edit the script and replace the TOKEN variable at the top with your own GitHub Personal Access Token. The token must have access to the GitHub GraphQL API.

Then simply run:

python script.py

When complete, it will print:

Done. Files saved to advisory_exports

Pagination is handled, so the script will keep requesting until all advisories are pulled.

No rate limiting logic is built in, so if your token has restrictions, you may need to wait or add delays.

The KEV match is done via CVE identifier only (case-insensitive).
