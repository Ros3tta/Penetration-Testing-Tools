#!/usr/bin/env python3
"""
Extract Global Address List (GAL) from Exchange 2013+ via OWA
Original: pigeonburger (2021)
Improved: SSL handling, robustness, hygiene
"""

import argparse
import json
import sys
import requests
import urllib3
from urllib.parse import urlparse

# ----------------------------
# SSL warning suppression
# ----------------------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----------------------------
# Argument parsing
# ----------------------------
parser = argparse.ArgumentParser(
    description="Extract the Global Address List (GAL) from Exchange via OWA"
)

parser.add_argument("-i", "--host", required=True, help="Exchange hostname or URL")
parser.add_argument("-u", "--username", required=True, help="Username")
parser.add_argument("-p", "--password", required=True, help="Password")
parser.add_argument(
    "-o",
    "--output-file",
    default="global_address_list.txt",
    help="Output file (default: global_address_list.txt)",
)

args = parser.parse_args()

# ----------------------------
# URL normalization
# ----------------------------
host = args.host.strip()

if not host.startswith(("http://", "https://")):
    host = f"https://{host}"

parsed = urlparse(host)
BASE_URL = f"{parsed.scheme}://{parsed.netloc}"

# ----------------------------
# Requests session
# ----------------------------
session = requests.Session()
session.verify = False  # <-- SSL fix
session.headers.update(
    {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) "
            "Gecko/20100101 Firefox/109.0"
        )
    }
)

print(f"[+] Connecting to {BASE_URL}/owa")

# ----------------------------
# Initial OWA request
# ----------------------------
try:
    session.get(f"{BASE_URL}/owa", timeout=10)
except requests.RequestException as e:
    sys.exit(f"[-] Failed to reach OWA: {e}")

# ----------------------------
# Auth
# ----------------------------
AUTH_URL = f"{BASE_URL}/owa/auth.owa"
PEOPLE_FILTERS_URL = f"{BASE_URL}/owa/service.svc?action=GetPeopleFilters"
FIND_PEOPLE_URL = f"{BASE_URL}/owa/service.svc?action=FindPeople"

login_data = {
    "username": args.username,
    "password": args.password,
    "destination": BASE_URL,
    "flags": "4",
    "forcedownlevel": "0",
}

session.post(AUTH_URL, data=login_data)

# ----------------------------
# Canary extraction
# ----------------------------
session_canary = session.cookies.get("X-OWA-CANARY")
if not session_canary:
    sys.exit("[-] Login failed (no X-OWA-CANARY cookie)")

print(f"[+] Login successful")
print(f"[+] Canary: {session_canary}")

# ----------------------------
# Get Address Lists
# ----------------------------
headers = {
    "Content-Type": "application/json",
    "X-OWA-CANARY": session_canary,
    "Action": "GetPeopleFilters",
}

try:
    resp = session.post(
        PEOPLE_FILTERS_URL, headers=headers, json={}, timeout=15
    ).json()
except Exception as e:
    sys.exit(f"[-] Failed to retrieve address lists: {e}")

address_list_id = None
for entry in resp:
    if entry.get("DisplayName") == "Default Global Address List":
        address_list_id = entry["FolderId"]["Id"]
        break

if not address_list_id:
    sys.exit("[-] Global Address List not found")

print(f"[+] GAL ID: {address_list_id}")

# ----------------------------
# FindPeople payload
# ----------------------------
people_data = {
    "__type": "FindPeopleJsonRequest:#Exchange",
    "Header": {
        "__type": "JsonRequestHeaders:#Exchange",
        "RequestServerVersion": "Exchange2013",
    },
    "Body": {
        "__type": "FindPeopleRequest:#Exchange",
        "IndexedPageItemView": {
            "__type": "IndexedPageView:#Exchange",
            "BasePoint": "Beginning",
            "Offset": 0,
            "MaxEntriesReturned": 100000,
        },
        "QueryString": None,
        "ParentFolderId": {
            "__type": "TargetFolderId:#Exchange",
            "BaseFolderId": {
                "__type": "AddressListId:#Exchange",
                "Id": address_list_id,
            },
        },
        "PersonaShape": {
            "__type": "PersonaResponseShape:#Exchange",
            "BaseShape": "Default",
        },
        "ShouldResolveOneOffEmailAddress": False,
    },
}

# ----------------------------
# Fetch users
# ----------------------------
headers["Action"] = "FindPeople"

try:
    resp = session.post(
        FIND_PEOPLE_URL,
        headers=headers,
        data=json.dumps(people_data),
        timeout=30,
    ).json()
except Exception as e:
    sys.exit(f"[-] FindPeople request failed: {e}")

users = resp.get("Body", {}).get("ResultSet", [])
if not users:
    sys.exit("[-] No users returned")

# ----------------------------
# Output
# ----------------------------
emails = set()

for user in users:
    try:
        email = user["EmailAddresses"][0]["EmailAddress"]
        emails.add(email)
    except (KeyError, IndexError):
        continue

with open(args.output_file, "w") as f:
    for email in sorted(emails):
        print(email)
        f.write(email + "\n")

print(f"\n[+] Fetched {len(emails)} unique emails")
print(f"[+] Written to {args.output_file}")
