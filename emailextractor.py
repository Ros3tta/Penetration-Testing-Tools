#!/usr/bin/env python3
#
# Extraction of the Global Address List (GAL) on Exchange >=2013 servers via Outlook Web Access (OWA)
# By Pigeonburger, June 2021
# Modified: SSL verification disabled + warnings suppressed
#

import requests
import json
import argparse
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Argument parser
parser = argparse.ArgumentParser(
    description="Extract the Global Address List (GAL) on Exchange 2013+ servers via OWA"
)
parser.add_argument(
    "-i", "--host",
    dest="hostname",
    help="Hostname for the Exchange Server",
    metavar="HOSTNAME",
    type=str,
    required=True
)
parser.add_argument(
    "-u", "--username",
    dest="username",
    help="Username to log in",
    metavar="USERNAME",
    type=str,
    required=True
)
parser.add_argument(
    "-p", "--password",
    dest="password",
    help="Password to log in",
    metavar="PASSWORD",
    type=str,
    required=True
)
parser.add_argument(
    "-o", "--output-file",
    dest="output",
    help="File to output emails to",
    metavar="OUTPUT_FILE",
    type=str,
    default="global_address_list.txt"
)

args = parser.parse_args()

url = args.hostname
USERNAME = args.username
PASSWORD = args.password
OUTPUT = args.output

# Start session
s = requests.Session()
s.verify = False  # Disable SSL verification globally

print(f"Connecting to {url}/owa")

# Normalize URL
try:
    s.get(url + "/owa")
    URL = url
except requests.exceptions.MissingSchema:
    s.get("https://" + url + "/owa")
    URL = "https://" + url

# Required endpoints
AUTH_URL = URL + "/owa/auth.owa"
PEOPLE_FILTERS_URL = URL + "/owa/service.svc?action=GetPeopleFilters"
FIND_PEOPLE_URL = URL + "/owa/service.svc?action=FindPeople"

# Login
login_data = {
    "username": USERNAME,
    "password": PASSWORD,
    "destination": URL,
    "flags": "4",
    "forcedownlevel": "0"
}

r = s.post(
    AUTH_URL,
    data=login_data,
    headers={
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) "
            "Gecko/20100101 Firefox/89.0"
        )
    }
)

# Extract Canary token
try:
    session_canary = s.cookies["X-OWA-CANARY"]
except KeyError:
    exit("\nInvalid login details. Login failed.")

print("\nLogin Successful!")
print("Canary key:", session_canary)

# Get address lists
r = s.post(
    PEOPLE_FILTERS_URL,
    headers={
        "Content-Type": "application/json",
        "X-OWA-CANARY": session_canary,
        "Action": "GetPeopleFilters"
    },
    data={}
).json()

# Find Global Address List ID
AddressListId = None
for entry in r:
    if entry.get("DisplayName") == "Default Global Address List":
        AddressListId = entry["FolderId"]["Id"]
        break

if not AddressListId:
    exit("Global Address List not found.")

print("Global List Address ID:", AddressListId)

# FindPeople request parameters
query = None
max_results = 99999

peopledata = {
    "__type": "FindPeopleJsonRequest:#Exchange",
    "Header": {
        "__type": "JsonRequestHeaders:#Exchange",
        "RequestServerVersion": "Exchange2013",
        "TimeZoneContext": {
            "__type": "TimeZoneContext:#Exchange",
            "TimeZoneDefinition": {
                "__type": "TimeZoneDefinitionType:#Exchange",
                "Id": "AUS Eastern Standard Time"
            }
        }
    },
    "Body": {
        "__type": "FindPeopleRequest:#Exchange",
        "IndexedPageItemView": {
            "__type": "IndexedPageView:#Exchange",
            "BasePoint": "Beginning",
            "Offset": 0,
            "MaxEntriesReturned": max_results
        },
        "QueryString": query,
        "ParentFolderId": {
            "__type": "TargetFolderId:#Exchange",
            "BaseFolderId": {
                "__type": "AddressListId:#Exchange",
                "Id": AddressListId
            }
        },
        "PersonaShape": {
            "__type": "PersonaResponseShape:#Exchange",
            "BaseShape": "Default"
        },
        "ShouldResolveOneOffEmailAddress": False
    }
}

# Execute FindPeople
r = s.post(
    FIND_PEOPLE_URL,
    headers={
        "Content-Type": "application/json",
        "X-OWA-CANARY": session_canary,
        "Action": "FindPeople"
    },
    data=json.dumps(peopledata)
).json()

# Parse and write emails
userlist = r["Body"]["ResultSet"]

with open(OUTPUT, "a+") as outputfile:
    for user in userlist:
        email = user["EmailAddresses"][0]["EmailAddress"]
        outputfile.write(email + "\n")
        print(email)

print(f"\nFetched {len(userlist)} emails")
print("Emails written to", OUTPUT)
