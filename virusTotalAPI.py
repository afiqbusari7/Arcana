import os
from pprint import pprint
from base64 import urlsafe_b64encode
from virustotal_python import Virustotal

API_KEY = "f6957b4ceada8ef6fb49a7c84fc143f8cb6f5595038f0cace0798ffb674b040c"

vtotal = Virustotal(API_KEY=API_KEY, API_VERSION="v3")


# Function to parse virus total results in Arcana
def parseResults(resp):
    results = resp.data["attributes"]["last_analysis_results"]
    count = {
        "undetected": 0,
        "malicious": 0
    }
    for key, value in results.items():
        if value["category"] == "malicious":
            count["malicious"] += 1
        else:
            count["undetected"] += 1
    return count


# Function to check virus total for hash of uploaded file
def testHash(FILE_ID):
    try:
        resp = vtotal.request(f"files/{FILE_ID}")
    except:
        return {"malicious": 0}  # If file have not been scanned before
    return parseResults(resp)


# Function to check virus total for suspicious URL
def testURL(url):
    try:
        # URL safe encode URL in base64 format
        # https://developers.virustotal.com/v3.0/reference#url
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
        # Obtain the analysis results for the URL using the url_id
        analysis_resp = vtotal.request(f"urls/{url_id}")
        return parseResults(analysis_resp)
    except Exception as err:
        print(f"An error occurred: {err}\nCatching and continuing with program.")
