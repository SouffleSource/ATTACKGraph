import requests
import json 

# Get the stix data from the MITRE ATT&CK repository
def fetchStix():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    response = requests.get(url, verify=False)
    if response.status_code == 200:
        mitredata = json.loads(response.text)
    return mitredata

if __name__ == "__main__":
    fetchStix()


