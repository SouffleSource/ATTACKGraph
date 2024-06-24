# ThreatAnalysis - MITRE ATT&CK in a Graph Database 

This repository contains a set of scripts to fetch, parse, and import MITRE ATT&CK data into a multi-modal graph database (ArangoDB).

## Overview
- `getData.py`: Fetches the raw MITRE ATT&CK data.
- `parseStix.py`: Parses the fetched data, structures it, and prepares it for import.
- `importArango.py`: Imports the structured data into an ArangoDB database.

## Prerequisites

- Python 3.x
- requests, json, jsonlines, and arango libraries
- An ArangoDB instance running

## Usage

### Step 1: Fetch MITRE ATT&CK Data
The script `getData.py` fetches the latest MITRE ATT&CK data from the MITRE ATT&CK repository.

### Step 2: Parse and Structure the Data
The script `parseStix.py` takes the fetched raw data, parses it, restructures it, and prepares it for import.

### Step 3: Import Data into ArangoDB
The script `importArango.py` imports the structured data into an ArangoDB database. Ensure your ArangoDB instance is running and properly configured.

Before running the script, modify the database configuration in `importArango.py`. 

```python
db = client.db('[Database Name]', username='[Database Username]', password='[Database Password]')
```
> [!WARNING]
> Hardcoding secrets is very high risk. Follow [secrets management best practices](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).

Then run the script:
```
python importArango.py
```
### Step 4: Configure a Graph
Once the script has imported the data, configure relationships to form a graph. 

The example below is a graph that can be queried to visualise relationships from Actors, Campaigns and Tools to their associated Techniques and Tools

![Screenshot of a graph settings](/assets/graphsettings.png)

### Step 5: Query the Graph
Once the graph has been created, you can visualise relationships and query the data within it. 

The example below finds all Techniques and Tools related to an Actor, Campaign or Tool and returns a count to gain a better understanding of their prevelance
```sql
FOR v IN ANY "intrusion-set/APT41" 
  GRAPH "adversarytotechnique" 
  LET inboundCount = LENGTH(FOR e IN INBOUND v._id GRAPH "adversarytotechnique" RETURN e) 
  RETURN { "node_id": v._id, "count": inboundCount }
```
## Script Details

To convert raw MITRE ATT&CK STIX data into a format suitable for a multi-modal database like ArangoDB, we follow a multi-step process involving data fetching, parsing, structuring, and importing.

First, the `getData.py` script fetches the latest MITRE ATT&CK data from the MITRE repository using an HTTP GET request. The fetched JSON data is then parsed into a Python dictionary for further processing.

Next, the `parseStix.py` script categorises and transforms this raw data. The script ensures the necessary folder structure is in place, creating directories for various entity types (e.g., `db/intrusion-set`, `db/malware`) and relationships (e.g., `edge/uses`, `edge/mitigates`). It then extracts and transforms entities like `intrusion-set`, `malware`, and `tool`, converting them into JSON Lines format (`.jsonl`) and storing them in their respective directories. Relationships such as `uses` and `mitigates` are similarly processed and stored in edge directories. The script also renames and restructures key-value pairs to avoid naming conflicts in ArangoDB.

Finally, the `importArango.py` script imports the structured data into ArangoDB. It establishes a connection to the ArangoDB instance, then iterates through the `db` directory to identify all entity `.jsonl` files and imports them into their corresponding collections in the database, creating collections as needed and updating existing documents on conflicts. The script also processes edge collections by iterating through the `edge` directory and importing relationship data into the relevant edge collections, ensuring the relationship structure is faithfully recreated in the database.

## Why?

Storing MITRE ATT&CK data in a graph database offers several significant benefits for threat intelligence analysis:

1. **Enhanced Data Relationships**: A graph database naturally models relationships, which is crucial for understanding connections between threat actors, techniques, tools, and mitigations. This promotes a more intuitive exploration of how various elements interact within the threat landscape.

2. **Improved Query Performance**: Graph databases can efficiently traverse relationships between nodes (entities) without complex joins, enabling faster and more flexible querying of interconnected data sets. This is particularly useful for identifying patterns and correlations in threat data.

3. **Visual Analysis**: Graph databases support visual representation of data, which can help analysts easily see and interpret relationships and flow of attack chains. This visual insight aids in quickly identifying potential attack paths and interdependencies.

4. **Contextual Insights**: By leveraging the relationships between different elements (e.g., a specific malware tied to certain techniques used by an adversary), analysts can gain deeper contextual insights into threats, leading to more informed decision-making and stronger defenses.

5. **Dynamic and Adaptive Threat Models**: As new data is ingested, graph databases can seamlessly integrate and establish relationships with existing data, ensuring that the threat model is continuously up-to-date with the latest intelligence.

6. **Complex Network Analysis**: Complex queries such as finding the central nodes (most used techniques or common threat actors) or identifying shortest paths (quickest way an attack could move through an organisation) are simplified and made more efficient with graph databases.

### Example

You know your organisation has poor detection and/or prevention of Cobal Strike from recent incidets and you want to know other tools, malware, and adversaries that share a similar set of techniques. By showing relationships two hops deep into the STIX data we can find the most relevant threats

![Screenshot of a two hop deep query in a MITRE ATT&CK graph using the source as Cobal Strike](/assets/cobalstriketwohop.png)

