import os
import jsonlines
from arango import ArangoClient
from arango.exceptions import DocumentInsertError



# define the prefix mapping for _from and _to values
prefix_mapping = {
    'campaign': 'campaign',
    'intrusion-set': 'adversary',
    'x-mitre-data-component': 'datacomponent',
    'attack-pattern': 'technique',
    'course-of-action': 'mitigation',
    'malware': 'software',
    'tool': 'software'
}


# create an ArangoDB client
client = ArangoClient(hosts='http://localhost:8529')

# connect to the database
db = client.db('[Database Name]', username='[Database Username]', password='[Database Password]')

# loop through all .jsonl files in the db directory and import them into the database (arangodb) as collections
# the collection should be named after the directory the file is in

def importc():
    for root, dirs, files in os.walk("db"):
        for file in files:
            if file.endswith(".jsonl"):
                with jsonlines.open(os.path.join(root, file), mode='r') as reader:
                    data = [obj for obj in reader]
                    # get the last directory in the root path as the collection name
                    collection = os.path.basename(root)
                    if not db.has_collection(collection):
                        db.create_collection(collection)
                    try:
                        db.collection(collection).import_bulk(data, on_duplicate='update')
                    except DocumentInsertError as e:
                        print(f"Error inserting documents into collection {collection}: {e}: {data}")
 

def importe():
    for root, dirs, files in os.walk("edge"):
        for file in files:
            if file.endswith(".jsonl"):
                with jsonlines.open(os.path.join(root, file), mode='r') as reader:
                    data = [obj for obj in reader]
                    # get the last directory in the root path as the collection name
                    collection = os.path.basename(root)
                    if not db.has_collection(collection):
                        db.create_collection(collection, edge=True)
                    try:
                        db.collection(collection).import_bulk(data, on_duplicate='update')
                    except DocumentInsertError as e:
                        print(f"Error inserting documents into collection {collection}: {e}: {data}")


importc()
importe()

