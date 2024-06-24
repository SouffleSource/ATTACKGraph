import os
import re
import json
import jsonlines
import shutil
from getData import fetchStix

mitre_dict = fetchStix()

if os.path.exists('edge'):
    shutil.rmtree('edge')
if os.path.exists('db'):
    shutil.rmtree('db')

def checkFolderStructure():
    dirs = ['db/intrusion-set', 'db/malware', 'db/tool', 'db/attack-pattern', 'db/x-mitre-data-source', 'db/course-of-action', 'db/campaign', 'db/tactic', 'db/x-mitre-data-component', 'edge/attributedto', 'edge/detects', 'edge/mitigates', 'edge/subtechniqueof', 'edge/uses']
    for folder in dirs:
        os.makedirs(folder, exist_ok=True)

def idtonameDict():
    id_to_name = {}
    for obj in mitre_dict['objects']:
        if 'id' in obj and 'name' in obj:
            name = obj['name']
            # Remove spaces from the name
            name = name.replace(' ', '')
            # Replace illegal characters with an empty string
            name = re.sub(r'[_\-\:\.@\(\)\+,=;\$\!\*\'%\/]', '', name)
            id_to_name[obj['id']] = name
    return id_to_name

def edgeidtoName(id_to_name):
    edge_dir = 'edge'
    for subdir, dirs, files in os.walk(edge_dir):
        for file in files:
            if file.endswith('.jsonl'):
                file_path = os.path.join(subdir, file)
                new_file_path = file_path + '.new'
                with jsonlines.open(file_path, 'r') as reader, jsonlines.open(new_file_path, 'w') as writer:
                    for data in reader:
                        from_id = data.get('_from')
                        if from_id in id_to_name:
                            from_id_prefix = from_id.split('--')[0]
                            from_id_name = id_to_name[from_id]
                            data['_from'] = from_id_prefix + '/' + from_id_name
                        to_id = data.get('_to')
                        if to_id in id_to_name:
                            to_id_prefix = to_id.split('--')[0]
                            to_id_name = id_to_name[to_id]
                            data['_to'] = to_id_prefix + '/' + to_id_name
                        writer.write(data)
                os.remove(file_path)
                os.rename(new_file_path, file_path)

def convertToJsonLines():
    for root, dirs, files in os.walk("db"):
        for file in files:
            if file.endswith(".json"):
                with open(os.path.join(root, file), "r") as f:
                    data = json.load(f)
                    with jsonlines.open(os.path.join(root, file.replace(".json", ".jsonl")), mode='w') as writer:
                        writer.write(data)
                os.remove(os.path.join(root, file))

def convertToJsonLinesEdge():
    for root, dirs, files in os.walk("edge"):
        for file in files:
            if file.endswith(".json"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r") as f:
                        data = json.load(f)
                    jsonl_path = os.path.join(root, file.replace(".json", ".jsonl"))
                    with jsonlines.open(jsonl_path, mode='w') as writer:
                        writer.write(data)
                    os.remove(file_path)
                except OSError as e:
                    print(f"Error converting {file_path}: {e}")


def renameandmoveKey(obj):
    new_obj = {}

    if 'name' in obj:
        new_obj['_key'] = obj['name']

    if 'id' in obj:
        new_obj['mitreid'] = obj['id']
    new_obj['_key'] = new_obj['_key'].replace(' ', '')
    new_obj['_key'] = re.sub(r'[_\-\:\.@\(\)\+,=;\$\!\*\'%\/]', '', new_obj['_key'])

    for key, value in obj.items():
        if key not in ['name', '_key', 'id', 'mitreid']:
            new_obj[key] = value

    return new_obj


def renameandmoveKeyEdge(obj):
    if 'source_ref' in obj and 'target_ref' in obj:
        obj['_from'] = obj.pop('source_ref')
        obj['_to'] = obj.pop('target_ref')
    if 'id' in obj:
        obj['_key'] = obj.pop('id')
    new_obj = {}
    for k, v in obj.items():
        if k in ['_key', '_from', '_to']:
            new_obj[k] = v
    for k, v in obj.items():
        if k not in ['_key', '_from', '_to']:
            new_obj[k] = v
    obj.clear()
    obj.update(new_obj)


def fetchAdversary():
    for obj in mitre_dict['objects']:
        if obj['type'] == "intrusion-set":
            filename = obj.get('name')
            if filename:
                filename = filename.replace(' ', '-')
                filename = filename.replace('/', '-')
                obj = renameandmoveKey(obj)
                with open(f'db/intrusion-set/{filename}.json', 'w') as outfile:
                    json.dump(obj, outfile, indent=4)

def fetchMalware():
    for obj in mitre_dict['objects']:
        if obj['type'] == "malware":
            filename = obj.get('name')
            if filename:
                filename = filename.replace(' ', '-')
                filename = filename.replace('/', '-')
                obj = renameandmoveKey(obj)
                with open(f'db/malware/{filename}.json', 'w') as outfile:
                    json.dump(obj, outfile, indent=4)

def fetchTool():
    for obj in mitre_dict['objects']:
        if obj['type'] == "tool":
            filename = obj.get('name')
            if filename:
                filename = filename.replace(' ', '-')
                filename = filename.replace('/', '-')
                obj = renameandmoveKey(obj)
                with open(f'db/tool/{filename}.json', 'w') as outfile:
                    json.dump(obj, outfile, indent=4)

def fetchTechnique():
    for obj in mitre_dict['objects']:
        if obj['type'] == "attack-pattern":
            filename = obj.get('name')
            if filename:
                filename = filename.replace(' ', '-')
                filename = filename.replace('/', '-')
                obj = renameandmoveKey(obj)
                with open(f'db/attack-pattern/{filename}.json', 'w') as outfile:
                    json.dump(obj, outfile, indent=4)

def fetchDataSource():
    for obj in mitre_dict['objects']:
        if obj['type'] == "x-mitre-data-source":
            filename = obj.get('name')
            if filename:
                filename = filename.replace(' ', '-')
                filename = filename.replace('/', '-')
                obj = renameandmoveKey(obj)
                with open(f'db/x-mitre-data-source/{filename}.json', 'w') as outfile:
                    json.dump(obj, outfile, indent=4)

def fetchMitigation():
    for obj in mitre_dict['objects']:
        if obj['type'] == "course-of-action":
            filename = obj.get('name')
            if filename:
                filename = filename.replace(' ', '-')
                filename = filename.replace('/', '-')
                obj = renameandmoveKey(obj)
                with open(f'db/course-of-action/{filename}.json', 'w') as outfile:
                    json.dump(obj, outfile, indent=4)

def fetchCampaign():
    for obj in mitre_dict['objects']:
        if obj['type'] == "campaign":
            filename = obj.get('name')
            if filename:
                filename = filename.replace(' ', '-')
                filename = filename.replace('/', '-')
                obj = renameandmoveKey(obj)
                with open(f'db/campaign/{filename}.json', 'w') as outfile:
                    json.dump(obj, outfile, indent=4)

def fetchTactic():
    for obj in mitre_dict['objects']:
        if obj['type'] == "x-mitre-tactic":
            filename = obj.get('name')
            if filename:
                filename = filename.replace(' ', '-')
                filename = filename.replace('/', '-')
                obj = renameandmoveKey(obj)
                with open(f'db/tactic/{filename}.json', 'w') as outfile:
                    json.dump(obj, outfile, indent=4)

def fetchDataComponent():
    for obj in mitre_dict['objects']:
        if obj['type'] == "x-mitre-data-component":
            filename = obj.get('name')
            if filename:
                filename = filename.replace(' ', '-')
                filename = filename.replace('/', '-')
                obj = renameandmoveKey(obj)
                with open(f'db/x-mitre-data-component/{filename}.json', 'w') as outfile:
                    json.dump(obj, outfile, indent=4)


def fetchMitigates():
    for obj in mitre_dict['objects']:
        if obj['type'] == "relationship" and obj['relationship_type'] == "mitigates":
            renameandmoveKeyEdge(obj)
            filename = f"mitigates_{obj['_key'][-12:]}"
            with open(f'edge/mitigates/{filename}.json', 'w') as outfile:
                json.dump(obj, outfile, indent=4)

def fetchUses():
    for obj in mitre_dict['objects']:
        if obj['type'] == "relationship" and obj['relationship_type'] == "uses":
            renameandmoveKeyEdge(obj)
            filename = f"uses_{obj['_key'][-12:]}"
            with open(f'edge/uses/{filename}.json', 'w') as outfile:
                json.dump(obj, outfile, indent=4)

def fetchSubtechniqueOf():
    for obj in mitre_dict['objects']:
        if obj['type'] == "relationship" and obj['relationship_type'] == "subtechnique-of":
            renameandmoveKeyEdge(obj)
            filename = f"subtechniqueof_{obj['_key'][-12:]}"
            with open(f'edge/subtechniqueof/{filename}.json', 'w') as outfile:
                json.dump(obj, outfile, indent=4)

def fetchDetects():
    for obj in mitre_dict['objects']:
        if obj['type'] == "relationship" and obj['relationship_type'] == "detects":
            renameandmoveKeyEdge(obj)
            filename = f"detects_{obj['_key'][-12:]}"
            with open(f'edge/detects/{filename}.json', 'w') as outfile:
                json.dump(obj, outfile, indent=4)

def fetchAttributedTo():
    for obj in mitre_dict['objects']:
        if obj['type'] == "relationship" and obj['relationship_type'] == "attributed-to":
            renameandmoveKeyEdge(obj)
            filename = f"attributedto_{obj['_key'][-12:]}"
            with open(f'edge/attributedto/{filename}.json', 'w') as outfile:
                json.dump(obj, outfile, indent=4)





checkFolderStructure()  
fetchAdversary()
fetchMalware()
fetchTool()
fetchTechnique()
fetchDataSource()
fetchMitigation()
fetchCampaign()
fetchTactic()
fetchDataComponent()
fetchMitigates()
fetchUses()
fetchSubtechniqueOf()
fetchDetects()
fetchAttributedTo()
convertToJsonLines()
convertToJsonLinesEdge()
id_to_name = idtonameDict()
edgeidtoName(id_to_name)
    

    

    


