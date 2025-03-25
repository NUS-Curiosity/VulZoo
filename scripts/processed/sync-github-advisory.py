import json
import os

processed_data_dir = '../../processed/github-advisory-database'
cve_github_advisory_mapping_file = '../../processed/relationships/rel-cve-github-advisory.json'

# traverse the processed data directory
# load each github advisory json
# check whether there is an "aliases" list in the json and there are any cve ids in the list
# if there are, add the (cve_id, github_advisory_path) pair to the mapping

cve_github_advisory_mapping = dict()
for root, dirs, files in os.walk(processed_data_dir):
    for file in files:
        if file.endswith('.json'):
            with open(os.path.join(root, file), 'r') as f:
                advisory_data = json.load(f)
                if 'aliases' in advisory_data:
                    for alias in advisory_data['aliases']:
                        if alias.startswith('CVE-'):
                            cve_id = alias
                            github_advisory_path = os.path.join(root, file)
                            # remove the '../../processed/' from the path
                            github_advisory_path = github_advisory_path[16:]
                            if cve_id not in cve_github_advisory_mapping:
                                cve_github_advisory_mapping[cve_id] = list()
                            cve_github_advisory_mapping[cve_id].append(github_advisory_path)


with open(cve_github_advisory_mapping_file, 'w') as f:
    json.dump(cve_github_advisory_mapping, f, indent=4)
