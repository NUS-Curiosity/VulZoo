#!/usr/bin/env python3

import xmltodict
import json

GREEN = '\033[92m'
RESET = '\033[0m'


def attr_to_key(_, key, value):
    if key.startswith('@'):
        key = key[1:] # remove the @
    return key, value


raw_data_file = "../../raw-data/cwe-database/cwec.xml"
intermediate_data_file = "../../intermediate/cwe-database/cwec.json"

with open(raw_data_file, "r") as f:
    data = f.read()

data_dict = xmltodict.parse(data, postprocessor=attr_to_key)
json_content = json.dumps(data_dict, indent=4)

with open(intermediate_data_file, "w") as f:
    f.write(json_content)

print(f"{GREEN}[*] CWE data has been converted to JSON format at {intermediate_data_file}{RESET}")
