#!/usr/bin/env python3

import re
import os
import json

# generate cve -- assessment mapping list
topics_dir = "../../processed/attackerkb-database/topics"
assessments_dir = "../../processed/attackerkb-database/assessments"
relationship_file = "../../processed/attackerkb-database/relationships.json"
cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
cve_topic_map = {}
for root, dirs, files in os.walk(f"{topics_dir}"):
    for file in files:
        if file.endswith(".json"):
            with open(os.path.join(root, file), "r") as f:
                data = json.load(f)
                for topic in data['data']:
                    # find cve in topic name
                    cve = cve_pattern.search(topic['name'])
                    if cve:
                        cve_topic_map[cve.group()] = topic['id']

topic_assessment_map = {}
for root, dirs, files in os.walk(f"{assessments_dir}"):
    for file in files:
        if file.endswith(".json"):
            with open(os.path.join(root, file), "r") as f:
                data = json.load(f)
                for assessment in data['data']:
                    if assessment['topicId'] not in topic_assessment_map:
                        topic_assessment_map[assessment['topicId']] = []
                    topic_assessment_map[assessment['topicId']].append(assessment['id'])

cve_assessment_map = {}

for cve, topic_id in cve_topic_map.items():
    if topic_id in topic_assessment_map:
        cve_assessment_map[cve] = topic_assessment_map[topic_id]

with open(relationship_file, "w") as f:
    json.dump(cve_assessment_map, f, indent=4)
