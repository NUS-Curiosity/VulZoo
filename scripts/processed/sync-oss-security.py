#!/usr/bin/env python3

import os
import json
import re

cve_mail_mapping_file = "../../processed/cve-mail-mappings.json"
raw_data_dir = "../../raw-data/oss-security-database"
raw_data_index_file = "oss-security-msg-links.json"
processed_data_dir = "../../processed/oss-security-database"
manifest_file = "../../processed/oss-security-database/manifest.txt"


def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


def get_subject(text):
    # the subject could be in multiple lines, and we need to extract the whole subject
    # the subject line starts with "Subject: "
    # the subject line ends with a newline character
    subject = ""
    begin = False
    for line in text.split('\n'):
        if line.startswith("Subject: "):
            begin = True
            subject += line
        elif begin:
            if line == "":
                break
            subject += line
    # replace multi-whitespaces with a single whitespace
    subject = ' '.join(subject.split())
    return subject


def _is_mail_of_interest_by_subject(subject):
    # check whether the subject contains a CVE ID with regex
    # the CVE ID is in the format CVE-\d{4}-\d{4,7}
    cve_id_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
    return cve_id_pattern.search(subject) is not None


def _is_mail_of_interest_by_text(text, filename, cve_mail_mappings):
    # check whether the mail text contains a CVE ID with regex
    # the CVE ID is in the format CVE-\d{4}-\d{4,7}
    cve_id_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
    # if there are CVEs, add the cve-mail mappings to the cve_mail_mappings dictionary and return True
    # if there are no CVEs, return False
    for cve_id in cve_id_pattern.findall(text):
        if cve_id not in cve_mail_mappings:
            cve_mail_mappings[cve_id] = []
        if f"oss-security-database/{filename}" not in cve_mail_mappings[cve_id]:
            cve_mail_mappings[cve_id].append(f"oss-security-database/{filename}")
    return len(cve_id_pattern.findall(text)) > 0


def is_mail_of_interest(mail_text, filename, cve_mail_mappings):
    # subject = get_subject(mail_text)
    # return _is_mail_of_interest_by_subject(subject)
    return _is_mail_of_interest_by_text(mail_text, filename, cve_mail_mappings)


def read_file(file):
    with open(file, 'r') as f:
        return f.read()
    

def write_file(file, content):
    with open(file, 'w') as f:
        f.write(content)


if __name__ == '__main__':
    ensure_dir(processed_data_dir)
    manifest = read_file(manifest_file).split('\n')
    cve_mail_mappings = json.loads(read_file(cve_mail_mapping_file))
    # each mail text is stored in a separate file, e.g., "2012/06/01/1"
    # iterate over all mail text files in raw_data_dir and process each file
    # skip the raw_data_index_file in the raw_data_dir
    for root, dirs, files in os.walk(raw_data_dir):
        for file in files:
            if file == raw_data_index_file:
                continue
            file_path = os.path.join(root, file)
            date_path = os.path.relpath(file_path, raw_data_dir)
            if date_path in manifest:
                continue
            
            mail_text = read_file(file_path)
            if is_mail_of_interest(mail_text, date_path, cve_mail_mappings):
                # store the mail text in the processed_data_dir
                processed_file_path = os.path.join(processed_data_dir, date_path)
                ensure_dir(os.path.dirname(processed_file_path))
                write_file(processed_file_path, mail_text)
                # update the manifest
                manifest.append(date_path)
    
    # update the manifest file
    write_file(manifest_file, '\n'.join(manifest))
    # update the cve-mail-mappings file
    write_file(cve_mail_mapping_file, json.dumps(cve_mail_mappings, indent=4))
