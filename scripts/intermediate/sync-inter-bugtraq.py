#!/usr/bin/env python3

import os
import re


raw_data_dir = "../../raw-data/bugtraq-database"
raw_data_index_file = "bugtraq-msg-links.json"
intermediate_data_dir = "../../intermediate/bugtraq-database"
manifest_file = "../../intermediate/bugtraq-database/manifest.txt"


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


def _is_mail_of_interest_by_text(text):
    # check whether the mail text contains a CVE ID with regex
    # the CVE ID is in the format CVE-\d{4}-\d{4,7}
    cve_id_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
    return cve_id_pattern.search(text) is not None


def is_mail_of_interest(mail_text):
    # subject = get_subject(mail_text)
    # return _is_mail_of_interest_by_subject(subject)
    return _is_mail_of_interest_by_text(mail_text)


def read_file(file):
    with open(file, 'r') as f:
        return f.read()
    

def write_file(file, content):
    with open(file, 'w') as f:
        f.write(content)


if __name__ == '__main__':
    ensure_dir(intermediate_data_dir)
    manifest = read_file(manifest_file).split('\n')    
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
            if is_mail_of_interest(mail_text):
                # store the mail text in the intermediate_data_dir
                intermediate_file_path = os.path.join(intermediate_data_dir, date_path)
                ensure_dir(os.path.dirname(intermediate_file_path))
                write_file(intermediate_file_path, mail_text)
                # update the manifest
                manifest.append(date_path)
    
    # update the manifest file
    write_file(manifest_file, '\n'.join(manifest))

