"""
query_vulzoo.py
This script is used to query the Vulzoo database, given a CVE ID.
"""

import sys
import argparse
import json
import os


VULZOO_BASE_PATH = "./processed"
NVD_DIR = os.path.join(VULZOO_BASE_PATH, 'nvd-database')
CVE_DIR = os.path.join(VULZOO_BASE_PATH, 'cve-database')
ZDI_DIR = os.path.join(VULZOO_BASE_PATH, 'zdi-advisory-database')
GITHUB_DIR = os.path.join(VULZOO_BASE_PATH, 'github-advisory-database')

PATCH_DIR = os.path.join(VULZOO_BASE_PATH, 'patch-database')
REL_CVE_PATCH_FILE = os.path.join(VULZOO_BASE_PATH, 'relationships/rel-cve-patch.json')
REL_CVE_MAIL_FILE = os.path.join(VULZOO_BASE_PATH, 'relationships/rel-cve-mail.json')
REL_CVE_GITHUB_ADVISORY_FILE = os.path.join(VULZOO_BASE_PATH, 'relationships/rel-cve-github-advisory.json')


def save_text(filename, content):
    with open(filename, 'w') as f:
        f.write(content)


def save_json(filename, content):
    with open(filename, 'w') as f:
        json.dump(content, f, indent=4)


def ensure_dir_exists(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)


def load_nvd_data(cve_id):
    # Load NVD data
    nvd_data = None
    # the first level dir in NVD is like CVE-2020
    first_level_dir = cve_id[ :8]
    # the second level dir in NVD is like CVE-2020-470xx, so we replace the last two number with 'xx'
    second_level_dir = cve_id[ :-2] + 'xx'
    # then the final json file is like CVE-2020-47002.json
    json_file = cve_id + '.json'
    nvd_file = os.path.join(NVD_DIR, first_level_dir, second_level_dir, json_file)
    if os.path.exists(nvd_file):
        with open(nvd_file, 'r') as f:
            nvd_data = json.load(f)

    return nvd_data


def load_cve_data(cve_id):
    # Load CVE data
    cve_data = None
    # the first level dir in CVE is like 2020
    first_level_dir = cve_id.split('-')[1]
    # the second level dir in CVE is like 27xxx, so we replace the last three number with 'xxx'
    second_level_dir = cve_id.split('-')[2][ :-3] + 'xxx'
    # then the final json file is like CVE-2020-27001.json
    json_file = cve_id + '.json'
    cve_file = os.path.join(CVE_DIR, first_level_dir, second_level_dir, json_file)
    if os.path.exists(cve_file):
        with open(cve_file, 'r') as f:
            cve_data = json.load(f)

    return cve_data


def load_github_data(cve_id):
    


def load_patch_data(cve_id, patch_id):
    patch_data = None
    year = cve_id.split('-')[1]
    patch_file = f'{PATCH_DIR}/{year}/{cve_id}/{patch_id}'
    if os.path.exists(patch_file):
        with open(patch_file, 'r') as f:
            patch_data = f.read()
    
    return patch_data


def load_mail_data(cve_id, mail_id):
    mail_data = None
    mail_file = f'{VULZOO_BASE_PATH}/{mail_id}'
    if os.path.exists(mail_file):
        with open(mail_file, 'r') as f:
            mail_data = f.read()
    
    return mail_data


def load_rel_cve_patch(cve_id):
    commit_list = list()
    with open(REL_CVE_PATCH_FILE, 'r') as f:
        rel_data = json.load(f)
        if cve_id in rel_data:
            commit_list = rel_data[cve_id]

    return commit_list


def load_rel_cve_mail(cve_id):
    mail_list = list()
    with open(REL_CVE_MAIL_FILE, 'r') as f:
        rel_data = json.load(f)
        if cve_id in rel_data:
            mail_list = rel_data[cve_id]

    return mail_list


def query_vulzoo(cve_id, workdir):
    cve_id = cve_id.upper()
    # Query Vulzoo database
    # The results will be stored in the workdir
    nvd_data = load_nvd_data(cve_id)
    if nvd_data:
        save_json(os.path.join(workdir, 'nvd.json'), nvd_data)    

    cve_data = load_cve_data(cve_id)
    if cve_data:
        save_json(os.path.join(workdir, 'cve.json'), cve_data)

    patch_list = load_rel_cve_patch(cve_id)
    if patch_list:
        save_json(os.path.join(workdir, 'patch.json'), patch_list)
        ensure_dir_exists(os.path.join(workdir, 'patches'))
        for patch_id in patch_list:
            patch_data = load_patch_data(cve_id, patch_id)
            if patch_data:
                save_text(os.path.join(workdir, 'patches', patch_id), patch_data)
    
    mail_list = load_rel_cve_mail(cve_id)
    if mail_list:
        save_json(os.path.join(workdir, 'mail.json'), mail_list)
        ensure_dir_exists(os.path.join(workdir, 'mails'))
        for mail_id in mail_list:
            # replace the '/' in mail_id with '_'
            mail_id_new = mail_id.replace('/', '_')
            mail_data = load_mail_data(cve_id, mail_id)
            if mail_data:
                save_text(os.path.join(workdir, 'mails', mail_id_new), mail_data)


def main():
    # Parse command line arguments
    # Basic usage:
    #   python query_vulzoo.py -c cve-2019-0708
    #   python query_vulzoo.py --cve cve-2019-0708
    # By default, the script will create folder in ./workdir/{cve_id} to store the results
    parser = argparse.ArgumentParser(description='Query Vulzoo database')
    parser.add_argument('-c', '--cve', required=True, help='CVE ID')
    parser.add_argument('--workdir', default='./workdir', help='Working directory (default: ./workdir)')
    args = parser.parse_args()

    cve_id = args.cve
    workdir = os.path.join(args.workdir, cve_id)
    # if the cve_id folder already exists, remove it and create a new one
    if os.path.exists(workdir):
        os.system('rm -rf {}'.format(workdir))

    ensure_dir_exists(workdir)    
    query_vulzoo(cve_id, workdir)


if __name__ == '__main__':
    main()
