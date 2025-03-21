#!/usr/bin/env python3

import os
import json
import time
import re
import requests
from collections import Counter
from urllib.parse import urlparse

header = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
}


def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


nvd_dir = "../../processed/nvd-database"
patch_dir = "../../processed/patch-database"
nvd_patch_links = "../../processed/relationships/temp-nvd-patch-links.json"
cve_patch_manifest = "../../processed/relationships/rel-cve-patch.json"


def is_prefix_of(str1, str2):
    if str2.startswith(str1):
        return True
    if str1.startswith(str2):
        return True
    return False


def save_patch(dst_dir, commit_hash, text, cve, manifest):
    ensure_dir(dst_dir)

    with open(f"{dst_dir}/{commit_hash}", "w") as f:
        f.write(text)

    if cve not in manifest:
        manifest[cve] = list()
    manifest[cve].append(commit_hash)


def fetch_patch_from_github(cve, url, manifest):
    # e.g., https://github.com/librenms/librenms/commit/ce8e5f3d056829bfa7a845f9dc2757e21e419ddc
    url = url.split("#")[0] # remove the anchor
    url = url.split("?")[0] # remove the query string
    url = url.strip("/")
    diff_url = f"{url}.diff"
    commit_hash = url.split("/")[-1]
    cve_year = cve.split("-")[1]
    dst_dir = f"{patch_dir}/{cve_year}/{cve}"
    # check whether the patch has been fetched
    if cve in manifest:
        if commit_hash in manifest[cve]:
            print(f"Skiping {commit_hash} for {cve}")
            return
        for commit in manifest[cve]:
            if is_prefix_of(commit_hash, commit):
                print(f"Skiping {commit_hash} for {cve} (same-prefix commit exists)")
                return

    r = requests.get(diff_url, headers=header)
    if r.status_code != 200:
        return

    print(f"Fetching patch for {cve} at {url}")
    save_patch(dst_dir, commit_hash, r.text, cve, manifest)
    time.sleep(1)
    

def fetch_patch_from_git_kernel(cve, url, manifest):
    # e.g., https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=cb66ddd156203daefb8d71158036b27b0e2caf63
    standard_pattern = re.compile(r"https://git.kernel.org/pub/scm/linux/kernel/git/.*/linux.git/commit\?.*id=.*")
    # Consider short hash and complete hash. For example, cb66ddd156203 and cb66ddd156203daefb8d71158036b27b0e2caf63
    commit_hash_pattern = re.compile(r"[0-9a-f]{12,40}")
    try:
        commit_hash = commit_hash_pattern.search(url).group()
    except AttributeError:
        return

    cve_year = cve.split("-")[1]
    dst_dir = f"{patch_dir}/{cve_year}/{cve}"
    # check whether the patch has been fetched
    if cve in manifest:
        if commit_hash in manifest[cve]:
            print(f"Skiping {commit_hash} for {cve}")
            return
        for commit in manifest[cve]:
            if is_prefix_of(commit_hash, commit):
                print(f"Skiping {commit_hash} for {cve} (same-prefix commit exists)")
                return

    if standard_pattern.match(url):
        real_url = url
    else:
        # follow 302 redirect to get the real url
        r = requests.get(url, headers=header)
        if r.status_code != 200:
            return
        # filter links like https://git.kernel.orgb/scm/linux/kernel/git/torvalds/linux.git/commit (CVE-2023-0210 in NVD)
        if "id=" not in r.url:
            return
        real_url = r.url

    # replace the "commit" in url with "patch"
    patch_url = real_url.replace("commit", "patch")
    r = requests.get(patch_url, headers=header)
    if r.status_code != 200:
        return

    print(f"Fetching patch for {cve} at {url}")

    save_patch(dst_dir, commit_hash, r.text, cve, manifest)
    time.sleep(3)


def dispatch_patch_fetcher(cve, url, patch_manifest):
    # github e.g., https://github.com/librenms/librenms/commit/ce8e5f3d056829bfa7a845f9dc2757e21e419ddc
    # git.kernel.org e.g., https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ce8e5f3d056829bfa7a845f9dc2757e21e419ddc
    # use re to match the domain
    github_pattern = re.compile(r"https://github\.com/.*/.*/commit/.*")
    if github_pattern.match(url):
        print(f"Processing {cve} at {url}")
        fetch_patch_from_github(cve, url, patch_manifest)
        return
    domain = urlparse(url).netloc
    if domain == "git.kernel.org":
        print(f"Processing {cve} at {url}")
        fetch_patch_from_git_kernel(cve, url, patch_manifest)
        return


def get_patch_links_from_nvd():
    res = {}
    for root, dirs, files in os.walk(nvd_dir):
        for file in files:
            if file.endswith(".json"):
                with open(os.path.join(root, file), "r") as f:
                    data = json.load(f)
                    try:
                        references = data['references']
                        for reference in references:
                            if "Patch" in reference['tags']:
                                if data['id'] not in res:
                                    res[data['id']] = list()
                                res[data['id']].append(reference['url'])
                    except KeyError:
                        continue
    return res


def show_topN_domains(patch_links, N=10):
    domain_list = list()
    for _, links in patch_links.items():
        for link in links:
            domain = urlparse(link).netloc
            domain_list.append(domain)
    
    domain_counter = Counter(domain_list)
    # print(f"Top {N} domains:")
    # for domain, count in domain_counter.most_common(N):
        # print(f"\t{domain}: {count}")


if __name__ == "__main__":
    try:
        patch_links = get_patch_links_from_nvd()
        with open(nvd_patch_links, "w") as f:
            json.dump(patch_links, f, indent=4)
        print(f"Patch links saved to {nvd_patch_links}")

        show_topN_domains(patch_links, N=10)

        with open(cve_patch_manifest, "r") as f:
            patch_manifest = json.load(f)
        for cve, urls in patch_links.items():
            for url in urls:
                dispatch_patch_fetcher(cve, url, patch_manifest)
                time.sleep(0.1)
        # update the patch manifest
        with open(cve_patch_manifest, "w") as f:
            json.dump(patch_manifest, f, indent=4)
    except KeyboardInterrupt:
        print("Interrupted")
