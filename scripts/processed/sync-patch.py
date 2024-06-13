#!/usr/bin/env python3

import os
import json
import time
import re
import requests
from collections import Counter
from urllib.parse import urlparse


def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


nvd_dir = "../../processed/nvd-database"
patch_dir = "../../processed/patch-database"
nvd_patch_links = "../../processed/patch-database/nvd-patch-links.json"
cve_patch_manifest = "../../processed/patch-database/patch-manifest.json"


def save_patch(dst_dir, commit_hash, text, cve, manifest):
    ensure_dir(dst_dir)

    with open(f"{dst_dir}/{commit_hash}", "w") as f:
        f.write(text)

    manifest[cve].append(commit_hash)


def fetch_patch_from_github(cve, url, manifest):
    # e.g., https://github.com/librenms/librenms/commit/ce8e5f3d056829bfa7a845f9dc2757e21e419ddc
    url = url.split("#")[0] # remove the anchor
    url.strip("/")
    diff_url = f"{url}.diff"
    commit_hash = url.split("/")[-1]
    cve_year = cve.split("-")[1]
    dst_dir = f"{patch_dir}/{cve_year}/{cve}"
    # check whether the patch has been fetched
    if os.path.exists(dst_dir):
        if commit_hash in manifest[cve]:
            return

    r = requests.get(diff_url)
    if r.status_code != 200:
        return

    print(f"Fetching patch for {cve} at {url}")
    save_patch(dst_dir, commit_hash, r.text, cve, manifest)


def fetch_patch_from_git_kernel(cve, url, manifest):
    # e.g., https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=cb66ddd156203daefb8d71158036b27b0e2caf63
    standard_pattern = re.compile(r"https://git.kernel.org/pub/scm/linux/kernel/git/.*/linux.git/commit\?.*id=.*")
    if standard_pattern.match(url):
        real_url = url
    else:
        # follow 302 redirect to get the real url
        r = requests.get(url)
        if r.status_code != 200:
            return
        # filter links like https://git.kernel.orgb/scm/linux/kernel/git/torvalds/linux.git/commit (CVE-2023-0210 in NVD)
        if "id=" not in r.url:
            return
        real_url = r.url

    # replace the "commit" in url with "patch"
    patch_url = real_url.replace("commit", "patch")
    r = requests.get(patch_url)
    if r.status_code != 200:
        return
    # get hash from the first line of r.text (path)
    # For example, "From bc0bdc5afaa740d782fbf936aaeebd65e5c2921d Mon Sep 17 00:00:00 2001"
    commit_hash = r.text.split("\n")[0].split(" ")[1]
    cve_year = cve.split("-")[1]
    dst_dir = f"{patch_dir}/{cve_year}/{cve}"
    # check whether the patch has been fetched
    if os.path.exists(dst_dir):
        if commit_hash in manifest[cve]:
            return

    print(f"Fetching patch for {cve} at {url}")

    save_patch(dst_dir, commit_hash, r.text, cve, manifest)


def dispatch_patch_fetcher(cve, url, patch_manifest):
    # github e.g., https://github.com/librenms/librenms/commit/ce8e5f3d056829bfa7a845f9dc2757e21e419ddc
    # git.kernel.org e.g., https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ce8e5f3d056829bfa7a845f9dc2757e21e419ddc
    # use re to match the domain
    github_pattern = re.compile(r"https://github\.com/.*/.*/commit/.*")
    if github_pattern.match(url):
        fetch_patch_from_github(cve, url, patch_manifest)
        return
    domain = urlparse(url).netloc
    if domain == "git.kernel.org":
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
    print(f"Top {N} domains:")
    for domain, count in domain_counter.most_common(N):
        print(f"\t{domain}: {count}")


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
                time.sleep(1)
        # update the patch manifest
        with open(cve_patch_manifest, "w") as f:
            json.dump(patch_manifest, f, indent=4)
    except KeyboardInterrupt:
        print("Interrupted")
