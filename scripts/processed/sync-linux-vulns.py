#!/usr/bin/env python3

import os
import json


def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


cve_mail_mapping_file = "../../relationships/rel-cve-mail.json"
src_dir = f"../../raw-data/linux-vulns-database/cve"
dst_dir = f"../../processed/linux-vulns-database"
sub_dirs = ["published", "rejected"]


if __name__ == "__main__":
    ensure_dir(dst_dir)

    for sub_dir in sub_dirs:
        # what we need: 
        # ../../raw-data/linux-vulns-database/cve/published/[year]/[cve-id].json
        # ../../raw-data/linux-vulns-database/cve/published/[year]/[cve-id].mbox
        # ../../raw-data/linux-vulns-database/cve/rejected/[year]/[cve-id].json
        # ../../raw-data/linux-vulns-database/cve/rejected/[year]/[cve-id].mbox
        src_sub_dir = f"{src_dir}/{sub_dir}"
        dst_sub_dir = f"{dst_dir}/{sub_dir}"
        ensure_dir(dst_sub_dir)

        for year in os.listdir(src_sub_dir):
            try:
                int(year)
            except ValueError:
                continue
            src_year_dir = f"{src_sub_dir}/{year}"
            dst_year_dir = f"{dst_sub_dir}/{year}"
            ensure_dir(dst_year_dir)

            os.system(f"cp {src_year_dir}/CVE-*.json {dst_year_dir}")
            os.system(f"cp {src_year_dir}/CVE-*.mbox {dst_year_dir}")

    # update cve_mail_mappings
    with open(cve_mail_mapping_file, "r") as f:
        cve_mail_mappings = json.load(f)
    
    for root, dirs, files in os.walk(dst_dir):
        for file in files:
            if file.endswith(".mbox"):
                # whole path example: ../../processed/linux-vulns-database/published/2019/CVE-2019-1234.mbox
                # path we need: linux-vulns-database/published/2019/CVE-2019-1234.mbox
                cve_id = file.split(".")[0]
                if cve_id not in cve_mail_mappings:
                    cve_mail_mappings[cve_id] = []
                rel_path = os.path.relpath(os.path.join(root, file), start="../../processed")
                if rel_path not in cve_mail_mappings[cve_id]:
                    cve_mail_mappings[cve_id].append(rel_path)
    
    with open(cve_mail_mapping_file, "w") as f:
        json.dump(cve_mail_mappings, f, indent=4)