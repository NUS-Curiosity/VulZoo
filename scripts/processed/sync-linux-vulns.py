#!/usr/bin/env python3

import os


def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


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
