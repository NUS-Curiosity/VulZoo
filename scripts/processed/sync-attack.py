#!/usr/bin/env python3

import os

# collections
attack_collection = [
    "enterprise-attack",
    "mobile-attack",
    "ics-attack",
]

src_dir = "../../raw-data/attack-database"
dst_dir = "../../processed/attack-database"


def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


if __name__ == "__main__":
    for attack in attack_collection:
        src_path = f"{src_dir}/{attack}"
        dst_path = f"{dst_dir}/{attack}"

        # ensure dir
        ensure_dir(dst_path)

        # copy
        os.system(f"cp {src_path}/{attack}.json {dst_path}/")

