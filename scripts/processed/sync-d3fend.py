#!/usr/bin/env python3

import os
import pandas as pd


src_dir = "../../raw-data/d3fend-database"
dst_dir = "../../processed/d3fend-database"


def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


if __name__ == "__main__":
    ensure_dir(dst_dir)

    os.system(f"cp {src_dir}/d3fend_ontology.json {dst_dir}/")

    df = pd.read_csv(f"{src_dir}/d3fend.csv")
    res = df.to_json(orient="records", indent=4)
    with open(f"{dst_dir}/d3fend.json", "w") as f:
        f.write(res)
