#!/usr/bin/env python3

import requests

local_file = "../raw-data/epss-database/epss_scores.csv"
base_url = "https://epss.cyentia.com/epss_scores-{which_date}.csv.gz"

