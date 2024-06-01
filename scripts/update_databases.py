#!/usr/bin/env python

import os

os.system("git pull --recurse-submodules")
os.system("wget https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -O ../cisa-kev-database/known_exploited_vulnerabilities.json")

