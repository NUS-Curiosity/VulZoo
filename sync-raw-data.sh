#!/bin/bash

# Vulnerabilities: cve, nvd, zdi, github, att&ck, 
# Exploits: exploit-db,
# Mail lists: Linux vulns,
git pull --recurse-submodules

RAW_DATA_DIR=raw-data

# cisa-kev
wget https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -O $RAW_DATA_DIR/cisa-kev-database/known_exploited_vulnerabilities.json

# cwe
wget https://cwe.mitre.org/data/xml/cwec_latest.xml.zip -O $RAW_DATA_DIR/cwe-database/cwec_latest.xml.zip
cd $RAW_DATA_DIR/cwe-database/
unzip -o cwec_latest.xml.zip
rm cwec_latest.xml.zip
cd -

# capec
wget https://capec.mitre.org/data/archive/capec_latest.zip -O $RAW_DATA_DIR/capec-database/capec_latest.zip
cd $RAW_DATA_DIR/capec-database/
unzip -o capec_latest.zip
rm capec_latest.zip
cd -

# d3fend
wget https://d3fend.mitre.org/ontologies/d3fend.json -O $RAW_DATA_DIR/d3fend-database/d3fend_ontology.json
wget https://d3fend.mitre.org/ontologies/d3fend.csv -O $RAW_DATA_DIR/d3fend-database/d3fend.csv

# oss-security
cd scripts/raw-data/
python3 sync-oss-security.py
cd -


echo "raw-data/ update | ts: `date '+%s'`" >> CHANGELOG
