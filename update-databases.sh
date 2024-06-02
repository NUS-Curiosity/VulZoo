#!/bin/bash

# cve, nvd, zdi, github
git pull --recurse-submodules

# cisa-kev
wget https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -O ../cisa-kev-database/known_exploited_vulnerabilities.json

# cwe
wget https://cwe.mitre.org/data/xml/cwec_latest.xml.zip -O cwe-database/cwec_latest.xml.zip
cd cwe-database/
unzip -o cwec_latest.xml.zip
rm cwec_latest.xml.zip
cd -

# capec
wget https://capec.mitre.org/data/archive/capec_latest.zip -O capec-database/capec_latest.zip
cd capec-database/
unzip -o capec_latest.zip
rm capec_latest.zip
cd -

echo "database update | ts: `date '+%s'`" >> CHANGELOG

