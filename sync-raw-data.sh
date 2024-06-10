#!/bin/bash

# this function is used to print the message in green color
function print_green {
  echo -e "\e[32m$1\e[0m"
}
# this function is used to print the message in yellow color
function print_yellow {
  echo -e "\e[33m$1\e[0m"
}

# Vulnerabilities: cve, nvd, zdi, github, att&ck, 
# Exploits: exploit-db,
# Mail lists: Linux vulns,
print_green "[*] Updating CVE, NVD, ZDI, GitHub SA, ATT&CK, Exploit-DB, Linux vulns"
git submodule update --remote

RAW_DATA_DIR=raw-data

# cisa-kev
print_green "[*] Updating CISA KEV"
wget https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -O $RAW_DATA_DIR/cisa-kev-database/kev.json

# cwe
print_green "[*] Updating CWE"
wget https://cwe.mitre.org/data/xml/cwec_latest.xml.zip -O $RAW_DATA_DIR/cwe-database/cwec_latest.xml.zip
cd $RAW_DATA_DIR/cwe-database/
unzip -o cwec_latest.xml.zip
rm cwec_latest.xml.zip
for file in cwec*.xml; do
  if [ -e "$file" ]; then
    mv "$file" "cwec.xml"
    break
  fi
done
cd -

# capec
print_green "[*] Updating CAPEC"
wget https://capec.mitre.org/data/archive/capec_latest.zip -O $RAW_DATA_DIR/capec-database/capec_latest.zip
cd $RAW_DATA_DIR/capec-database/
unzip -o capec_latest.zip
rm capec_latest.zip
# mv ap_schema*.xsd ap_schema.xsd # rename the file
for file in ap_schema*.xsd; do
  if [ -e "$file" ]; then
    mv "$file" "ap_schema.xsd"
    break
  fi
done
# mv capec*.xml capec.xml # rename the file
for file in capec*.xml; do
  if [ -e "$file" ]; then
    mv "$file" "capec.xml"
    break
  fi
done
cd -

# d3fend
print_green "[*] Updating D3FEND"
wget https://d3fend.mitre.org/ontologies/d3fend.json -O $RAW_DATA_DIR/d3fend-database/d3fend_ontology.json
wget https://d3fend.mitre.org/ontologies/d3fend.csv -O $RAW_DATA_DIR/d3fend-database/d3fend.csv

# oss-security
print_green "[*] Updating OSS-Security"
cd scripts/raw-data/
python3 sync-oss-security.py
cd -


echo "raw-data/ update | ts: `date '+%s'`" >> CHANGELOG

print_yellow "[!] Please manually run scripts/raw-data/sync-attackerkb.py with the API key to update AttackerKB"
