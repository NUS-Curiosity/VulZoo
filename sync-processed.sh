#!/bin/bash

# this function is used to print the message in green color
function print_green {
  echo -e "\e[32m$1\e[0m"
}
# this function is used to print the message in yellow color
function print_yellow {
  echo -e "\e[33m$1\e[0m"
}

raw_data_DIR=raw-data
processed_DIR=processed

cd scripts/processed/
print_green "[*][$processed_DIR] Updating OSS-Security"
python sync-oss-security.py
print_green "[*][$processed_DIR] Updating CWE"
python sync-cwe.py
print_green "[*][$processed_DIR] Updating CAPEC"
python sync-capec.py
print_green "[*][$processed_DIR] Updating ATT&CK"
python sync-attack.py
print_green "[*][$processed_DIR] Updating D3FEND"
python sync-d3fend.py
print_green "[*][$processed_DIR] Updating Linux Vulns"
python sync-linux-vulns.py
print_green "[*][$processed_DIR] Updating Patches"
python sync-patch.py
cd - &> /dev/null

print_green "[*][$processed_DIR] Updating MITRE CVE"
mkdir -p $processed_DIR/cve-database
# copy cve-database/[year]/ dirs into processed/cve-database/
cp -r $raw_data_DIR/cve-database/1*/ $processed_DIR/cve-database/
cp -r $raw_data_DIR/cve-database/2*/ $processed_DIR/cve-database/

print_green "[*][$processed_DIR] Updating ZDI Advisories"
mkdir -p $processed_DIR/zdi-advisory-database
cp -r $raw_data_DIR/zdi-advisory-database/advisories/* $processed_DIR/zdi-advisory-database/

print_green "[*][$processed_DIR] Updating NVD"
mkdir -p $processed_DIR/nvd-database
cp -r $raw_data_DIR/nvd-database/CVE-*/ $processed_DIR/nvd-database/

print_green "[*][$processed_DIR] Updating GitHub Security Advisories"
mkdir -p $processed_DIR/github-advisory-database
cp -r $raw_data_DIR/github-advisory-database/advisories/github-reviewed/* $processed_DIR/github-advisory-database/

echo "processed/ update | ts: `date '+%s'`" >> CHANGELOG
