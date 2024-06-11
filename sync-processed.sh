#!/bin/bash

# this function is used to print the message in green color
function print_green {
  echo -e "\e[32m$1\e[0m"
}
# this function is used to print the message in yellow color
function print_yellow {
  echo -e "\e[33m$1\e[0m"
}

processed_DIR=processed

# oss-security, cwe
print_green "[*][$processed_DIR] Updating OSS-Security, CWE"
cd scripts/processed/
python sync-inter-oss-security.py
python sync-inter-cwe.py
cd -

echo "processed/ update | ts: `date '+%s'`" >> CHANGELOG
