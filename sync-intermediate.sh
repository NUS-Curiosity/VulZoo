#!/bin/bash

# this function is used to print the message in green color
function print_green {
  echo -e "\e[32m$1\e[0m"
}
# this function is used to print the message in yellow color
function print_yellow {
  echo -e "\e[33m$1\e[0m"
}

INTERMEDIATE_DIR=intermediate

# oss-security, cwe
print_green "[*][$INTERMEDIATE_DIR] Updating OSS-Security, CWE"
cd scripts/intermediate/
python sync-inter-oss-security.py
python sync-inter-cwe.py
cd -

echo "intermediate/ update | ts: `date '+%s'`" >> CHANGELOG
