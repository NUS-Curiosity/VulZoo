#!/bin/bash

RAW_DATA_DIR=raw-data

print_green "[*][$RAW_DATA_DIR] Updating CPE"
wget https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz -O $RAW_DATA_DIR/cpe-database/official-cpe-dictionary_v2.3.xml.gz
cd $RAW_DATA_DIR/cpe-database/
gunzip official-cpe-dictionary_v2.3.xml.gz

for file in official-cpe-dictionary*.xml; do
  if [ -e "$file" ]; then
    mv "$file" "cpe.xml"
    break
  fi
done
cd - &> /dev/null