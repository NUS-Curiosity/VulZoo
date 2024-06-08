#!/bin/bash

INTERMEDIATE_DIR=intermediate

# oss-security
cd scripts/intermediate/
python sync-inter-oss-security.py
cd -

echo "intermediate/ update | ts: `date '+%s'`" >> CHANGELOG
