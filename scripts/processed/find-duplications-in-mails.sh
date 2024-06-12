#!/bin/bash

# Create a temporary file to store the hash values and filenames
tempfile=$(mktemp)

# Calculate the hash values of all files in the directory and store the results in the temporary file
find $1 -type f -exec sha256sum {} \; > "$tempfile"

# Find and display duplicate files
echo "[*] Finding duplicate files in $1"
echo "[+] The following are identical files:"
sort "$tempfile" | awk '{
    hash=$1
    file=$2
    if (hash in seen) {
        seen[hash] = seen[hash] "\n\t" file
    } else {
        seen[hash] = file
    }
} END {
    for (hash in seen) {
        split(seen[hash], files, " ")
        if (length(files) > 1) {
            print seen[hash]
        }
    }
}'

# Remove the temporary file
rm "$tempfile"
