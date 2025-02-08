#!/bin/bash

# Check if the directory is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 script_files/"
    exit 1
fi

# Check if the provided argument is a directory
if [ ! -d "$1" ]; then
    echo "Error: '$1' is not a directory."
    exit 1
fi

# Change to the specified directory
cd "$1" || exit

# Change permission for all files in the directory
for file in *; do
    if [ -f "$file" ]; then
        chmod +x "$file"
        dos2unix "$file"
        echo "Updated permission for $file"
    fi
done
