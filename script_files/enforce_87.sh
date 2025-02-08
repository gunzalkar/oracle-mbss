#!/bin/bash

# Define the path to the audit rules file
AUDIT_RULES_FILE="/etc/audit/rules.d/privileged.rules"

# Create the audit rules directory if it doesn't exist
if [ ! -d "$(dirname "$AUDIT_RULES_FILE")" ]; then
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")"
fi

# Create the audit rules file if it doesn't exist
if [ ! -f "$AUDIT_RULES_FILE" ]; then
    touch "$AUDIT_RULES_FILE"
fi

# Find all privileged programs (setuid or setgid)
PRIVILEGED_PROGRAMS=$(find / -xdev -perm /6000 -type f 2>/dev/null)

# Initialize a temporary file for new rules
TEMP_RULES_FILE=$(mktemp)

for PROGRAM in $PRIVILEGED_PROGRAMS; do
    # Check if the program is already in the audit rules
    if ! grep -q "$PROGRAM" "$AUDIT_RULES_FILE"; then
        # Add a new audit rule for the program
        echo "-a always,exit -F path=$PROGRAM -F perm=x -F auid>=1000 -F auid!=unset" >> "$TEMP_RULES_FILE"
    fi
done

# Add new rules to the audit rules file if there are any
if [ -s "$TEMP_RULES_FILE" ]; then
    cat "$TEMP_RULES_FILE" >> "$AUDIT_RULES_FILE"
    # Reload the audit rules
    auditctl -R "$AUDIT_RULES_FILE"
    echo "Audit rules have been updated."
else
    echo "No new audit rules needed."
fi

# Clean up temporary file
rm "$TEMP_RULES_FILE"

