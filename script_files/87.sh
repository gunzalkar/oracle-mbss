#!/bin/bash

# Define the path to the audit rules file
AUDIT_RULES_FILE="/etc/audit/rules.d/privileged.rules"

# Find all privileged programs (setuid or setgid)
PRIVILEGED_PROGRAMS=$(find / -xdev -perm /6000 -type f 2>/dev/null)

for PROGRAM in $PRIVILEGED_PROGRAMS; do
    # Check if the program is in the audit rules
    if grep -q "$PROGRAM" "$AUDIT_RULES_FILE"; then
        echo "OK: '$PROGRAM' found in auditing rules."
    else
        echo "Warning: '$PROGRAM' not found in on-disk configuration."
    fi
done
