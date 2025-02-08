#!/bin/bash

# Define the path to the audit rules file
AUDIT_RULES_FILE="/etc/audit/rules.d/mount.rules"

# Find UID_MIN
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)

# Function to check if a rule is present in a file
check_rule_in_file() {
    local file="$1"
    local rule="$2"
    grep -F -q "$rule" "$file"
}

# Verify on-disk rules
if [ -n "$UID_MIN" ]; then
    # Define expected rules
    ON_DISK_RULES_ARCH64="-a always,exit -F arch=b64 -S mount -F auid>=${UID_MIN} -F auid!=unset -k mounts"
    ON_DISK_RULES_ARCH32="-a always,exit -F arch=b32 -S mount -F auid>=${UID_MIN} -F auid!=unset -k mounts"

    # Check if both rules are present in the on-disk configuration
    if check_rule_in_file "$AUDIT_RULES_FILE" "$ON_DISK_RULES_ARCH64" && check_rule_in_file "$AUDIT_RULES_FILE" "$ON_DISK_RULES_ARCH32"; then
        echo "On-disk configuration is correct."
    else
        echo "ERROR: On-disk configuration is incorrect."
    fi

    # Verify loaded rules
    LOADED_RULES_ARCH64="-a always,exit -F arch=b64 -S mount -F auid>=${UID_MIN} -F auid!=-1 -k mounts"
    LOADED_RULES_ARCH32="-a always,exit -F arch=b32 -S mount -F auid>=${UID_MIN} -F auid!=-1 -k mounts"

    LOADED_RULES=$(auditctl -l)

    if echo "$LOADED_RULES" | grep -F -q "$LOADED_RULES_ARCH64" && echo "$LOADED_RULES" | grep -F -q "$LOADED_RULES_ARCH32"; then
        echo "Audit rules are correctly loaded."
        echo "Passed"
    else
        echo "ERROR: Audit rules are incorrect or missing."
    fi
else
    echo "ERROR: Variable 'UID_MIN' is unset."
fi
