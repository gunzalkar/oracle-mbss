#!/bin/bash

# Get UID_MIN from /etc/login.defs
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)

if [ -n "$UID_MIN" ]; then
    # Create audit rules for 64-bit systems
    echo "-a always,exit -F arch=b64 -S mount -F auid>=${UID_MIN} -F auid!=unset -k mounts" > /etc/audit/rules.d/mount.rules
    echo "-a always,exit -F arch=b32 -S mount -F auid>=${UID_MIN} -F auid!=unset -k mounts" >> /etc/audit/rules.d/mount.rules

    # Apply the rules
    auditctl -R /etc/audit/rules.d/mount.rules

    # Verify the rules were applied
    echo "Rules applied successfully. Current rules:"
    auditctl -l | grep -E "^-a always,exit -F arch=b(64|32) -S mount -F auid>=${UID_MIN} -F auid!=unset -k mounts"
else
    echo "ERROR: Variable 'UID_MIN' is unset."
fi

