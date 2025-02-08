#!/usr/bin/env bash

# Function to check if 'at' is installed
if rpm -q at >/dev/null; then
    echo "'at' is installed on the system."

    # Check if /etc/at.deny exists
    if [ -e /etc/at.deny ]; then
        echo "Fail: /etc/at.deny exists. Removing it..."
        rm -f /etc/at.deny
    else
        echo "/etc/at.deny does not exist. Proceeding..."
    fi

    # Check if /etc/at.allow exists
    if [ ! -e /etc/at.allow ]; then
        echo "Fail: /etc/at.allow doesn't exist. Creating it..."
        touch /etc/at.allow
        chown root:root /etc/at.allow
        chmod 600 /etc/at.allow
