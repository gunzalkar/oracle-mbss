#!/usr/bin/env bash
{
    if rpm -q cronie >/dev/null; then
        # Check if /etc/cron.deny exists
        if [ -e /etc/cron.deny ]; then
            echo "Fail: cron.deny exists"
        fi

        # Check if /etc/cron.allow exists
        if [ ! -e /etc/cron.allow ]; then
            echo "Fail: cron.allow doesn't exist"
        else
            # Check if permissions on /etc/cron.allow are too permissive
            if ! stat -Lc "%a" /etc/cron.allow | grep -Eq "^[0,2,4,6]00$"; then
                echo "Fail: cron.allow mode too permissive"
            fi
            
            # Check if owner and group of /etc/cron.allow are not root
            if ! stat -Lc "%u:%g" /etc/cron.allow | grep -Eq "^0:0$"; then
                echo "Fail: cron.allow owner and/or group not root"
            fi
        fi

        # Ensure that if /etc/cron.deny does not exist, /etc/cron.allow must be correctly set
        if [ ! -e /etc/cron.deny ] && [ -e /etc/cron.allow ] && \
           stat -Lc "%a" /etc/cron.allow | grep -Eq "^[0,2,4,6]00$" && \
           stat -Lc "%u:%g" /etc/cron.allow | grep -Eq "^0:0$"; then
            echo "Pass"
        fi
    else
        echo "Pass: cron is not installed on the system"
    fi
}
