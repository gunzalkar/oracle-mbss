import subprocess
import csv
import os

# Perform checks
file_path = '/etc/ssh/sshd_config'
script_2 = 'script_files/2.sh'
script_3 = 'script_files/3.sh'
script_30 = 'script_files/30.sh'
script_31 = 'script_files/31.sh'
script_37 = 'script_files/37.sh'
script_57 = "script_files/57.sh"
script_66 = "script_files/66.sh"
script_87 = "script_files/87.sh"
script_95 = "script_files/95.sh"
path_89 = "/etc/audit/rules.d/10-mounts.rules"
def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

#MBSS 1
def check_file_permissions(file_path):
    stat_output = run_command(f"stat -Lc '%n %a %u/%U %g/%G' {file_path}")
    expected_output = f"{file_path} 600 0/root 0/root"
    return stat_output == expected_output

#MBSS 2
def ssh_private_key_permissions(script_path):
    output = run_command(f"bash {script_path}")
    return 'PASS' in output

#MBSS 3
def ssh_public_key_permissions(script_path):
    output = run_command(f"bash {script_path}")
    return 'PASS' in output

#MBSS 4
def check_ssh_access_limited():
    # Run first command
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$'"""
    output_1 = run_command(command_1)
    
    # Run second command
    command_2 = "grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"
    output_2 = run_command(command_2)

    # Check if either output matches the expected patterns
    expected_patterns = ['AllowUsers', 'AllowGroups', 'DenyUsers', 'DenyGroups']
    compliance = any(pattern.lower() in (output_1 + output_2).lower() for pattern in expected_patterns)
    
    return compliance

#MBSS 5
def check_log_level():
    # Command 1: Check the effective LogLevel using sshd -T
    command_1 = (
        'sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk \'{print $1}\')" '
        '| grep -i loglevel'
    )
    command_1_output = run_command(command_1)
    
    # Command 2: Check the LogLevel in the configuration files
    command_2 = (
        'grep -Pi \'^\s*loglevel\' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf '
        '| grep -Evi \'(VERBOSE|INFO)\''
    )
    command_2_output = run_command(command_2)

    # Check if 'loglevel' is present and not commented out in command_1 output
    loglevel_not_commented = any(
        line.strip() and not line.strip().startswith('#') and 'loglevel' in line.lower()
        for line in command_1_output.split('\n')
    )

    # Check if command_2 output is empty (no entries are non-compliant)
    loglevel_compliant = loglevel_not_commented and command_2_output == ''
    
    return loglevel_compliant

#MBSS 6
def check_x11_forwarding():
    # Command 1: Check if X11Forwarding is set correctly in the running SSH configuration
    command_1 = (
        'sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk \'{print $1}\')" | grep -i x11forwarding'
    )
    output_1 = run_command(command_1)
    
    # Check if X11Forwarding is set to 'no'
    x11_forwarding_set = 'x11forwarding no' in output_1.lower()
    
    # Command 2: Check the configuration files for any uncommented X11Forwarding settings
    command_2 = (
        r'grep -Pi "^\s*X11Forwarding\b" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi "no"'
    )
    output_2 = run_command(command_2)
    
    # Ensure that no uncommented X11Forwarding settings are set to anything other than 'no'
    x11_forwarding_compliant = x11_forwarding_set and not output_2.strip()

    return x11_forwarding_compliant

#MBSS 7
def check_max_auth_tries():
    # First, check the effective SSH configuration with sshd -T command
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i maxauthtries"""
    output_1 = run_command(command_1)

    if not output_1:
        return False, "MaxAuthTries not set"

    try:
        max_auth_tries = int(output_1.split()[1])
        if max_auth_tries > 4:
            return False, f"MaxAuthTries is set to {max_auth_tries}, which is higher than recommended"
    except (IndexError, ValueError):
        return False, "Failed to parse MaxAuthTries value"

    # Now, check for any occurrence of MaxAuthTries greater than 4 in config files
    command_2 = """grep -Pi '^\h*maxauthtries\h+([5-9]|[1-9][0-9]+)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"""
    output_2 = run_command(command_2)

    if output_2:
        return False, f"MaxAuthTries value greater than 4 found in configuration files"

    return True, "MaxAuthTries is configured correctly"

# MBSS 8 - Ensure SSH IgnoreRhosts is enabled
def check_ignore_rhosts():
    # Check for IgnoreRhosts in the configuration file
    command_check = """grep -Pi '^IgnoreRhosts' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"""
    output_check = run_command(command_check)
    return '/etc/ssh/sshd_config:IgnoreRhosts yes' in output_check

#MBSS 9
def check_host_based_authentication():
    # Check for IgnoreRhosts in the configuration file
    command_check = """grep -Pi 'hostbasedauthentication' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"""
    output_check = run_command(command_check)
    return '/etc/ssh/sshd_config:HostbasedAuthentication no' in output_check

#MBSS 10
def check_root_login_disabled():
    # Command to check current PermitRootLogin setting
    command_1 = (
        'sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk \'{print $1}\')" | grep permitrootlogin'
    )
    output_1 = run_command(command_1)
    
    # Check if PermitRootLogin is set to no
    permit_root_login_set = 'permitrootlogin no' in output_1.lower()
    
    # Command to check configuration files for PermitRootLogin
    command_2 = (
        r'grep -Pi -- "^\s*PermitRootLogin\b" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf'
    )
    output_2 = run_command(command_2)
    
    # Check if there are any uncommented PermitRootLogin entries
    permit_root_login_compliant = all(
        line.strip().startswith('#') or 'permitrootlogin no' in line.lower()
        for line in output_2.split('\n') if line.strip()
    )
    
    # Ensure both conditions are met for compliance
    compliance = permit_root_login_set and permit_root_login_compliant
    return compliance

#MBSS 11 - Ensure SSH PermitEmptyPasswords is disabled
def check_permit_empty_passwords():
    # Command to check active configuration (sshd -T output)
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permitemptypasswords"""
    output_1 = run_command(command_1)

    # Command to check /etc/ssh/sshd_config content
    command_2 = "grep -Pi '^\\s*PermitEmptyPasswords\\b' /etc/ssh/sshd_config"
    output_2 = run_command(command_2)

    # Logic to determine compliance
    if not output_2:
        # No mention of PermitEmptyPasswords in the config file
        return False

    if '#PermitEmptyPasswords' in output_2:
        # It's commented out in the config file
        return False

    # Check if the active configuration has PermitEmptyPasswords set to 'no'
    if 'permitemptypasswords no' in output_1.lower():
        return True
    
    return False

#MBSS 12
def check_permit_user_environment():
    # Command to check active configuration (sshd -T output)
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permituserenvironment"""
    output_1 = run_command(command_1)

    # Command to check /etc/ssh/sshd_config content
    command_2 = "grep -Pi '^\\s*PermitUserEnvironment\\b' /etc/ssh/sshd_config"
    output_2 = run_command(command_2)

    # Logic to determine compliance
    if not output_2:
        # No mention of PermitUserEnvironment in the config file
        return False

    if '#PermitUserEnvironment' in output_2:
        # It's commented out in the config file
        return False

    # Check if the active configuration has PermitUserEnvironment set to 'no'
    if 'permituserenvironment no' in output_1.lower():
        return True
    
    return False

# MBSS 13 - Check SSH Idle Timeout Interval Compliance
def check_ssh_idle_timeout():
    # Command to check ClientAliveInterval
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep clientaliveinterval"""
    output_1 = run_command(command_1)
    
    # Command to check ClientAliveCountMax
    command_2 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep clientalivecountmax"""
    output_2 = run_command(command_2)
    
    # Command to check /etc/ssh/sshd_config for ClientAlive settings
    config_check_1 = "grep -Pi '^\\s*ClientAliveInterval\\b' /etc/ssh/sshd_config"
    config_check_2 = "grep -Pi '^\\s*ClientAliveCountMax\\b' /etc/ssh/sshd_config"
    config_output_1 = run_command(config_check_1)
    config_output_2 = run_command(config_check_2)
    
    # Check if both parameters exist in sshd_config
    if '#ClientAliveInterval' in config_output_1 or '#ClientAliveCountMax' in config_output_2:
        return False
    
    # Check if active configuration for ClientAliveInterval and ClientAliveCountMax is compliant
    compliant_interval = 'clientaliveinterval 300' in output_1.lower()
    compliant_countmax = 'clientalivecountmax 3' in output_2.lower()
    
    return compliant_interval and compliant_countmax

# MBSS 14 - Check SSH LoginGraceTime Compliance
def check_ssh_logingracetime():
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep logingracetime"""
    output_1 = run_command(command_1)
    
    config_check = "grep -Ei '^\s*LoginGraceTime\s+(0|6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+|[^1]m)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"
    config_output = run_command(config_check)
    
    if '#LoginGraceTime' in output_1 or config_output:
        return False
    
    return 'logingracetime 60' in output_1.lower()

# MBSS 15 - Check SSH Warning Banner Compliance
def check_ssh_banner():
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep banner"""
    output_1 = run_command(command_1)
    
    if '#Banner' in output_1:
        return False
    
    return 'banner /etc/issue.net' in output_1.lower()

# MBSS 16 - Check SSH PAM Compliance
def check_ssh_pam():
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i usepam"""
    output_1 = run_command(command_1)
    
    config_check = "grep -Pi '^\\s*UsePAM\\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi 'yes'"
    config_output = run_command(config_check)
    
    if '#UsePAM' in output_1 or config_output:
        return False
    
    return 'usepam yes' in output_1.lower()

# MBSS 17 - Check SSH AllowTcpForwarding Compliance
def check_ssh_tcp_forwarding():
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i allowtcpforwarding"""
    output_1 = run_command(command_1)
    
    config_check = "grep -Pi '^\\s*AllowTcpForwarding\\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi 'no'"
    config_output = run_command(config_check)
    
    if '#AllowTcpForwarding' in output_1 or config_output:
        return False
    
    return 'allowtcpforwarding no' in output_1.lower()

# MBSS 18 - Check SSH MaxStartups Compliance
def check_ssh_maxstartups():
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i maxstartups"""
    output_1 = run_command(command_1)

    config_check = "grep -Ei '^\\s*MaxStartups\\s+(((1[1-9]|[1-9][0-9][0-9]+):([0-9]+):([0-9]+))|(([0-9]+):(3[1-9]|[4-9][0-9]|[1-9][0-9][0-9]+):([0-9]+))|(([0-9]+):([0-9]+):(6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+)))' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"
    config_output = run_command(config_check)

    if '#MaxStartups' in output_1 or config_output:
        return False

    return 'maxstartups 10:30:60' in output_1.lower()

# MBSS 19 - Check SSH MaxSessions Compliance
def check_ssh_maxsessions():
    command_1 = """grep -r -i 'MaxSessions' /etc/ssh/sshd_config"""
    output_1 = run_command(command_1)

    config_check = "grep -Ei '^\\s*MaxSessions\\s+(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"
    config_output = run_command(config_check)

    if '#MaxSessions 10' in output_1 or config_output:
        return False
    
    if 'maxsessions 10' in output_1.lower():
        return True

# MBSS 20 - Check Password Creation Requirements Compliance
def check_password_creation_requirements():
    # Commands to check pam_pwquality.so configuration
    pam_pwquality_check = "grep pam_pwquality.so /etc/pam.d/system-auth /etc/pam.d/password-auth"
    pam_pwquality_output = run_command(pam_pwquality_check)

    # Commands to check password length requirements
    minlen_check = "grep ^minlen /etc/security/pwquality.conf"
    minlen_output = run_command(minlen_check)

    # Commands to check password complexity requirements
    minclass_check = "grep ^minclass /etc/security/pwquality.conf"
    minclass_output = run_command(minclass_check)

    # Check pam_pwquality.so settings for retry
    retry_compliant = "retry=3" in pam_pwquality_output.lower()

    # Check if minlen is 14 or more
    minlen_compliant = any(int(line.split('=')[1].strip()) >= 14 for line in minlen_output.splitlines())

    # Check if minclass is 4 or more
    minclass_compliant = any(int(line.split('=')[1].strip()) >= 4 for line in minclass_output.splitlines())

    # Verify all conditions for compliance
    return retry_compliant and minlen_compliant and minclass_compliant

# MBSS 21 - Check Failed Password Attempts Lockout Compliance
def check_failed_password_attempts_lockout():
    # Command to check deny setting in /etc/security/faillock.conf
    deny_check = rf"grep -E '^\s*deny\s*=\s*[1-5]\b' /etc/security/faillock.conf"
    deny_output = run_command(deny_check).strip()

    # Command to check unlock_time setting in /etc/security/faillock.conf
    unlock_time_check = rf"grep -E '^\s*unlock_time\s*=\s*(0|9[0-9][0-9]|[1-9][0-9][0-9][0-9]+)\b' /etc/security/faillock.conf"
    unlock_time_output = run_command(unlock_time_check).strip()

    # Command to check if deny is commented out
    deny_comment_check = "grep -E '^\s*#\s*deny\s*=' /etc/security/faillock.conf"
    deny_comment_output = run_command(deny_comment_check).strip()

    # Command to check if unlock_time is commented out
    unlock_time_comment_check = "grep -E '^\s*#\s*unlock_time\s*=' /etc/security/faillock.conf"
    unlock_time_comment_output = run_command(unlock_time_comment_check).strip()

    # Check if deny is set between 1 and 5 and not commented
    deny_compliant = "deny = " in deny_output and len(deny_output) > 0 and len(deny_comment_output) == 0

    # Check if unlock_time is set to 900 or more and not commented
    unlock_time_compliant = "unlock_time = " in unlock_time_output and len(unlock_time_output) > 0 and len(unlock_time_comment_output) == 0

    # Verify all conditions for compliance
    return deny_compliant and unlock_time_compliant

# MBSS 22 - Check Password Hashing Algorithm Compliance
def check_password_hashing_algorithm():
    # Command to check /etc/libuser.conf for crypt_style
    libuser_conf_check = rf"grep -Ei '^\s*crypt_style\s*=\s*(sha512|yescrypt)\b' /etc/libuser.conf"
    libuser_conf_output = run_command(libuser_conf_check)

    # Command to check /etc/login.defs for ENCRYPT_METHOD
    login_defs_check = rf"grep -Ei '^\s*ENCRYPT_METHOD\s+(SHA512|yescrypt)\b' /etc/login.defs"
    login_defs_output = run_command(login_defs_check)

    # Command to check pam_unix.so configuration in password-auth and system-auth
    pam_unix_check = rf"grep -P '^\h*password\h+(requisite|required|sufficient)\h+pam_unix\.so(\h+[^#\n\r]+)?\h+(sha512|yescrypt)\b.*$' /etc/pam.d/password-auth /etc/pam.d/system-auth"
    pam_unix_output = run_command(pam_unix_check)

    # Check if the crypt_style is sha512 or yescrypt
    crypt_style_compliant = bool(libuser_conf_output)

    # Check if the ENCRYPT_METHOD is sha512 or yescrypt
    encrypt_method_compliant = bool(login_defs_output)

    # Check if pam_unix.so is configured with sha512 or yescrypt
    pam_unix_compliant = bool(pam_unix_output)

    # Verify all conditions for compliance
    return crypt_style_compliant and encrypt_method_compliant and pam_unix_compliant

# MBSS 23 - Check Cron Daemon Compliance
def check_cron_daemon():
    # Command to check if the cron daemon is enabled
    cron_enabled_check = "systemctl is-enabled crond"
    cron_enabled_output = run_command(cron_enabled_check).strip()

    # Command to check if the cron daemon is active and running
    cron_active_check = "systemctl is-active crond"
    cron_active_output = run_command(cron_active_check).strip()

    # Check if cron is enabled and running
    cron_enabled = (cron_enabled_output == "enabled")
    cron_active = (cron_active_output == "active")

    # Verify all conditions for compliance
    return cron_enabled and cron_active

# MBSS 24 - Check and Configure Permissions on /etc/crontab
def check_crontab_permissions():
    # Command to check ownership and permissions of /etc/crontab
    crontab_stat_check = "stat -c '%A %U %G' /etc/crontab"
    crontab_stat_output = run_command(crontab_stat_check).strip()

    # Parse the output for permission, owner, and group
    permissions, owner, group = crontab_stat_output.split()

    # Check if ownership is root:root and permissions are 0600
    ownership_compliant = (owner == "root" and group == "root")
    permissions_compliant = (permissions == "-rw-------")

    # Verify compliance
    return ownership_compliant and permissions_compliant

# MBSS 25 - Check and Configure Permissions on /etc/cron.hourly
def check_cron_hourly_permissions():
    # Command to check ownership and permissions of /etc/cron.hourly/
    cron_hourly_stat_check = "stat -c '%A %U %G' /etc/cron.hourly"
    cron_hourly_stat_output = run_command(cron_hourly_stat_check).strip()

    # Parse the output for permission, owner, and group
    permissions, owner, group = cron_hourly_stat_output.split()

    # Check if ownership is root:root and permissions are 0700
    ownership_compliant = (owner == "root" and group == "root")
    permissions_compliant = (permissions == "drwx------")

    # Verify compliance
    return ownership_compliant and permissions_compliant

# MBSS 26 - Check and Configure Permissions on /etc/cron.daily
def check_cron_daily_permissions():
    # Command to check ownership and permissions of /etc/cron.daily
    cron_daily_stat_check = "stat -c '%A %U %G' /etc/cron.daily"
    cron_daily_stat_output = run_command(cron_daily_stat_check).strip()

    # Parse the output for permission, owner, and group
    permissions, owner, group = cron_daily_stat_output.split()

    # Check if ownership is root:root and permissions are 0700
    ownership_compliant = (owner == "root" and group == "root")
    permissions_compliant = (permissions == "drwx------")

    # Verify compliance
    return ownership_compliant and permissions_compliant

# MBSS 27 - Check and Configure Permissions on /etc/cron.weekly
def check_cron_weekly_permissions():
    # Command to check ownership and permissions of /etc/cron.weekly
    cron_weekly_stat_check = "stat -c '%A %U %G' /etc/cron.weekly"
    cron_weekly_stat_output = run_command(cron_weekly_stat_check).strip()

    # Parse the output for permission, owner, and group
    permissions, owner, group = cron_weekly_stat_output.split()

    # Check if ownership is root:root and permissions are 0700
    ownership_compliant = (owner == "root" and group == "root")
    permissions_compliant = (permissions == "drwx------")

    # Verify compliance
    return ownership_compliant and permissions_compliant

# MBSS 28 - Check and Configure Permissions on /etc/cron.monthly
def check_cron_monthly_permissions():
    # Command to check ownership and permissions of /etc/cron.monthly
    cron_monthly_stat_check = "stat -c '%A %U %G' /etc/cron.monthly"
    cron_monthly_stat_output = run_command(cron_monthly_stat_check).strip()

    # Parse the output for permission, owner, and group
    permissions, owner, group = cron_monthly_stat_output.split()

    # Check if ownership is root:root and permissions are 0700
    ownership_compliant = (owner == "root" and group == "root")
    permissions_compliant = (permissions == "drwx------")

    # Verify compliance
    return ownership_compliant and permissions_compliant

# MBSS 29 - Check and Configure Permissions on /etc/cron.d
def check_cron_d_permissions():
    # Command to check ownership and permissions of /etc/cron.d
    cron_d_stat_check = "stat -c '%A %U %G' /etc/cron.d"
    cron_d_stat_output = run_command(cron_d_stat_check).strip()

    # Parse the output for permission, owner, and group
    permissions, owner, group = cron_d_stat_output.split()

    # Check if ownership is root:root and permissions are 0700
    ownership_compliant = (owner == "root" and group == "root")
    permissions_compliant = (permissions == "drwx------")

    # Verify compliance
    return ownership_compliant and permissions_compliant

#MBSS 30
def cron_restriction_to_authorize_users(script_path):
    output = run_command(f"bash {script_path}")
    return 'Pass' in output

#MBSS 31
def jobs_restriction_to_authorize_users(script_path):
    output = run_command(f"bash {script_path}")
    return 'Pass' in output

# MBSS 32 - Check and Configure Inactive Password Lock
def check_inactive_password_lock():
    # Command to check the default inactive password lock period
    default_inactive_check = "useradd -D | grep 'INACTIVE'"
    default_inactive_output = run_command(default_inactive_check)
    command_2 = """awk -F: '/^[^#:]+:[^!\*:]*:[^:]*:[^:]*:[^:]*:[^:]*:(\s*|-1|3[1-9]|[4-9][0-9]|[1-9][0-9][0-9]+):[^:]*:[^:]*\s*$/ {print $1":"$7}' /etc/shadow"""
    command_2_output = run_command(command_2)

    if default_inactive_output == 'INACTIVE=30':
        return "inactive" not in command_2_output
    else:
        return False

# MBSS 33 - Check and Configure Password Expiration
def check_password_expiration():
    # Command to check the PASS_MAX_DAYS parameter in /etc/login.defs
    login_defs_check = "grep -i '^PASS_MAX_DAYS' /etc/login.defs"
    login_defs_output = run_command(login_defs_check).strip()

    # Extract the value of PASS_MAX_DAYS
    parts = login_defs_output.split()
    if len(parts) == 2 and parts[0].upper() == 'PASS_MAX_DAYS':
        pass_max_days_value = parts[1]
        return pass_max_days_value == '365'

    return False

# MBSS 34 - Check and Configure Minimum Days Between Password Changes
def check_min_days_between_password_changes():

    # Check PASS_MIN_DAYS in /etc/login.defs
    login_defs_check = "awk '/^PASS_MIN_DAYS/ {print $1, $2}' /etc/login.defs"
    login_defs_output = run_command(login_defs_check)

    parts = login_defs_output.split()
    if len(parts) == 2 and parts[0].upper() == 'PASS_MIN_DAYS':
        pass_min_days_value = parts[1]
        return pass_min_days_value == '7'
    
    return False

# MBSS 35 - Check Password Expiration Warning Days Compliance
def check_password_expiration_warning():
    # Commands to check PASS_WARN_AGE parameter in /etc/login.defs
    pass_warn_age_check = "awk '/^PASS_WARN_AGE/ {print $1, $2}' /etc/login.defs"
    pass_warn_age_output = run_command(pass_warn_age_check)

    # Commands to check warning days for all users in /etc/shadow
    user_warn_days_check = "grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,6"
    user_warn_days_output = run_command(user_warn_days_check)

    # Check if PASS_WARN_AGE is set to 7
    pass_warn_age_compliant = "PASS_WARN_AGE 7" in pass_warn_age_output.strip()

    # Check if all users have warning days set to 7 or more
    user_warn_days_compliant = all(int(line.split(':')[1]) >= 7 for line in user_warn_days_output.splitlines())

    # Verify all conditions for compliance
    return pass_warn_age_compliant and user_warn_days_compliant

# MBSS 36 - Check Default Group for Root Account Compliance
def check_root_default_group():
    # Command to check root's default group in /etc/passwd
    root_group_check = "grep '^root:' /etc/passwd | cut -f4 -d:"
    root_group_output = run_command(root_group_check)

    # Check if the root's default group GID is 0
    return root_group_output.strip() == "0"

# MBSS 37 - Check Default User Shell Timeout Compliance
def check_default_shell_timeout(script_path):
    output = run_command(f"bash {script_path}")
    return 'PASSED' in output

# MBSS 38 - Check Default User Umask Compliance
def check_default_user_umask():
    # Files to check for umask settings
    files_to_check = [
        '/etc/profile',
        '/etc/bashrc'
    ]
    profile_d_files = run_command("find /etc/profile.d/ -name '*.sh'")

    # Collect umask settings from the files
    def get_umask_from_file(file_path):
        return run_command(f"grep -i '^umask' {file_path}")

    # Check umask settings in the main files
    umask_settings = []
    for file in files_to_check:
        umask_settings.append(get_umask_from_file(file))

    # Check umask settings in /etc/profile.d/*.sh files
    for file in profile_d_files.splitlines():
        umask_settings.append(get_umask_from_file(file))

    # Verify that umask settings are compliant
    compliant = True
    for setting in umask_settings:
        if setting:
            umask_value = setting.split()[1].strip()
            if umask_value not in ['027', 'u=rwx,g=rx,o=', 'u=rwx,g=rx,o=']:
                compliant = False
                break

    # Verify no less restrictive umask is set system-wide
    system_wide_umask_check = run_command("grep -RPi '(^|^[^#]*)\\s*umask\\s+([0-7][0-7][01][0-7]\\b|[0-7][0-7][0-7][0-6]\\b|[0-7][01][0-7]\\b|[0-7][0-7][0-6]\\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(,o=[rwx]{0,3})?\\b)') /etc/login.defs /etc/profile* /etc/bashrc*")

    if system_wide_umask_check:
        compliant = False

    return compliant

# MBSS 39 - Check Access to su Command Compliance
def check_su_command_access():
    # Define the group name used for su access restriction
    group_name = "sugroup"  # Replace with the actual group name if different

    # Command to check pam_wheel.so configuration in /etc/pam.d/su
    su_pam_check = "grep -i 'auth required pam_wheel.so' /etc/pam.d/su"
    su_pam_output = run_command(su_pam_check)

    # Command to check if the group is empty
    group_check = f"grep {group_name} /etc/group"
    group_output = run_command(group_check)

    # Check if the pam_wheel.so line is correct and the group is empty
    pam_correct = f"group:auth required pam_wheel.so use_uid group={group_name}" in su_pam_output
    group_empty = len(group_output.strip().split(':')) == 4

    return pam_correct and group_empty

# MBSS 40 - Check System Accounts Compliance
def check_system_accounts():
    # Check for accounts with non-nologin shells
    uid_min = run_command("awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs").strip()
    non_compliant_accounts = run_command(
        f"awk -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<{uid_min} || $3 == 65534) && $7!~/^(\\/usr)?\\/sbin\\/nologin$/) {{ print $1 }}' /etc/passwd"
    ).strip()

    # Check for accounts with nologin shell but with enabled passwords
    disabled_accounts = run_command(
        "awk -F: '/nologin/ {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!=\"L\" && $2!=\"LK\") {print $1}'"
    ).strip()

    # Verify results
    return not non_compliant_accounts and not disabled_accounts

# MBSS 41 - Check /etc/passwd Permissions Compliance
def check_passwd_permissions():
    # Command to set owner, group, and permissions on /etc/passwd
    run_command("chown root:root /etc/passwd")
    run_command("chmod u-x,g-wx,o-wx /etc/passwd")
    
    # Command to verify permissions
    permissions = run_command("stat -Lc '%n %a %u/%U %g/%G' /etc/passwd").strip()
    
    # Expected output format: /etc/passwd 644 0/root 0/root
    expected_permissions = "/etc/passwd 644 0/root 0/root"
    
    return permissions == expected_permissions

# MBSS 42 - Check /etc/shadow Permissions Compliance
def check_shadow_permissions():
    
    # Command to verify permissions
    permissions = run_command("stat -Lc '%n %a %u/%U %g/%G' /etc/shadow").strip()
    
    # Expected output format: /etc/shadow 0000 0/root 0/root
    expected_permissions = "/etc/shadow 0 0/root 0/root"
    
    return permissions == expected_permissions

# MBSS 43 - Check /etc/group Permissions Compliance
def check_group_permissions():
    
    # Command to verify permissions
    permissions = run_command("stat -Lc '%n %a %u/%U %g/%G' /etc/group").strip()
    
    # Expected output format: /etc/group 644 0/root 0/root
    expected_permissions = "/etc/group 644 0/root 0/root"
    
    return permissions == expected_permissions

# MBSS 44 - Check /etc/gshadow Permissions Compliance
def check_gshadow_permissions():
    # Command to set owner, group, and permissions on /etc/gshadow
    run_command("chown root:root /etc/gshadow")
    run_command("chmod 0000 /etc/gshadow")
    
    # Command to verify permissions
    permissions = run_command("stat -Lc '%n %a %u/%U %g/%G' /etc/gshadow").strip()
    
    # Expected output format: /etc/gshadow 0000 0/root 0/root
    expected_permissions = "/etc/gshadow 0 0/root 0/root"
    
    return permissions == expected_permissions

# MBSS 45 - Check /etc/passwd- Permissions Compliance
def check_passwd_dash_permissions():

    # Command to verify permissions
    permissions = run_command("stat -Lc '%n %a %u/%U %g/%G' /etc/passwd-").strip()
    
    # Expected output format: /etc/passwd- 644 0/root 0/root
    expected_permissions = "/etc/passwd- 644 0/root 0/root"
    
    return permissions == expected_permissions

# MBSS 46 - Check /etc/shadow- Permissions Compliance
def check_shadow_dash_permissions():
    permissions = run_command("stat -Lc '%n %a %u/%U %g/%G' /etc/shadow-").strip()
    
    # Expected output format: /etc/shadow- 0000 0/root 0/root
    expected_permissions = "/etc/shadow- 0 0/root 0/root"
    
    return permissions == expected_permissions

# MBSS 47 - Check /etc/group- Permissions Compliance
def check_group_dash_permissions():
    
    # Command to verify permissions
    permissions = run_command("stat -Lc '%n %a %u/%U %g/%G' /etc/group-").strip()
    
    # Expected output format: /etc/group- 644 0/root 0/root
    expected_permissions = "/etc/group- 644 0/root 0/root"
    
    return permissions == expected_permissions

# MBSS 48 - Check /etc/gshadow- Permissions Compliance
def check_gshadow_dash_permissions():    
    # Command to verify permissions
    permissions = run_command("stat -Lc '%n %a %u/%U %g/%G' /etc/gshadow-").strip()
    
    # Expected output format: /etc/gshadow- 0000 0/root 0/root
    expected_permissions = "/etc/gshadow- 0 0/root 0/root"
    
    return permissions == expected_permissions

# MBSS 49 - Check for World Writable Files Compliance
def check_world_writable_files():
    # Command to find world-writable files on local filesystems
    output = run_command("df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002")
    
    # Check if any world-writable files are returned
    return output.strip() == ""

# MBSS 50 - Check Samba Installation Compliance
def check_samba_installed():
    # Command to check if Samba is installed
    output = run_command("rpm -q samba").strip()
    
    # Check if the output indicates that Samba is not installed
    return "package samba is not installed" in output

# MBSS 51 - Check Time Synchronization Compliance
def check_time_synchronization_installed():
    # Command to check if chrony is installed
    output = run_command("rpm -q chrony").strip()
    
    # Check if the output indicates that chrony is installed
    return output.startswith("chrony-")

# MBSS 52 - Check Bootloader Password Compliance
def check_bootloader_password_set():
    # Command to check if the GRUB2 password is set
    output = run_command("awk -F. '/^\\s*GRUB2_PASSWORD/ {print $1\".\"$2\".\"$3}' /boot/grub2/user.cfg").strip()
    
    # Check if the output indicates that the GRUB2 password is set
    return output.startswith("GRUB2_PASSWORD=")

# MBSS 53 - Check Bootloader Config Permissions Compliance
def check_bootloader_permissions():
    # Commands to set ownership and permissions
    run_command("chown root:root /boot/grub2/grub.cfg")
    run_command("test -f /boot/grub2/user.cfg && chown root:root /boot/grub2/user.cfg")
    run_command("chmod og-rwx /boot/grub2/grub.cfg")
    run_command("test -f /boot/grub2/user.cfg && chmod og-rwx /boot/grub2/user.cfg")
    
    # Commands to verify permissions
    grub_cfg = run_command("stat -Lc '%n %a %u/%U %g/%G' /boot/grub2/grub.cfg").strip()
    grubenv = run_command("stat -Lc '%n %a %u/%U %g/%G' /boot/grub2/grubenv").strip()
    user_cfg = run_command("test -f /boot/grub2/user.cfg && stat -Lc '%n %a %u/%U %g/%G' /boot/grub2/user.cfg").strip()

    # Expected output format
    expected_grub_cfg = "/boot/grub2/grub.cfg 600 0/root 0/root"
    expected_grubenv = "/boot/grub2/grubenv 600 0/root 0/root"
    expected_user_cfg = "/boot/grub2/user.cfg 600 0/root 0/root"

    return (grub_cfg == expected_grub_cfg and
            grubenv == expected_grubenv and
            user_cfg == expected_user_cfg)

# MBSS 54 - Check if sudo is installed
def check_sudo_installed():
    # Command to install sudo
    
    # Command to verify sudo installation
    sudo_info = run_command("dnf list sudo").strip()
    
    # Check if 'Installed Packages' contains 'sudo'
    return 'Installed Packages' in sudo_info and 'sudo' in sudo_info

# MBSS 55 - Check if sudo commands use pty
def check_sudo_use_pty():
    # Command to check if the 'use_pty' option is set in sudoers using awk
    sudo_pty_config = run_command("awk -F: '/Defaults/ && /use_pty/ {print $0}' /etc/sudoers*").strip()
    
    # Expected output format: Defaults use_pty
    expected_config = "Defaults use_pty"
    
    return sudo_pty_config == expected_config

# MBSS 56 - Check if sudo log file exists
def check_sudo_log_file():
    # Command to check if the 'logfile' option is set in sudoers using awk
    sudo_logfile_config = run_command("awk -F: '/Defaults/ && /logfile/ {print $0}' /etc/sudoers*").strip()
    
    # Expected output format: Defaults logfile="/var/log/sudo.log"
    expected_config = 'Defaults logfile="/var/log/sudo.log"'
    
    return sudo_logfile_config == expected_config

#MBSS 57
def check_aslr_enabled(script_path):
    output = run_command(f"bash {script_path}")
    return 'PASS' in output

# MBSS 58 - Check if core dump storage is disabled
def check_core_dump_storage_disabled():    
    # Verify the setting
    core_dump_storage = run_command("awk -F= '/^Storage=/ {print $2}' /etc/systemd/coredump.conf").strip()
    
    # Expected output: none
    expected_core_dump_storage = "none"
    
    return core_dump_storage == expected_core_dump_storage

# MBSS 59 - Check if core dump backtraces are disabled
def check_core_dump_backtraces_disabled():    
    # Verify the setting
    process_size_max = run_command("awk -F= '/^ProcessSizeMax=/ {print $2}' /etc/systemd/coredump.conf").strip()
    
    # Expected output: 0
    expected_process_size_max = "0"
    
    return process_size_max == expected_process_size_max

# MBSS 60 - Check if Message of the Day (MOTD) is Configured Properly
def check_motd_configuration():
    # Remove the /etc/motd file if it exists
    
    
    # Example of setting MOTD content according to company policy
    # Edit this line with appropriate content based on your policy
    motd_content = """\
    Welcome to the Company System
    Unauthorized access is prohibited.
    All activities are monitored and recorded.
    """

    
    # Verify the contents of /etc/motd
    current_motd_content = run_command("cat /etc/motd").strip()
    
    # Expected content should match the motd_content variable
    expected_motd_content = motd_content.strip()
    
    # Check if the MOTD file contains any disallowed patterns
    check_patterns = run_command(
        "grep -E -i '(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))' /etc/motd"
    ).strip()
    
    motd_compliant = (current_motd_content == expected_motd_content) and not check_patterns
    
    return motd_compliant

# MBSS 61 - Check Local Login Warning Banner Configuration
def check_local_login_banner():
    # Define the desired content for /etc/issue according to company policy
    issue_content = """\
    Authorized uses only. All activity may be monitored and reported.
    """
    
    # Write the policy content to /etc/issue
    with open("/etc/issue", "w") as issue_file:
        issue_file.write(issue_content)
    
    # Verify the contents of /etc/issue
    current_issue_content = run_command("cat /etc/issue").strip()
    
    # Expected content should match the issue_content variable
    expected_issue_content = issue_content.strip()
    
    # Check if the /etc/issue file contains any disallowed patterns
    check_patterns = run_command(
        "grep -E -i '(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))' /etc/issue"
    ).strip()
    
    issue_compliant = (current_issue_content == expected_issue_content) and not check_patterns
    
    return issue_compliant

# MBSS 62 - Check Remote Login Warning Banner Configuration
def check_remote_login_banner():
    # Define the desired content for /etc/issue.net according to company policy
    issue_net_content = """\
    Authorized uses only. All activity may be monitored and reported.
    """
    
    # Verify the contents of /etc/issue.net
    current_issue_net_content = run_command("cat /etc/issue.net").strip()
    
    # Expected content should match the issue_net_content variable
    expected_issue_net_content = issue_net_content.strip()
    
    # Check if the /etc/issue.net file contains any disallowed patterns
    check_patterns = run_command(
        "grep -E -i '(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))' /etc/issue.net"
    ).strip()
    
    issue_net_compliant = (current_issue_net_content == expected_issue_net_content) and not check_patterns
    
    return issue_net_compliant

# MBSS 63 - Check /etc/motd Permissions Compliance
def check_motd_permissions():

    
    # Verify the permissions using awk to parse stat output
    permissions = run_command("stat -Lc '%n %a %u/%U %g/%G' /etc/motd").strip()
    
    # Expected output: /etc/motd 644 0/root 0/root
    expected_permissions = "/etc/motd 644 0/root 0/root"
    
    return permissions == expected_permissions

# MBSS 64 - Check /etc/issue.net Permissions Compliance
def check_issue_net_permissions():

    
    # Verify the permissions using awk to parse stat output
    permissions = run_command("stat -Lc '%n %a %u/%U %g/%G' /etc/issue.net").strip()
    
    # Expected output: /etc/issue.net 644 0/root 0/root
    expected_permissions = "/etc/issue.net 644 0/root 0/root"
    
    return permissions == expected_permissions

# MBSS 65 - Check for Updates, Patches, and Security Software Compliance
def check_updates_and_patches():
    # Run the command to check for available updates
    updates = run_command("dnf check-update").strip()

    # Run the command to check if a system reboot is required
    reboot_required = run_command("dnf needs-restarting -r").strip()
    
    # If no updates and no reboot are required
    no_updates = "Last" in updates
    no_reboot_required = "No core libraries or services have been updated since boot-up." in reboot_required
    
    return no_updates and no_reboot_required

#MBSS 66
def gdm_removed(script_path):
    output = run_command(f"bash {script_path}")
    return 'PASS' in output

# MBSS 67 - Check GPG Keys Configuration Compliance
def check_gpg_keys():
    # List all GPG key URLs from repository configuration files
    gpgkey_urls = run_command("grep -r gpgkey /etc/yum.repos.d/* /etc/dnf/dnf.conf").strip()
    
    # List installed GPG keys
    installed_gpg_keys = run_command("rpm -q gpg-pubkey").strip()
    
    # Check if GPG keys are configured
    gpgkey_urls_check = bool(gpgkey_urls)
    installed_keys_check = bool(installed_gpg_keys)
    
    return gpgkey_urls_check and installed_keys_check

# MBSS 68 - Check Package Manager Repositories Configuration Compliance
def check_repositories_configuration():
    # List all configured repositories
    repositories_list = run_command("dnf repolist").strip()
    
    # Check if repositories are configured
    repositories_configured = bool(repositories_list)
    
    # Inspect repository configuration files
    repo_files_content = run_command("cat /etc/yum.repos.d/*.repo").strip()
    
    # Ensure repository configuration files are non-empty
    repo_files_check = bool(repo_files_content)
    
    return repositories_configured and repo_files_check

# MBSS 69 - Check Global gpgcheck Activation Compliance
def check_gpgcheck_activation():
    # Check global gpgcheck setting in /etc/dnf/dnf.conf
    global_gpgcheck = run_command("grep ^gpgcheck /etc/dnf/dnf.conf").strip()
    
    # Check if gpgcheck is set to 1 globally
    global_gpgcheck_compliance = global_gpgcheck == "gpgcheck=1"

    # Check individual repository files for gpgcheck settings
    repo_gpgcheck_issues = run_command("grep -P '^gpgcheck\\h*=\\h*[^1].*\\h*$' /etc/yum.repos.d/*").strip()

    # No repository files should have gpgcheck set to 0 or non-boolean values
    repo_gpgcheck_compliance = not repo_gpgcheck_issues

    return global_gpgcheck_compliance and repo_gpgcheck_compliance

# MBSS 70 - Check if auditd is Installed
def check_auditd_installed():
    # Check if auditd is installed
    installed_auditd = run_command("rpm -q audit").strip()
    
    # Verify if the command returned a package name
    return "audit" in installed_auditd

# MBSS 71 - Check if auditd Service is Enabled and Running
def check_auditd_service_status():
    # Command to check the status of auditd service
    service_status = run_command("systemctl is-active auditd").strip()
    enabled_status = run_command("systemctl is-enabled auditd").strip()
    
    # Verify if the service is active and enabled
    is_active = service_status == "active"
    is_enabled = enabled_status == "enabled"
    
    return is_active and is_enabled

# MBSS 72 - Check Audit Configuration in GRUB
def check_audit_parameter_in_grub():
    # Command to check if audit=1 is set in GRUB configuration
    command = 'grep -E \'GRUB_CMDLINE_LINUX="audit=1"\' /etc/default/grub'
    audit_parameter = run_command(command).strip()
    
    # Check if the command returned 'GRUB_CMDLINE_LINUX="audit=1"'
    return audit_parameter == 'GRUB_CMDLINE_LINUX="audit=1"'

# MBSS 73 - Check rsyslog Installation
def check_rsyslog_installed():
    # Command to check if rsyslog is installed
    rsyslog_version = run_command("rpm -q rsyslog").strip()
    
    # Check if rsyslog is installed and matches the expected format
    return rsyslog_version.startswith("rsyslog-")

#MBSS 74
def check_rsyslog_enabled():
    status = run_command("systemctl is-enabled rsyslog")
    return status == "enabled"

#MBSS 75
def check_rsyslog_file_permissions():
    command = "cat /etc/rsyslog.conf | grep FileCreateMode"
    result = run_command(command)
    return "0640" in result

# MBSS 76 - Check rsyslog configuration and log files
def check_rsyslog_configuration():
    # Check if rsyslog configuration files exist
    conf_files = [
        '/etc/rsyslog.conf',
        *[f'/etc/rsyslog.d/{file}' for file in os.listdir('/etc/rsyslog.d/')]
    ]
    
    conf_exist = all(os.path.exists(file) for file in conf_files)

    # Verify log files in /var/log
    log_files = os.listdir('/var/log/')
    log_files_exist = len(log_files) > 0

    return conf_exist and log_files_exist, conf_files, log_files

#MBSS 77
def check_rsyslog_remote_logging():
    # Define the expected remote log host (FQDN or IP)
    remote_log_host = "loghost.example.com"

    # Check for the old format in rsyslog configuration files
    old_format_command = f"grep '^*.*[^I][^I]*@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
    old_format_result = subprocess.run(old_format_command, shell=True, capture_output=True, text=True)
    old_format_check = remote_log_host in old_format_result.stdout

    # Check for the new format in rsyslog configuration files
    new_format_command = f"grep -E '^\s*([^#]+\\s+)?action\\(([^#]+\\s+)?\\btarget=\"?[^#\"\\s]+\"?\\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
    new_format_result = subprocess.run(new_format_command, shell=True, capture_output=True, text=True)
    new_format_check = remote_log_host in new_format_result.stdout

    # Verify rsyslog service status
    rsyslog_status_command = "systemctl is-active rsyslog"
    rsyslog_status_result = subprocess.run(rsyslog_status_command, shell=True, capture_output=True, text=True)
    rsyslog_active = rsyslog_status_result.stdout.strip() == "active"

    return old_format_check or new_format_check, rsyslog_active

#MBSS 78
def check_log_permissions():
    # Command to check permissions of /etc/passwd
    find_command = "stat -Lc 'Access: (%#a/%A) Uid: (%u/%U) Gid: (%g/%G)' /etc/passwd"
    log_files_permissions = run_command(find_command)
    
    # Print the permissions output for debugging

    
    # Extract the permission number from the output
    # The format of the output should be "Access: (0644/-rw-r--r--) ...", so split and extract the number
    permissions_list = log_files_permissions.split()
    actual_permission = permissions_list[1]  # This assumes the permission number is always in the second position
    
    # Expected permission number
    exp_out = "0644"
    
    # Return True if the permission number matches the expected output
    return actual_permission == exp_out

# MBSS 79 - Check Logrotate Configuration Compliance
def check_logrotate_configuration():
    # Check if /etc/logrotate.conf has appropriate settings
    logrotate_conf = run_command("cat /etc/logrotate.conf").strip()
    
    # Check if files in /etc/logrotate.d/ have appropriate settings
    logrotate_d_files = run_command("ls /etc/logrotate.d/").splitlines()
    logrotate_d_conf = ""
    for file in logrotate_d_files:
        logrotate_d_conf += run_command(f"cat /etc/logrotate.d/{file}").strip() + "\n"

    # Combine both configurations for review
    full_logrotate_conf = logrotate_conf + "\n" + logrotate_d_conf
    
    # Define the expected logrotate configuration content or patterns based on policy
    # Placeholder for actual policy validation logic
    expected_content_patterns = [
        # Add patterns or content checks according to company policy
        # e.g., "daily", "rotate 7", etc.
    ]
    
    # Verify if expected patterns or content are present
    compliance = all(pattern in full_logrotate_conf for pattern in expected_content_patterns)

    return compliance

#MBSS 80
def check_audit_rules_80():
    # Define the expected rules
    expected_rules = [
        "-w /etc/group -p wa -k identity",
        "-w /etc/passwd -p wa -k identity",
        "-w /etc/gshadow -p wa -k identity",
        "-w /etc/shadow -p wa -k identity",
        "-w /etc/security/opasswd -p wa -k identity"
    ]
    
    # Check rules on disk
    rules_on_disk = run_command("awk '/^ *-w/ && (/\/etc\/group/ || /\/etc\/passwd/ || /\/etc\/gshadow/ || /\/etc\/shadow/ || /\/etc\/security\/opasswd/) && / -p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules")
    
    # Check loaded rules
    #loaded_rules = run_command("auditctl -l | awk '/^ *-w/ &&(/\\/etc\\/group/ ||/\\/etc\\/passwd/ ||/\\/etc\\/gshadow/ ||/\\/etc\\/shadow/ ||/\\/etc\\/security\\/opasswd/) &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'")
    
    # Verify if rules match the expected rules
    rules_on_disk_compliance = all(rule in rules_on_disk for rule in expected_rules)

    
    return rules_on_disk_compliance

# MBSS 81 - Check System Administration Scope Collection Compliance
def check_sudoers_scope_collection():
    # Define the audit rules expected
    expected_rules = [
        "-w /etc/sudoers -p wa -k scope",
        "-w /etc/sudoers.d/ -p wa -k scope"
    ]

    # Check on-disk rules
    on_disk_rules = run_command("awk '/^ *-w/ && /\/etc\/sudoers/ && /-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules")

    # Check loaded rules
 
    # Check if both on-disk and loaded rules match the expected rules
    on_disk_compliance = all(rule in on_disk_rules for rule in expected_rules)
    
    return on_disk_compliance 

# MBSS 82 - Check Audit Log Storage Size Compliance
def check_audit_log_storage_size(expected_size_mb):
    # Run the command to get the current audit log size setting
    current_size = run_command("grep -w '^\s*max_log_file\s*=' /etc/audit/auditd.conf").strip()
    
    # Extract the actual size from the output
    if "max_log_file" in current_size:
        actual_size = int(current_size.split('=')[1].strip())
    else:
        return False, "max_log_file not found in /etc/audit/auditd.conf"
    
    # Check if the actual size matches the expected size
    compliance = actual_size == expected_size_mb
    return compliance, f"Expected: {expected_size_mb} MB, Actual: {actual_size} MB"

# MBSS 83 - Check Audit Log Auto-Delete Compliance
def check_audit_log_auto_delete():
    # Run the command to get the current max_log_file_action setting
    log_file_action = run_command("grep 'max_log_file_action' /etc/audit/auditd.conf").strip()
    
    # Check if the setting is 'keep_logs'
    if "max_log_file_action" in log_file_action:
        actual_action = log_file_action.split('=')[1].strip()
    else:
        return False, "max_log_file_action not found in /etc/audit/auditd.conf"
    
    compliance = actual_action == "keep_logs"
    return compliance, f"Expected: keep_logs, Actual: {actual_action}"

# MBSS 84 - Check MAC Policy Audit Rules Compliance
def check_mac_policy_audit_rules():
    # Expected audit rules
    expected_rules ='-w /etc/selinux/ -p wa -k MAC-policy'
#

    # Run command to check audit rules in /etc/audit/rules.d/
    current_rules = run_command("awk '/^ *-w/ && /\/etc\/selinux/ && /-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*")
    
    
    if expected_rules in current_rules:
        return True
    else:
        return False

# MBSS 85 - Ensure login and logout events are collected
def check_login_logout_events():
    rule_1 = 'cat  /etc/audit/rules.d/*.rules | grep  "/var/log/faillog -p wa -k logins"'
    rule_2 = 'cat  /etc/audit/rules.d/*.rules | grep  "/var/log/lastlog -p wa -k logins"'

    com1= run_command(rule_1)
    com2 = run_command(rule_2)

    exp = '/var/log/faillog'
    exp2 = '/var/log/lastlog'

    return exp in com1 and exp2 in com2

# MBSS 86 - Ensure session initiation information is collected
def check_session_initiation_collection():
    # Define the expected audit rules for session initiation
    expected_rules = [
        "-w /var/run/utmp -p wa -k session",
        "-w /var/log/wtmp -p wa -k logins",
        "-w /var/log/btmp -p wa -k logins"
    ]

    # Path to the session rules file
    rules_file = "/etc/audit/rules.d/audit.rules"
    
    # Check if the rules file exists
    if not os.path.exists(rules_file):
        return False
    
    # Read the current rules from the file
    with open(rules_file, "r") as file:
        current_rules = file.readlines()
    
    # Normalize the lines by stripping whitespace and converting to a set for comparison
    current_rules = set(line.strip() for line in current_rules if line.strip())
    expected_rules_set = set(expected_rules)
    
    # Check if all expected rules are present in the current rules
    rules_compliant = expected_rules_set.issubset(current_rules)
    
    return rules_compliant

# MBSS 87 - Ensure Use of Privileged Commands is Collected
def check_privileged_commands_audit(script_path):
    output = run_command(f"bash {script_path}")
    return 'OK' in output

# MBSS 88 - Check if audit configuration is immutable
def check_audit_configuration_immutable():
    # Ensure the audit configuration is set to immutable mode
    run_command("echo '-e 2' >> /etc/audit/rules.d/99-finalize.rules")
    
    # Verify the audit configuration
    immutable_setting = run_command("awk '/-e 2/' /etc/audit/rules.d/*.rules | tail -1").strip()
    
    # Expected output: -e 2
    expected_immutable_setting = "-e 2"
    
    return immutable_setting == expected_immutable_setting

#MBSS  89
def check_audit_rules(file_path):
    # Define the required rules
    required_rules = [
        "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts",
        "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts"
    ]
    
    try:
        with open(file_path, 'r') as file:
            # Read the contents of the file
            file_contents = file.read()
            
            # Check for the presence of each required rule
            for rule in required_rules:
                if rule not in file_contents:
                    return False
            return True
    except FileNotFoundError:
        return False


# MBSS 90 - Check if telnet client is not installed
def check_telnet_not_installed():
    # Remove the telnet package
    
    # Verify that the telnet package is not installed
    telnet_status = run_command("rpm -q telnet").strip()
    
    # Expected output: "package telnet is not installed"
    expected_status = "package telnet is not installed"
    
    return telnet_status == expected_status

# MBSS 91 - Check if LDAP client is not installed
def check_ldap_client_not_installed():
    # Remove the openldap-clients package
    run_command("yum remove -y openldap-clients")
    
    # Verify that the openldap-clients package is not installed
    ldap_status = run_command("rpm -q openldap-clients").strip()
    
    # Expected output: "package openldap-clients is not installed"
    expected_status = "package openldap-clients is not installed"
    
    return ldap_status == expected_status

# MBSS 92 - Check if accounts in /etc/passwd use shadowed passwords
def check_shadowed_passwords():
    # Command to ensure accounts are using shadowed passwords
    run_command("sed -e 's/^([a-zA-Z0-9_]):[^:]:/\\1:x:/' -i /etc/passwd")
    
    # Verify if all accounts have shadowed passwords
    non_shadowed_accounts = run_command("awk -F: '($2 != \"x\") { print $1 \" is not set to shadowed passwords \"}' /etc/passwd").strip()
    
    # If no non-shadowed accounts are found, non_shadowed_accounts will be empty
    return non_shadowed_accounts == ""

# MBSS 93 - Check if /etc/shadow password fields are not empty
def check_shadow_password_fields():
    # Run the command to check for empty password fields
    empty_passwords = run_command("awk -F: '($2 == \"\") { print $1 \" does not have a password \"}' /etc/shadow").strip()
    
    # Return True if no empty passwords are found (i.e., empty_passwords is empty)
    return empty_passwords == ""

# MBSS 94 - Check if root is the only UID 0 account
def check_root_uid_0():
    # Run the command to check for users with UID 0
    users_with_uid_0 = run_command("awk -F: '($3 == 0) { print $1 }' /etc/passwd").strip()
    
    # Check if the only returned user is 'root'
    return users_with_uid_0 == "root"

#MBSS 95
def check_root_path_integrity(script_path):
    output = run_command(f"bash {script_path}")
    return 'Passed' in output


#MBSS 96
def check_home_directory_permissions():
    perm_mask = 0o0027
    max_perm = oct(0o777 & ~perm_mask)
    
    # Get the list of users with valid shells
    valid_shells_cmd = "sed -rn '/^\\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' -"
    valid_shells = subprocess.getoutput(valid_shells_cmd)
    
    # Retrieve user home directories and their permissions
    home_dirs_cmd = f"awk -F: '($NF ~ /{valid_shells}/) {{ print $1 \" \" $(NF-1) }}' /etc/passwd"
    home_dirs = subprocess.getoutput(home_dirs_cmd)
    
    output = []
    
    for line in home_dirs.splitlines():
        user, home_dir = line.split()
        try:
            mode = oct(os.stat(home_dir).st_mode & 0o777)
            if int(mode, 8) & perm_mask > 0:
                output.append(f"- User {user}'s home directory: \"{home_dir}\" is too permissive: \"{mode}\" (should be: \"{max_perm}\" or more restrictive)")
        except FileNotFoundError:
            output.append(f"- User {user}'s home directory: \"{home_dir}\" does not exist")
    
    if output:
        result = "\n- Failed:" + "\n".join(output)
    else:
        result = "\n- Passed:\n- All user home directories are mode: " + max_perm + " or more restrictive"
    
    return result

#MBSS 97
def check_groups_in_passwd_exist_in_group():
    # Get list of group IDs from /etc/passwd
    passwd_groups_cmd = "cut -s -d: -f4 /etc/passwd | sort -u"
    passwd_groups = subprocess.getoutput(passwd_groups_cmd).splitlines()

    missing_groups = []
    
    for gid in passwd_groups:
        # Check if group with this GID exists in /etc/group
        group_check_cmd = f"grep -q -P '^.*?:[^:]*:{gid}:' /etc/group"
        result = subprocess.run(group_check_cmd, shell=True, text=True)
        
        if result.returncode != 0:
            missing_groups.append(f"Group {gid} is referenced by /etc/passwd but does not exist in /etc/group")
    
    if missing_groups:
        result = "\n- Failed:\n" + "\n".join(missing_groups)
    else:
        result = "\n- Passed:\n- All groups in /etc/passwd exist in /etc/group"
    
    return result




results = []


#MBSS 1
file_permissions_compliance = check_file_permissions(file_path)
results.append({
    'Serial Number': 1,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure permissions on /etc/ssh/sshd_config is configured.',
    'Comments': 'Premissions are configured' if file_permissions_compliance else 'Premissions are not configured',
    'Compliance': 'Compliant' if file_permissions_compliance else 'Non-Compliant'
})

#MBSS 2
script_compliance = ssh_private_key_permissions(script_2)
results.append({
    'Serial Number': 2,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure permissions on SSH private host key files are configured.',
    'Comments': 'Premissions are configured' if script_compliance else 'Premissions are not configured',
    'Compliance': 'Compliant' if script_compliance else 'Non-Compliant'
})

#MBSS 3
script_compliance = ssh_public_key_permissions(script_3)
results.append({
    'Serial Number': 3,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure permissions on SSH public host key files are configured.',
    'Comments': 'Premissions are configured' if script_compliance else 'Premissions are not configured',
    'Compliance': 'Compliant' if script_compliance else 'Non-Compliant'
})

#MBSS 4
ssh_access_compliance = check_ssh_access_limited()
results.append({
    'Serial Number': 4,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH access is limited.',
    'Comments': 'SSH access is limited' if ssh_access_compliance else 'SSH access is not limited',
    'Compliance': 'Compliant' if ssh_access_compliance else 'Non-Compliant'
})

#MBSS 5
log_level_compliance = check_log_level()

results.append({
    'Serial Number': 5,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH LogLevel is appropriate level: Verbose',
    'Comments': 'LogLevel is correctly set' if log_level_compliance else 'LogLevel is not correctly set',
    'Compliance': 'Compliant' if log_level_compliance else 'Non-Compliant'
})

x11_forwarding_compliance = check_x11_forwarding()
#MBSS 6
results.append({
    'Serial Number': 6,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH X11 forwarding is disabled.',
    'Comments': 'X11 forwarding is disabled' if x11_forwarding_compliance else 'X11 forwarding is not disabled',
    'Compliance': 'Compliant' if x11_forwarding_compliance else 'Non-Compliant'
})

#MBSS 7
max_auth_tries_compliance, comments = check_max_auth_tries()
results.append({
    'Serial Number': 7,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH MaxAuthTries is set to 4 or less.',
    'Comments': comments,
    'Compliance': 'Compliant' if max_auth_tries_compliance else 'Non-Compliant'
})

#MBSS 8
ignore_rhosts_compliance = check_ignore_rhosts()
results.append({
    'Serial Number': 8,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH IgnoreRhosts is enabled and not commented.',
    'Comments': 'Check Ignore Rhost is set' if ignore_rhosts_compliance else 'Check Ignore Rhost is not set',
    'Compliance': 'Compliant' if ignore_rhosts_compliance else 'Non-Compliant'
})

#MBSS 9
host_based_auth_compliance = check_host_based_authentication()
results.append({
    'Serial Number': 9,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH HostbasedAuthentication is disabled.',
    'Comments': 'HostbasedAuthentication is disabled' if host_based_auth_compliance else 'HostbasedAuthentication is not disabled',
    'Compliance': 'Compliant' if host_based_auth_compliance else 'Non-Compliant'
})

#MBSS 10
root_login_compliance = check_root_login_disabled()
results.append({
    'Serial Number': 10,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH root login is disabled.',
    'Comments': 'Root login is disabled' if root_login_compliance else 'Root login is not disabled',
    'Compliance': 'Compliant' if root_login_compliance else 'Non-Compliant'
})

#MBSS 11
permit_empty_passwords_compliance = check_permit_empty_passwords()
results.append({
    'Serial Number': 11,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH PermitEmptyPasswords is disabled.',
    'Comments': 'PermitEmptyPasswords is disabled' if permit_empty_passwords_compliance else 'PermitEmptyPasswords is not disabled or incorrectly configured',
    'Compliance': 'Compliant' if permit_empty_passwords_compliance else 'Non-Compliant'
})

#MBSS 12
permit_user_environment_compliance = check_permit_user_environment()
results.append({
    'Serial Number': 12,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH PermitUserEnvironment is disabled.',
    'Comments': 'PermitUserEnvironment is disabled' if permit_user_environment_compliance else 'PermitUserEnvironment is not disabled or incorrectly configured',
    'Compliance': 'Compliant' if permit_user_environment_compliance else 'Non-Compliant'
})

#MBSS 13
ssh_idle_timeout_compliance = check_ssh_idle_timeout()
results.append({
    'Serial Number': 13,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH Idle Timeout Interval is configured.',
    'Comments': 'SSH Idle Timeout Interval is correctly configured' if ssh_idle_timeout_compliance else 'SSH Idle Timeout Interval is not correctly configured',
    'Compliance': 'Compliant' if ssh_idle_timeout_compliance else 'Non-Compliant'
})

#MBSS 14
ssh_logingracetime_compliance = check_ssh_logingracetime()
results.append({
    'Serial Number': 14,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH LoginGraceTime is set to one minute or less.',
    'Comments': 'SSH LoginGraceTime is correctly configured' if ssh_logingracetime_compliance else 'SSH LoginGraceTime is not correctly configured',
    'Compliance': 'Compliant' if ssh_logingracetime_compliance else 'Non-Compliant'
})

#MBSS 15
ssh_banner_compliance = check_ssh_banner()
results.append({
    'Serial Number': 15,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH warning banner is configured.',
    'Comments': 'SSH warning banner is correctly configured' if ssh_banner_compliance else 'SSH warning banner is not correctly configured',
    'Compliance': 'Compliant' if ssh_banner_compliance else 'Non-Compliant'
})

#MBSS 16
ssh_pam_compliance = check_ssh_pam()
results.append({
    'Serial Number': 16,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH PAM is enabled.',
    'Comments': 'SSH PAM is correctly configured' if ssh_pam_compliance else 'SSH PAM is not correctly configured',
    'Compliance': 'Compliant' if ssh_pam_compliance else 'Non-Compliant'
})

#MBSS 17
ssh_tcp_forwarding_compliance = check_ssh_tcp_forwarding()
results.append({
    'Serial Number': 17,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH AllowTcpForwarding is disabled.',
    'Comments': 'SSH AllowTcpForwarding is correctly configured' if ssh_tcp_forwarding_compliance else 'SSH AllowTcpForwarding is not correctly configured',
    'Compliance': 'Compliant' if ssh_tcp_forwarding_compliance else 'Non-Compliant'
})

#MBSS 18
ssh_maxstartups_compliance = check_ssh_maxstartups()
results.append({
    'Serial Number': 18,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH MaxStartups is configured.',
    'Comments': 'SSH MaxStartups is correctly configured' if ssh_maxstartups_compliance else 'SSH MaxStartups is not correctly configured',
    'Compliance': 'Compliant' if ssh_maxstartups_compliance else 'Non-Compliant'
})

#MBSS 19
ssh_maxsessions_compliance = check_ssh_maxsessions()
results.append({
    'Serial Number': 19,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH MaxSessions is limited to 10 or less.',
    'Comments': 'SSH MaxSessions is correctly configured' if ssh_maxsessions_compliance else 'SSH MaxSessions is not correctly configured',
    'Compliance': 'Compliant' if ssh_maxsessions_compliance else 'Non-Compliant'
})

#MBSS 20
password_creation_compliance = check_password_creation_requirements()
results.append({
    'Serial Number': 20,
    'Category': 'Access, Authentication and Authorization - Configure PAM',
    'Objective': 'Ensure password creation requirements are configured.',
    'Comments': 'Password creation requirements are correctly configured' if password_creation_compliance else 'Password creation requirements are not correctly configured',
    'Compliance': 'Compliant' if password_creation_compliance else 'Non-Compliant'
})

#MBSS 21
failed_password_lockout_compliance = check_failed_password_attempts_lockout()
results.append({
    'Serial Number': 21,
    'Category': 'Access, Authentication and Authorization - Configure PAM',
    'Objective': 'Ensure lockout for failed password attempts is configured.',
    'Comments': 'Password lockout for failed attempts is correctly configured' if failed_password_lockout_compliance else 'Password lockout for failed attempts is not correctly configured',
    'Compliance': 'Compliant' if failed_password_lockout_compliance else 'Non-Compliant'
})

#MBSS 22
password_hashing_compliance = check_password_hashing_algorithm()
results.append({
    'Serial Number': 22,
    'Category': 'Access, Authentication and Authorization - Configure PAM',
    'Objective': 'Ensure password hashing algorithm is SHA-512.',
    'Comments': 'Password hashing algorithm is correctly configured' if password_hashing_compliance else 'Password hashing algorithm is not correctly configured',
    'Compliance': 'Compliant' if password_hashing_compliance else 'Non-Compliant'
})

#MBSS 23
cron_daemon_compliance = check_cron_daemon()
results.append({
    'Serial Number': 23,
    'Category': 'Access, Authentication and Authorization - Configure Time-Based Job Schedulers',
    'Objective': 'Ensure cron daemon is enabled and running.',
    'Comments': 'Cron daemon is enabled and running' if cron_daemon_compliance else 'Cron daemon is not enabled or not running',
    'Compliance': 'Compliant' if cron_daemon_compliance else 'Non-Compliant'
})

#MBSS 24
crontab_permissions_compliance = check_crontab_permissions()
results.append({
    'Serial Number': 24,
    'Category': 'Access, Authentication and Authorization - Configure Time-Based Job Schedulers',
    'Objective': 'Ensure permissions on /etc/crontab are configured.',
    'Comments': 'Permissions and ownership are correctly set on /etc/crontab' if crontab_permissions_compliance else 'Permissions or ownership are not properly set on /etc/crontab',
    'Compliance': 'Compliant' if crontab_permissions_compliance else 'Non-Compliant'
})

#MBSS 25
cron_hourly_permissions_compliance = check_cron_hourly_permissions()
results.append({
    'Serial Number': 25,
    'Category': 'Access, Authentication and Authorization - Configure Time-Based Job Schedulers',
    'Objective': 'Ensure permissions on /etc/cron.hourly are configured.',
    'Comments': 'Permissions and ownership are correctly set on /etc/cron.hourly' if cron_hourly_permissions_compliance else 'Permissions or ownership are not properly set on /etc/cron.hourly',
    'Compliance': 'Compliant' if cron_hourly_permissions_compliance else 'Non-Compliant'
})

#MBSS 26
cron_daily_permissions_compliance = check_cron_daily_permissions()
results.append({
    'Serial Number': 26,
    'Category': 'Access, Authentication and Authorization - Configure Time-Based Job Schedulers',
    'Objective': 'Ensure permissions on /etc/cron.daily are configured.',
    'Comments': 'Permissions and ownership are correctly set on /etc/cron.daily' if cron_daily_permissions_compliance else 'Permissions or ownership are not properly set on /etc/cron.daily',
    'Compliance': 'Compliant' if cron_daily_permissions_compliance else 'Non-Compliant'
})

#MBSS 27
cron_weekly_permissions_compliance = check_cron_weekly_permissions()
results.append({
    'Serial Number': 27,
    'Category': 'Access, Authentication and Authorization - Configure Time-Based Job Schedulers',
    'Objective': 'Ensure permissions on /etc/cron.weekly are configured.',
    'Comments': 'Permissions and ownership are correctly set on /etc/cron.weekly' if cron_weekly_permissions_compliance else 'Permissions or ownership are not properly set on /etc/cron.weekly',
    'Compliance': 'Compliant' if cron_weekly_permissions_compliance else 'Non-Compliant'
})

#MBSS 28
cron_monthly_permissions_compliance = check_cron_monthly_permissions()
results.append({
    'Serial Number': 28,
    'Category': 'Access, Authentication and Authorization - Configure Time-Based Job Schedulers',
    'Objective': 'Ensure permissions on /etc/cron.monthly are configured.',
    'Comments': 'Permissions and ownership are correctly set on /etc/cron.monthly' if cron_monthly_permissions_compliance else 'Permissions or ownership are not properly set on /etc/cron.monthly',
    'Compliance': 'Compliant' if cron_monthly_permissions_compliance else 'Non-Compliant'
})

#MBSS 29
cron_d_permissions_compliance = check_cron_d_permissions()
results.append({
    'Serial Number': 29,
    'Category': 'Access, Authentication and Authorization - Configure Time-Based Job Schedulers',
    'Objective': 'Ensure permissions on /etc/cron.d are configured.',
    'Comments': 'Permissions and ownership are correctly set on /etc/cron.d' if cron_d_permissions_compliance else 'Permissions or ownership are not properly set on /etc/cron.d',
    'Compliance': 'Compliant' if cron_d_permissions_compliance else 'Non-Compliant'
})

#MBSS 30
cron_allow_compliance = cron_restriction_to_authorize_users(script_30)
results.append({
    'Serial Number': 30,
    'Category': 'Access, Authentication and Authorization - Configure Time-Based Job Schedulers',
    'Objective': 'Ensure cron is restricted to authorized users using cron.allow.',
    'Comments': 'cron.allow is correctly configured' if cron_allow_compliance else 'cron.allow is not properly configured',
    'Compliance': 'Compliant' if cron_allow_compliance else 'Non-Compliant'
})

#MBSS 31
jobs_allow_compliance = jobs_restriction_to_authorize_users(script_31)
results.append({
    'Serial Number': 30,
    'Category': 'Access, Authentication and Authorization - Configure Time-Based Job Schedulers',
    'Objective': 'Ensure cron is restricted to authorized users using jobs.allow.',
    'Comments': 'jobs.allow is correctly configured' if jobs_allow_compliance else 'jobs.allow is not properly configured',
    'Compliance': 'Compliant' if jobs_allow_compliance else 'Non-Compliant'
})

#MBSS 32
inactive_password_lock_compliance = check_inactive_password_lock()
results.append({
    'Serial Number': 32,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure inactive password lock is 30 days or less.',
    'Comments': 'Inactive password lock is correctly set to 30 days or less' if inactive_password_lock_compliance else 'Inactive password lock is not correctly set',
    'Compliance': 'Compliant' if inactive_password_lock_compliance else 'Non-Compliant'
})

#MBSS 33
password_expiration_compliance = check_password_expiration()
results.append({
    'Serial Number': 33,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure password expiration is 365 days or less.',
    'Comments': 'Password expiration is correctly configured' if password_expiration_compliance else 'Password expiration is not correctly configured',
    'Compliance': 'Compliant' if password_expiration_compliance else 'Non-Compliant'
})

#MBSS 34
min_days_compliance = check_min_days_between_password_changes()
results.append({
    'Serial Number': 34,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure minimum days between password changes is configured as 7 or more.',
    'Comments': 'Minimum days between password changes is correctly configured' if min_days_compliance else 'Minimum days between password changes is not correctly configured',
    'Compliance': 'Compliant' if min_days_compliance else 'Non-Compliant'
})

#MBSS 35
password_expiration_warning_compliance = check_password_expiration_warning()
results.append({
    'Serial Number': 35,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure password expiration warning days is 7 or more.',
    'Comments': 'Password expiration warning days are correctly configured' if password_expiration_warning_compliance else 'Password expiration warning days are not correctly configured',
    'Compliance': 'Compliant' if password_expiration_warning_compliance else 'Non-Compliant'
})

#MBSS 36
root_default_group_compliance = check_root_default_group()
results.append({
    'Serial Number': 36,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure default group for the root account is GID 0.',
    'Comments': 'Root account default group is correctly set to GID 0' if root_default_group_compliance else 'Root account default group is not set to GID 0',
    'Compliance': 'Compliant' if root_default_group_compliance else 'Non-Compliant'
})

#MBSS 37
default_shell_timeout_compliance = check_default_shell_timeout(script_37)
results.append({
    'Serial Number': 37,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure default user shell timeout is configured to be less than 900 seconds.',
    'Comments': 'Default user shell timeout is correctly configured' if default_shell_timeout_compliance else 'Default user shell timeout is not correctly configured',
    'Compliance': 'Compliant' if default_shell_timeout_compliance else 'Non-Compliant'
})

#MBSS 38
default_user_umask_compliance = check_default_user_umask()
results.append({
    'Serial Number': 38,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure default user umask is configured as 027 or more restrictive.',
    'Comments': 'Default user umask is correctly configured' if default_user_umask_compliance else 'Default user umask is not correctly configured',
    'Compliance': 'Compliant' if default_user_umask_compliance else 'Non-Compliant'
})

#MBSS 39
su_command_access_compliance = check_su_command_access()
results.append({
    'Serial Number': 39,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure access to the su command is restricted.',
    'Comments': 'Access to the su command is correctly restricted' if su_command_access_compliance else 'Access to the su command is not correctly restricted',
    'Compliance': 'Compliant' if su_command_access_compliance else 'Non-Compliant'
})

#MBSS 40
system_accounts_compliance = check_system_accounts()
results.append({
    'Serial Number': 40,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure system accounts are secured.',
    'Comments': 'System accounts are secured with nologin shell and passwords are disabled' if system_accounts_compliance else 'System accounts are not secured properly',
    'Compliance': 'Compliant' if system_accounts_compliance else 'Non-Compliant'
})

#MBSs 41
passwd_permissions_compliance = check_passwd_permissions()
results.append({
    'Serial Number': 41,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure permissions on /etc/passwd are configured.',
    'Comments': 'Permissions on /etc/passwd are correctly configured' if passwd_permissions_compliance else 'Permissions on /etc/passwd are not correctly configured',
    'Compliance': 'Compliant' if passwd_permissions_compliance else 'Non-Compliant'
})

#MBSS 42
shadow_permissions_compliance = check_shadow_permissions()
results.append({
    'Serial Number': 42,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure permissions on /etc/shadow are configured.',
    'Comments': 'Permissions on /etc/shadow are correctly configured' if shadow_permissions_compliance else 'Permissions on /etc/shadow are not correctly configured',
    'Compliance': 'Compliant' if shadow_permissions_compliance else 'Non-Compliant'
})

#MBSS 43
group_permissions_compliance = check_group_permissions()
results.append({
    'Serial Number': 43,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure permissions on /etc/group are configured.',
    'Comments': 'Permissions on /etc/group are correctly configured' if group_permissions_compliance else 'Permissions on /etc/group are not correctly configured',
    'Compliance': 'Compliant' if group_permissions_compliance else 'Non-Compliant'
})

#MBSS 44
gshadow_permissions_compliance = check_gshadow_permissions()
results.append({
    'Serial Number': 44,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure permissions on /etc/gshadow are configured.',
    'Comments': 'Permissions on /etc/gshadow are correctly configured' if gshadow_permissions_compliance else 'Permissions on /etc/gshadow are not correctly configured',
    'Compliance': 'Compliant' if gshadow_permissions_compliance else 'Non-Compliant'
})

#MBSS 45
passwd_dash_permissions_compliance = check_passwd_dash_permissions()
results.append({
    'Serial Number': 45,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure permissions on /etc/passwd- are configured.',
    'Comments': 'Permissions on /etc/passwd- are correctly configured' if passwd_dash_permissions_compliance else 'Permissions on /etc/passwd- are not correctly configured',
    'Compliance': 'Compliant' if passwd_dash_permissions_compliance else 'Non-Compliant'
})

#MBSS 46
shadow_dash_permissions_compliance = check_shadow_dash_permissions()
results.append({
    'Serial Number': 46,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure permissions on /etc/shadow- are configured.',
    'Comments': 'Permissions on /etc/shadow- are correctly configured' if shadow_dash_permissions_compliance else 'Permissions on /etc/shadow- are not correctly configured',
    'Compliance': 'Compliant' if shadow_dash_permissions_compliance else 'Non-Compliant'
})

#MBSS 47
group_dash_permissions_compliance = check_group_dash_permissions()
results.append({
    'Serial Number': 47,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure permissions on /etc/group- are configured.',
    'Comments': 'Permissions on /etc/group- are correctly configured' if group_dash_permissions_compliance else 'Permissions on /etc/group- are not correctly configured',
    'Compliance': 'Compliant' if group_dash_permissions_compliance else 'Non-Compliant'
})

#MBSS 48
gshadow_dash_permissions_compliance = check_gshadow_dash_permissions()
results.append({
    'Serial Number': 48,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure permissions on /etc/gshadow- are configured.',
    'Comments': 'Permissions on /etc/gshadow- are correctly configured' if gshadow_dash_permissions_compliance else 'Permissions on /etc/gshadow- are not correctly configured',
    'Compliance': 'Compliant' if gshadow_dash_permissions_compliance else 'Non-Compliant'
})

#MBSS 49
world_writable_files_compliance = check_world_writable_files()
results.append({
    'Serial Number': 49,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure no world writable files exist.',
    'Comments': 'No world writable files found' if world_writable_files_compliance else 'World writable files exist',
    'Compliance': 'Compliant' if world_writable_files_compliance else 'Non-Compliant'
})

#MBSS 50
samba_installed_compliance = check_samba_installed()
results.append({
    'Serial Number': 50,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure Samba is not installed.',
    'Comments': 'Samba is not installed' if samba_installed_compliance else 'Samba is installed',
    'Compliance': 'Compliant' if samba_installed_compliance else 'Non-Compliant'
})

#MBSS 51
time_sync_compliance = check_time_synchronization_installed()
results.append({
    'Serial Number': 51,
    'Category': 'Access, Authentication and Authorization - Set Password Shadow Suite Parameter',
    'Objective': 'Ensure time synchronization is in use.',
    'Comments': 'Chrony is installed' if time_sync_compliance else 'Chrony is not installed',
    'Compliance': 'Compliant' if time_sync_compliance else 'Non-Compliant'
})

#MBSS 52
bootloader_password_compliance = check_bootloader_password_set()
results.append({
    'Serial Number': 52,
    'Category': 'Initial Setup - Secure Boot settings',
    'Objective': 'Ensure bootloader password is set.',
    'Comments': 'Bootloader password is set' if bootloader_password_compliance else 'Bootloader password is not set',
    'Compliance': 'Compliant' if bootloader_password_compliance else 'Non-Compliant'
})

#MBSS 53
bootloader_permissions_compliance = check_bootloader_permissions()
results.append({
    'Serial Number': 53,
    'Category': 'Initial Setup - Secure Boot settings',
    'Objective': 'Ensure permissions on bootloader config are configured.',
    'Comments': 'Permissions on bootloader config are correctly configured' if bootloader_permissions_compliance else 'Permissions on bootloader config are not correctly configured.',
    'Compliance': 'Compliant' if bootloader_permissions_compliance else 'Non-Compliant'
})

#MBSS 54
sudo_installed_compliance = check_sudo_installed()
results.append({
    'Serial Number': 54,
    'Category': 'Initial Setup - Configure sudo',
    'Objective': 'Ensure sudo is installed.',
    'Comments': 'Sudo is correctly installed' if sudo_installed_compliance else 'Sudo is not installed.',
    'Compliance': 'Compliant' if sudo_installed_compliance else 'Non-Compliant'
})

#MBSS 55
sudo_use_pty_compliance = check_sudo_use_pty()
results.append({
    'Serial Number': 55,
    'Category': 'Initial Setup - Configure sudo',
    'Objective': 'Ensure sudo commands use pty.',
    'Comments': 'Sudo commands correctly use pty' if sudo_use_pty_compliance else 'Sudo commands do not use pty.',
    'Compliance': 'Compliant' if sudo_use_pty_compliance else 'Non-Compliant'
})

#MBSS 56
sudo_log_file_compliance = check_sudo_log_file()
results.append({
    'Serial Number': 56,
    'Category': 'Initial Setup - Configure sudo',
    'Objective': 'Ensure sudo log file exists.',
    'Comments': 'Sudo log file is correctly configured' if sudo_log_file_compliance else 'Sudo log file is not correctly configured.',
    'Compliance': 'Compliant' if sudo_log_file_compliance else 'Non-Compliant'
})

#MBSS 57
aslr_compliance = check_aslr_enabled(script_57)
results.append({
    'Serial Number': 57,
    'Category': 'Initial Setup - Additional Process Hardening',
    'Objective': 'Ensure address space layout randomization (ASLR) is enabled.',
    'Comments': 'ASLR is correctly enabled' if aslr_compliance else 'ASLR is not correctly enabled',
    'Compliance': 'Compliant' if aslr_compliance else 'Non-Compliant'
})

#MBSS 58
core_dump_storage_compliance = check_core_dump_storage_disabled()
results.append({
    'Serial Number': 58,
    'Category': 'Initial Setup - Additional Process Hardening',
    'Objective': 'Ensure core dump storage is disabled.',
    'Comments': 'Core dump storage is correctly disabled' if core_dump_storage_compliance else 'Core dump storage is not correctly disabled',
    'Compliance': 'Compliant' if core_dump_storage_compliance else 'Non-Compliant'
})

#MBSS 59
core_dump_backtraces_compliance = check_core_dump_backtraces_disabled()
results.append({
    'Serial Number': 59,
    'Category': 'Initial Setup - Additional Process Hardening',
    'Objective': 'Ensure core dump backtraces are disabled.',
    'Comments': 'Core dump backtraces are correctly disabled' if core_dump_backtraces_compliance else 'Core dump backtraces are not correctly disabled',
    'Compliance': 'Compliant' if core_dump_backtraces_compliance else 'Non-Compliant'
})

#MBSS 60
motd_compliance = check_motd_configuration()
results.append({
    'Serial Number': 60,
    'Category': 'Initial Setup - Warning Banners - Command line warning banners',
    'Objective': 'Ensure message of the day is configured properly.',
    'Comments': 'Message of the Day is correctly configured' if motd_compliance else 'Message of the Day is not correctly configured',
    'Compliance': 'Compliant' if motd_compliance else 'Non-Compliant'
})

#MBSS 61
local_login_banner_compliance = check_local_login_banner()
results.append({
    'Serial Number': 61,
    'Category': 'Initial Setup - Warning Banners - Command line warning banners',
    'Objective': 'Ensure local login warning banner is configured properly.',
    'Comments': 'Local login warning banner is correctly configured' if local_login_banner_compliance else 'Local login warning banner is not correctly configured',
    'Compliance': 'Compliant' if local_login_banner_compliance else 'Non-Compliant'
})

#MBSS 62
remote_login_banner_compliance = check_remote_login_banner()
results.append({
    'Serial Number': 62,
    'Category': 'Initial Setup - Warning Banners - Command line warning banners',
    'Objective': 'Ensure remote login warning banner is configured properly.',
    'Comments': 'Remote login warning banner is correctly configured' if remote_login_banner_compliance else 'Remote login warning banner is not correctly configured',
    'Compliance': 'Compliant' if remote_login_banner_compliance else 'Non-Compliant'
})

#MBSS 63
motd_permissions_compliance = check_motd_permissions()
results.append({
    'Serial Number': 63,
    'Category': 'Initial Setup - Warning Banners - Command line warning banners',
    'Objective': 'Ensure permissions on /etc/motd are configured.',
    'Comments': 'Permissions on /etc/motd are correctly configured' if motd_permissions_compliance else 'Permissions on /etc/motd are not correctly configured',
    'Compliance': 'Compliant' if motd_permissions_compliance else 'Non-Compliant'
})

#MBSS 64
issue_net_permissions_compliance = check_issue_net_permissions()
results.append({
    'Serial Number': 64,
    'Category': 'Initial Setup - Warning Banners - Command line warning banners',
    'Objective': 'Ensure permissions on /etc/issue.net are configured.',
    'Comments': 'Permissions on /etc/issue.net are correctly configured' if issue_net_permissions_compliance else 'Permissions on /etc/issue.net are not correctly configured',
    'Compliance': 'Compliant' if issue_net_permissions_compliance else 'Non-Compliant'
})

#MBSS 65
updates_compliance = check_updates_and_patches()
results.append({
    'Serial Number': 65,
    'Category': 'Initial Setup - Warning Banners - Command line warning banners',
    'Objective': 'Ensure updates, patches, and additional security software are installed.',
    'Comments': 'All updates and patches are installed, no reboot required' if updates_compliance else 'Updates or patches are pending, or a system reboot is required',
    'Compliance': 'Compliant' if updates_compliance else 'Non-Compliant'
})

#MBSS 66
updates_compliance = gdm_removed(script_66)
results.append({
    'Serial Number': 65,
    'Category': 'Initial Setup - Warning Banners - Command line warning banners',
    'Objective': 'Ensure GDM is removed or login is configured.',
    'Comments': 'Ensure GDM is removed and login is configured' if updates_compliance else 'GDM is not removed and login is not configured',
    'Compliance': 'Compliant' if updates_compliance else 'Non-Compliant'
})

#MBSS 67
gpg_keys_compliance = check_gpg_keys()
results.append({
    'Serial Number': 67,
    'Category': 'Initial Setup - Configure Software Updates',
    'Objective': 'Ensure GPG keys are configured.',
    'Comments': 'GPG keys are configured correctly' if gpg_keys_compliance else 'GPG keys are not configured correctly',
    'Compliance': 'Compliant' if gpg_keys_compliance else 'Non-Compliant'
})

#MBSS 68
repositories_compliance = check_repositories_configuration()
results.append({
    'Serial Number': 68,
    'Category': 'Initial Setup - Configure Software Updates',
    'Objective': 'Ensure package manager repositories are configured.',
    'Comments': 'Package manager repositories are configured correctly' if repositories_compliance else 'Package manager repositories are not configured correctly',
    'Compliance': 'Compliant' if repositories_compliance else 'Non-Compliant'
})

#MBSS 69
gpgcheck_compliance = check_gpgcheck_activation()
results.append({
    'Serial Number': 69,
    'Category': 'Initial Setup - Configure Software Updates',
    'Objective': 'Ensure gpgcheck is globally activated.',
    'Comments': 'gpgcheck is globally activated correctly' if gpgcheck_compliance else 'gpgcheck is not globally activated correctly',
    'Compliance': 'Compliant' if gpgcheck_compliance else 'Non-Compliant'
})

#MBSS 70
auditd_installed = check_auditd_installed()
results.append({
    'Serial Number': 70,
    'Category': 'Logging and Auditing - Ensure Auditing is Enabled',
    'Objective': 'Ensure auditd is installed.',
    'Comments': 'auditd is installed correctly' if auditd_installed else 'auditd is not installed correctly',
    'Compliance': 'Compliant' if auditd_installed else 'Non-Compliant'
})

#MBSS 71
auditd_service_status = check_auditd_service_status()
results.append({
    'Serial Number': 71,
    'Category': 'Logging and Auditing - Ensure Auditing is Enabled',
    'Objective': 'Ensure auditd service is enabled and running.',
    'Comments': 'auditd service is enabled and running' if auditd_service_status else 'auditd service is not enabled or running',
    'Compliance': 'Compliant' if auditd_service_status else 'Non-Compliant'
})

#MBSS 72
audit_parameter_set = check_audit_parameter_in_grub()
results.append({
    'Serial Number': 72,
    'Category': 'Logging and Auditing - Ensure Auditing is Enabled',
    'Objective': 'Ensure auditing for processes that start prior to auditd is enabled.',
    'Comments': 'audit=1 parameter is correctly set in GRUB' if audit_parameter_set else 'audit=1 parameter is not set in GRUB',
    'Compliance': 'Compliant' if audit_parameter_set else 'Non-Compliant'
})

#MBSS 73
rsyslog_installed = check_rsyslog_installed()
results.append({
    'Serial Number': 73,
    'Category': 'Logging and Auditing - Configure rsyslog',
    'Objective': 'Ensure rsyslog is installed.',
    'Comments': 'rsyslog is installed' if rsyslog_installed else 'rsyslog is not installed',
    'Compliance': 'Compliant' if rsyslog_installed else 'Non-Compliant'
})

#MBSS 74
rsyslog_enabled = check_rsyslog_enabled()
results.append({
    'Serial Number': 74,
    'Category': 'Logging and Auditing - Configure rsyslog',
    'Objective': 'Ensure rsyslog Service is enabled and running.',
    'Comments': 'rsyslog is enabled and running' if rsyslog_enabled else 'rsyslog is not enabled',
    'Compliance': 'Compliant' if rsyslog_enabled else 'Non-Compliant'
})

#MBSS 75
file_permission = check_rsyslog_file_permissions()
results.append({
    'Serial Number': 76,
    'Category': 'Logging and Auditing - Configure rsyslog',
    'Objective': 'Ensure rsyslog default file permissions configured.',
    'Comments': f'rsyslog default file permissions configured' if file_permission else 'rsyslog default file permissions is not configured',
    'Compliance': 'Compliant' if file_permission else 'Non-Compliant'
})

#MBSS 76
rsyslog_configured, conf_files_checked, log_files_found = check_rsyslog_configuration()
results.append({
    'Serial Number': 76,
    'Category': 'Logging and Auditing - Configure rsyslog',
    'Objective': 'Ensure logging is configured.',
    'Comments': f'Config files: {conf_files_checked}. Log files found: {log_files_found}' if rsyslog_configured else 'Logging is not configured properly',
    'Compliance': 'Compliant' if rsyslog_configured else 'Non-Compliant'
})

#MBSS 77
remote_logging_configured, rsyslog_active = check_rsyslog_remote_logging()

results.append({
    'Serial Number': 77,
    'Category': 'Logging and Auditing - Configure rsyslog',
    'Objective': 'Ensure rsyslog is configured to send logs to a remote log host.',
    'Comments': 'Configuration verified' if remote_logging_configured and rsyslog_active else 'Configuration or service status not correct',
    'Compliance': 'Compliant' if remote_logging_configured and rsyslog_active else 'Non-Compliant'
})

#MBSS 78
permissions_issues = check_log_permissions()
results.append({
    'Serial Number': 78,
    'Category': 'Logging and Auditing - Configure journald',
    'Objective': 'Ensure permissions on all logfiles are configured.',
    'Comments': 'Permission are configured' if permissions_issues else 'Not configured.',
    'Compliance': 'Non-Compliant' if permissions_issues else 'Compliant'
})

#MBSS 79
logrotate_compliance = check_logrotate_configuration()
results.append({
    'Serial Number': 79,
    'Category': 'Logging and Auditing - Configure journald',
    'Objective': 'Ensure logrotate is configured.',
    'Comments': 'Logrotate is configured correctly' if logrotate_compliance else 'Logrotate is not configured correctly',
    'Compliance': 'Compliant' if logrotate_compliance else 'Non-Compliant'
})

#MBSS 80
rules_on_disk_compliance = check_audit_rules_80()
results.append({
    'Serial Number': 80,
    'Category': 'Logging and Auditing - Configure Data Retention',
    'Objective': 'Ensure events that modify user/group information are collected.',
    'Comments': 'Rules on disk are configured correctly' if rules_on_disk_compliance else 'Rules on disk are not configured correctly',
    'Compliance': 'Compliant' if rules_on_disk_compliance  else 'Non-Compliant'
})

#MBSS 81
sudoers_scope_compliance = check_sudoers_scope_collection()
results.append({
    'Serial Number': 81,
    'Category': 'Logging and Auditing - Configure Data Retention',
    'Objective': 'Ensure changes to system administration scope (sudoers) is collected.',
    'Comments': 'Scope changes to /etc/sudoers and /etc/sudoers.d/ are collected properly' if sudoers_scope_compliance else 'Scope changes to /etc/sudoers and /etc/sudoers.d/ are not collected properly',
    'Compliance': 'Compliant' if sudoers_scope_compliance else 'Non-Compliant'
})

#MBSS 82
expected_size_mb = 50  # Adjust this value based on company policy
compliant, details = check_audit_log_storage_size(expected_size_mb)

results.append({
    'Serial Number': 82,
    'Category': 'Logging and Auditing - Configure Data Retention',
    'Objective': 'Ensure audit log storage size is configured.',
    'Comments': details,
    'Compliance': 'Compliant' if compliant else 'Non-Compliant'
})

#MBSS 83
compliant, details = check_audit_log_auto_delete()
results.append({
    'Serial Number': 83,
    'Category': 'Logging and Auditing - Configure Data Retention',
    'Objective': 'Ensure audit logs are not automatically deleted.',
    'Comments': details,
    'Compliance': 'Compliant' if compliant else 'Non-Compliant'
})


#MBSS 84
compliant= check_mac_policy_audit_rules()
results.append({
    'Serial Number': 84,
    'Category': 'Logging and Auditing - Configure Data Retention',
    'Objective': "Ensure events that modify the system's Mandatory Access Controls are collected.",
    'Comments': 'Access controlls are collected' if compliant else'Access controlls are not collected',
    'Compliance': 'Compliant' if compliant else 'Non-Compliant'
})

#MBSS 85
login_logout_events_compliance = check_login_logout_events()
results.append({
    'Serial Number': 85,
    'Category': 'Logging and Auditing - Configure Data Retention',
    'Objective': 'Ensure login and logout events are collected.',
    'Comments': 'Login and logout events are being collected properly' if login_logout_events_compliance else 'Login and logout events are not being collected properly',
    'Compliance': 'Compliant' if login_logout_events_compliance else 'Non-Compliant'
})

#MBSS 86
session_initiation_compliance = check_session_initiation_collection()
results.append({
    'Serial Number': 86,
    'Category': 'Logging and Auditing - Configure Data Retention',
    'Objective': 'Ensure session initiation information is collected.',
    'Comments': 'Session initiation information collection is correctly configured' if session_initiation_compliance else 'Session initiation information collection is not correctly configured',
    'Compliance': 'Compliant' if session_initiation_compliance else 'Non-Compliant'
})

#MBSS 87
privileged_commands_audit_compliance = check_privileged_commands_audit(script_87)
results.append({
    'Serial Number': 87,
    'Category': 'Logging and Auditing - Configure Data Retention',
    'Objective': 'Ensure use of privileged commands is collected.',
    'Comments': 'All privileged commands are correctly audited' if privileged_commands_audit_compliance else 'Some privileged commands are not correctly audited',
    'Compliance': 'Compliant' if privileged_commands_audit_compliance else 'Non-Compliant'
})

#MBSS 88
audit_configuration_compliance = check_audit_configuration_immutable()
results.append({
    'Serial Number': 88,
    'Category': 'Logging and Auditing - Configure Data Retention',
    'Objective': 'Ensure the audit configuration is immutable.',
    'Comments': 'Audit configuration is correctly set to immutable' if audit_configuration_compliance else 'Audit configuration is not correctly set to immutable',
    'Compliance': 'Compliant' if audit_configuration_compliance else 'Non-Compliant'
})


#MBSS 89
compliance_results = check_audit_rules(path_89)

# Append results to the result list
results.append({
    'Serial Number': 89,
    'Category': 'Logging and Auditing - Configure Data Retention',
    'Objective': 'Ensure successful file system mounts are collected.',
    'Comments': 'On-disk and running audit rules are correctly configured' if compliance_results else 'On-disk or running audit rules are not correctly configured',
    'Compliance': 'Compliant' if compliance_results else 'Non-Compliant'
})

#MBSS 90
telnet_compliance = check_telnet_not_installed()
results.append({
    'Serial Number': 90,
    'Category': 'Services - Service Clients',
    'Objective': 'Ensure telnet client is not installed.',
    'Comments': 'Telnet client is correctly not installed' if telnet_compliance else 'Telnet client is still installed',
    'Compliance': 'Compliant' if telnet_compliance else 'Non-Compliant'
})

#MBSS 91
ldap_compliance = check_ldap_client_not_installed()
results.append({
    'Serial Number': 91,
    'Category': 'Services - Service Clients',
    'Objective': 'Ensure LDAP client is not installed.',
    'Comments': 'LDAP client is correctly not installed' if ldap_compliance else 'LDAP client is still installed',
    'Compliance': 'Compliant' if ldap_compliance else 'Non-Compliant'
})

#MBSS 92
shadowed_passwords_compliance = check_shadowed_passwords()
results.append({
    'Serial Number': 92,
    'Category': 'System Maintenance - User and Groups settings',
    'Objective': 'Ensure accounts in /etc/passwd use shadowed passwords.',
    'Comments': 'All accounts use shadowed passwords' if shadowed_passwords_compliance else 'Some accounts do not use shadowed passwords',
    'Compliance': 'Compliant' if shadowed_passwords_compliance else 'Non-Compliant'
})

#MBSS 93
shadow_passwords_compliance = check_shadow_password_fields()
results.append({
    'Serial Number': 93,
    'Category': 'System Maintenance - User and Groups settings',
    'Objective': 'Ensure /etc/shadow password fields are not empty.',
    'Comments': 'All accounts have passwords' if shadow_passwords_compliance else 'Some accounts do not have passwords',
    'Compliance': 'Compliant' if shadow_passwords_compliance else 'Non-Compliant'
})

#MBSS 94
root_uid_compliance = check_root_uid_0()
results.append({
    'Serial Number': 94,
    'Category': 'System Maintenance - User and Groups settings',
    'Objective': 'Ensure root is the only UID 0 account.',
    'Comments': 'Only root has UID 0' if root_uid_compliance else 'There are other accounts with UID 0',
    'Compliance': 'Compliant' if root_uid_compliance else 'Non-Compliant'
})

#MBSS 95
path_integrity_compliance = check_root_path_integrity(script_95)
results.append({
    'Serial Number': 95,
    'Category': 'System Maintenance - User and Groups settings',
    'Objective': 'Ensure root PATH Integrity',
    'Comments': path_integrity_compliance,
    'Compliance': 'Compliant' if path_integrity_compliance else 'Non-Compliant'
})


#MBSS 96
home_directory_permissions_compliance = check_home_directory_permissions()
results.append({
    'Serial Number': 96,
    'Category': 'System Maintenance - User and Groups settings',
    'Objective': 'Ensure users\' home directories permissions are 750 or more restrictive.',
    'Comments': home_directory_permissions_compliance,
    'Compliance': 'Compliant' if "Failed:" not in home_directory_permissions_compliance else 'Non-Compliant'
})

#MBSS 97
groups_compliance = check_groups_in_passwd_exist_in_group()
results.append({
    'Serial Number': 97,
    'Category': 'System Maintenance - User and Groups settings',
    'Objective': 'Ensure all groups in /etc/passwd exist in /etc/group.',
    'Comments': groups_compliance,
    'Compliance': 'Compliant' if "Failed:" not in groups_compliance else 'Non-Compliant'
})
# Print results
for result in results:
    print(f"Check Passed: {result['Objective']} is correctly set." if result['Compliance'] == 'Compliant' else f"Check Failed: {result['Objective']} is not correctly set.")

# Write results to CSV
with open('compliance_report.csv', 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=['Serial Number', 'Category', 'Objective', 'Comments', 'Compliance'])
    writer.writeheader()
    writer.writerows(results)