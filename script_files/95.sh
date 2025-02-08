#!/bin/bash

# Get the PATH for the root user
RPCV="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"

# Initialize compliance flag
compliant=true

# Check for empty directories
if echo "$RPCV" | grep -q "::"; then
    echo "PATH contains an empty directory (::)"
    compliant=false
fi

# Check for trailing colons
if echo "$RPCV" | grep -q ":$"; then
    echo "PATH contains a trailing (:)"
    compliant=false
fi

# Check directories in PATH
for x in $(echo "$RPCV" | tr ":" " "); do
    if [ -d "$x" ]; then
        # Check permissions and ownership
        ls -ldH "$x" | awk '
            $9 == "." {print "PATH contains current working directory (.)"}
            $3 != "root" {print $9, "is not owned by root"}
            substr($1,6,1) != "-" {print $9, "is group writable"}
            substr($1,9,1) != "-" {print $9, "is world writable"}
        ' || compliant=false
    else
        echo "$x is not a directory"
        compliant=false
    fi
done

# Output final compliance status
if $compliant; then
    echo "Compliance Check Passed: All conditions are met."
else
    echo "Compliance Check Failed: Issues found."
fi

