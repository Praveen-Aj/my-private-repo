#!/bin/bash
# create.sh
# Usage: ./create.sh <patch_name>
#
# This script performs the following steps:
#   1. Verifies that oxe_connect_env is available.
#   2. Executes oxe_connect_env with the numeric parameter (4042663) and the specified patch name.
#   3. Uses csh to source the temporary connection file (written in C-shell syntax)
#      and converts its environment to Bash export statements.
#   4. Deletes the temporary file after sourcing.
#
# Note: Deleting the temporary file here is safe because it is only used to set up
#       the environment for the current connection and does not affect the patch itself.

if ! command -v oxe_connect_env >/dev/null 2>&1; then
  echo "Error: oxe_connect_env not found in PATH." >&2
  exit 1
fi

echo "Using oxe_connect_env: $(which oxe_connect_env)"
echo "Attempting to connect to patch: $1"

oxe_connect_env 4042663 -n "$1"
if [ $? -ne 0 ]; then
  echo "Error: oxe_connect_env command failed." >&2
  exit 1
fi

TEMP_FILE=~/tmp/connect.4042663
if [ ! -f "$TEMP_FILE" ]; then
  echo "Error: Temporary connection file $TEMP_FILE not found." >&2
  exit 1
fi

# Use C-shell to source the temporary file and output the resulting environment.
ENV_OUTPUT=$(csh -f -c "source $TEMP_FILE; env")
if [ $? -ne 0 ]; then
  echo "Error: Sourcing temporary connection file via csh failed." >&2
  exit 1
fi

# Convert each environment variable into a Bash export.
while IFS= read -r line; do
    if [[ "$line" == *"="* ]]; then
        var=$(echo "$line" | cut -d '=' -f 1)
        val=$(echo "$line" | cut -d '=' -f 2-)
        export "$var"="$val"
    fi
done <<< "$ENV_OUTPUT"

rm "$TEMP_FILE"
if [ $? -ne 0 ]; then
  echo "Error: Removing temporary connection file failed." >&2
  exit 1
fi

echo "Patch connection established successfully."
exit 0