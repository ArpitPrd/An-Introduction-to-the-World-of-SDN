#!/bin/bash
# secure_copy.sh - Simplified script for copying files/directories to a remote server.
#
# Usage: ./secure_copy.sh <local_source_path> <remote_destination_path>
#
# Note: Directories are now copied using rsync and automatically exclude .git folders.

# -----------------------------------------------------------------------------
# REQUIRED CONFIGURATION
# Modify these two variables with your target server details.
# -----------------------------------------------------------------------------
REMOTE_USER="baadalvm"  # <-- CHANGE ME (e.g., 'ubuntu', 'ec2-user')
REMOTE_HOST="10.17.51.248"       # <-- CHANGE ME (The server's IP address or hostname)
# -----------------------------------------------------------------------------

# --- 1. Argument Validation ---

# Check if the configuration variables have been changed
if [[ "$REMOTE_USER" == "your_username_here" || "$REMOTE_HOST" == "192.168.1.100" ]]; then
    echo "ERROR: Please update the 'REMOTE_USER' and 'REMOTE_HOST' variables in the script."
    exit 1
fi

# Check if exactly two arguments were provided (source and destination)
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <local_source_path> <remote_destination_path>"
    echo ""
    echo "This script copies a file/directory from your local machine to the pre-configured remote server."
    echo "  <local_source_path>       e.g., ~/Desktop/my_file.txt or ~/my_project/"
    echo "  <remote_destination_path> e.g., /home/${REMOTE_USER}/uploads/ or /tmp/"
    exit 1
fi

# --- 2. Variable Assignment ---

LOCAL_SOURCE="$1"
REMOTE_PATH="$2"
REMOTE_TARGET="${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}"

# --- 3. Execution ---

# Check if the local source file/directory exists
if [ ! -e "$LOCAL_SOURCE" ]; then
    echo "ERROR: Local source file or directory not found: ${LOCAL_SOURCE}"
    exit 1
fi

# Determine if the source is a directory. If so, use rsync with exclusions.
if [ -d "$LOCAL_SOURCE" ]; then
    echo "Copying directory (recursive) using rsync to: ${REMOTE_TARGET}"
    echo "Excluding common hidden directories (.git, .DS_Store)."
    
    # Define files/patterns to exclude (e.g., Git metadata, macOS files)
    # This prevents the permission denied errors by skipping the .git folder.
    EXCLUDES=("--exclude=.git" "--exclude=.DS_Store" "--exclude=*.pyc")
    
    # -a: archive mode (preserves permissions, timestamps, etc.)
    # -v: verbose output (show files being transferred)
    # -z: compression during transfer (can speed things up)
    # -r: recursive (rsync -a implies -r, but we keep it explicit)
    # Note: We use LOCAL_SOURCE (no trailing slash) to copy the whole source folder 
    # into the REMOTE_PATH (e.g., local_project/ goes into /home/user/remote_path/)
    
    rsync -avz "${EXCLUDES[@]}" "${LOCAL_SOURCE}" "${REMOTE_TARGET}"
else
    echo "Copying file using scp to: ${REMOTE_TARGET}"
    # Standard file copy using scp.
    scp "${LOCAL_SOURCE}" "${REMOTE_TARGET}"
fi

# --- 4. Result Status ---

if [ "$?" -eq 0 ]; then
    echo ""
    echo "File transfer successful!"
else
    echo ""
    echo "File transfer failed. Check your configuration, paths, or remote permissions."
fi
