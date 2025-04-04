#!/bin/bash

# create_test_file.sh - Creates a test file of specified size
# Usage: ./create_test_file.sh [filename] [size_in_MB]

# Default values
FILENAME="test_file.txt"
SIZE_MB=1

# Check if filename is provided
if [ $# -ge 1 ]; then
    FILENAME="$1"
fi

# Check if size is provided
if [ $# -ge 2 ]; then
    SIZE_MB="$2"

    # Validate that size is a positive number
    if ! [[ "$SIZE_MB" =~ ^[0-9]+$ ]]; then
        echo "Error: Size must be a positive integer (in MB)"
        exit 1
    fi
fi

echo "Creating test file: $FILENAME with exact size of $SIZE_MB MB"

# Method 1: Create file with exact size using dd
# This creates a file with the exact byte count requested
dd if=/dev/urandom of="$FILENAME" bs=1M count="$SIZE_MB" status=progress

# Method 2: Create a more structured text file with exact size
# Uncomment this section if you prefer a text file with line numbers
# instead of random binary data

# # Calculate exact byte size
# SIZE_BYTES=$(($SIZE_MB * 1048576))
# 
# # Create a temporary file with header
# echo "SGX Test File - Created $(date)" > "$FILENAME.tmp"
# echo "----------------------------------------" >> "$FILENAME.tmp"
# echo "" >> "$FILENAME.tmp"
# 
# # Get header size
# HEADER_SIZE=$(stat -c%s "$FILENAME.tmp")
# 
# # Calculate remaining bytes needed
# REMAINING_BYTES=$(($SIZE_BYTES - $HEADER_SIZE))
# 
# # Create the main content with exact size
# dd if=/dev/urandom bs=$REMAINING_BYTES count=1 status=none | base64 | fold -w 70 >> "$FILENAME.tmp"
# 
# # Trim to exact size
# truncate -s $SIZE_BYTES "$FILENAME.tmp"
# 
# # Replace with final file
# mv "$FILENAME.tmp" "$FILENAME"

# Get actual file size
ACTUAL_SIZE=$(du -h "$FILENAME" | cut -f1)
ACTUAL_BYTES=$(stat -c%s "$FILENAME")
EXPECTED_BYTES=$(($SIZE_MB * 1048576))

echo "File created successfully!"
echo "Filename: $FILENAME"
echo "Requested size: $SIZE_MB MB ($EXPECTED_BYTES bytes)"
echo "Actual size: $ACTUAL_SIZE ($ACTUAL_BYTES bytes)"

# Verify size accuracy
if [ $ACTUAL_BYTES -eq $EXPECTED_BYTES ]; then
    echo "✓ Size is exactly as requested"
else
    DIFF=$(($ACTUAL_BYTES - $EXPECTED_BYTES))
    echo "! Size differs by $DIFF bytes"
fi
