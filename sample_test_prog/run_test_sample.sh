#!/bin/bash

# Configuration
TEST_BIN="./monitor_test_v3"

# 1. Compile the test suite using the Makefile
echo "--- Compiling Test Suite ---"
if ! make; then
    echo "Error: Compilation failed."
    exit 1
fi

echo "--- Starting Test Suite ---"
echo "Note: This will perform forks, execs, and file ops."
echo "Press [Ctrl+C] to stop the test."
echo "------------------------------------------------"

# 2. Run the binary
# We use a trap to ensure the script continues to the cleanup phase after Ctrl+C
trap "echo -e '\nStopping test...';" SIGINT
$TEST_BIN

# 3. Cleanup Phase
echo "------------------------------------------------"
read -p "Test stopped. Delete all binaries and test files? (y/n): " cleanup_choice

if [[ "$cleanup_choice" =~ ^[Yy]$ ]]; then
    echo "Cleaning up..."
    make clean
    echo "All test artifacts removed."
else
    echo "Binaries preserved in current directory."
fi
