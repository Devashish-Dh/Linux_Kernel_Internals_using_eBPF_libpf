#!/bin/bash

# Define the log file
LOG_FILE="monitor_output.log"

# Build the Project
echo "Compiling project..."
make clean && make

echo "Starting BPF Monitor..."
echo "Output is being saved to $LOG_FILE"
echo "Press Ctrl+C to stop."

# Run with sudo, unbuffered output, and pipe to tee
# 'stdbuf -oL' ensures the output isn't held in a buffer so grep sees it instantly
sudo stdbuf -oL ./LLT007 | tee "$LOG_FILE"
