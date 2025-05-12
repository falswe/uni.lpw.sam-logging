#!/bin/bash

# Configuration
CLIENT_PATH="/home/we/unitn-repos/lpw/labs/cloves-client/iot_testbed_client.py"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
JOB_FILE="$SCRIPT_DIR/job.json"
DOWNLOAD_DIR="$SCRIPT_DIR/downloads"
CHECK_INTERVAL=10

# Create download directory
mkdir -p "$DOWNLOAD_DIR"

# Submit job and extract ID
echo "Submitting job..."
SUBMIT_OUTPUT=$(python $CLIENT_PATH schedule $JOB_FILE)
echo "$SUBMIT_OUTPUT"

JOB_ID=$(echo "$SUBMIT_OUTPUT" | grep -o "'job_id': [0-9]*" | grep -o "[0-9]*")

if [ -z "$JOB_ID" ]; then
    echo "Error: Could not extract job ID"
    exit 1
fi

echo "Job ID: $JOB_ID"
echo "Waiting for job to complete..."

# Wait for job completion
while ! python $CLIENT_PATH completed | grep -q "Id: $JOB_ID"; do
    echo "Job still running. Checking again in $CHECK_INTERVAL seconds..."
    sleep $CHECK_INTERVAL
done

echo "Job $JOB_ID completed!"

# Download and cleanup
echo "Downloading results to $DOWNLOAD_DIR..."
python $CLIENT_PATH download $JOB_ID -u --dest-dir "$DOWNLOAD_DIR"
rm -f "$DOWNLOAD_DIR/job_${JOB_ID}.tar.gz"

echo "Log available at $DOWNLOAD_DIR/job_${JOB_ID}/job.log"

exit 0