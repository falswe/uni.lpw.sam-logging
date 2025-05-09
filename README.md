# SAM Logging Framework

A specialized logging module for SAM (Synchronous Actions Management) protocols in Zephyr RTOS. This framework efficiently captures protocol actions, encodes them using Z85, and provides visualization tools for analysis.

## Repository Structure

```
sam-logging/
├── application/         # Main Zephyr application
│   ├── src/
│   │   ├── main.c       # Sample application showing logging usage
│   │   ├── sam_log.c    # Logging implementation
│   │   └── sam_log.h    # Logging API definitions
│   └── analyze/
│       └── sam-log-viewer.html  # Web-based log visualization tool
├── z85/                 # Z85 encoding library (submodule)
│   └── src/
│       ├── z85.c        # Z85 implementation
│       └── z85.h        # Z85 API definitions
└── z85decode/           # Command-line tool for decoding Z85 logs
    ├── z85decode.c      # Decoder implementation
    └── makefile         # Build script for the decoder
```

## Building

Build the sample application using `west`. Builds are placed in the `build/` directory within `application/`.

1.  **Navigate to the Application Directory:**
    ```bash
    cd application
    ```

2.  **Build for Native POSIX (Simulation on Host):**
    ```bash
    west build -p always -b native_posix
    ```

3.  **Build for DWM3001CDK Hardware:**
    ```bash
    west build -p always -b dwm3001cdk
    ```

## Running

**Native POSIX:**
    ```bash
    ./build/application/zephyr/zephyr.exe
    ```
    *(Look for logging output in the terminal)*

## Using the Logging API

The logging API is defined in `sam_log.h`. Here's a quick overview of the main functions:

```c
// Initialize the logging subsystem
int sam_log_init(void);

// Log an action with all possible fields
int sam_log_action(enum sam_log_status status, uint16_t custom_status, 
                  uint32_t slot_idx, int16_t slot_idx_diff, 
                  uint8_t slots_to_use, bool set_default_slots,
                  const void *custom_data, uint16_t custom_data_len);

// Get logging statistics
int sam_log_get_stats(struct sam_log_stats *stats);

// Flush logs and output as encoded string
int sam_log_flush(char *log_name, uint32_t epoch_id, size_t *bytes_written);
```

## Analyzing Logs

### Using the Web-Based Viewer

1. Open `application/analyze/sam-log-viewer.html` in a web browser
2. Copy the log output from your terminal
3. Paste it into the input area
4. Click "Parse Logs" to analyze the data

The viewer provides:
- A summary of all logged actions
- Detailed inspection of each action's fields
- Visualization of the binary data
- Timeline view of protocol execution

## Dependencies

- Zephyr RTOS (tested with version 3.2.0+)
- Z85 library (included as a submodule)