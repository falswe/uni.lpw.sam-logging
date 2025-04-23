# sam-logging - Zephyr Logging Module

A custom logging module designed for use within the Zephyr RTOS ecosystem, tailored for SAM.

## Building

Build the sample application using `west`. Builds are placed in the `build/` directory within `application/`.

1.  **Navigate to the Application Directory:**
    ```bash
    cd application
    # Ensure direnv environment is active
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

1.  **Native POSIX:**
    ```bash
    ./build/application/zephyr/zephyr.exe | less
    ```
    *(Look for logging output in the terminal)*

2.  **DWM3001CDK Hardware:**
    *   Ensure the board is connected via J-Link.
    *   Make sure `nrfjprog` (from nRF Command Line Tools) and J-Link tools are in your PATH.
    *   Flash the built firmware:
        ```bash
        # From the 'application' directory
        west flash
        ```
    *   You will need a separate terminal and serial tool (like `minicom`, `screen`, or `nrfjprog --log`) to view the serial output from the board.
