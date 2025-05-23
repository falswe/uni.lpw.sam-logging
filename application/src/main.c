#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "../include/sam_log.h"

LOG_MODULE_REGISTER(main, CONFIG_LOG_DEFAULT_LEVEL);

/* Buffer for custom data payloads */
static uint8_t custom_data_buffer[64];

/* Initialize the custom data buffer with pattern data */
static void init_custom_data(void) {
    for (int i = 0; i < sizeof(custom_data_buffer); i++) {
        custom_data_buffer[i] = i & 0xFF;
    }
}

/* Demonstrate basic logging capabilities */
static void showcase_basic_logging(void) {
    LOG_INF("=== Basic Logging Demo ===");

    /* Simple status log */
    sam_log_action(SAM_LOG_RX_SUCCESS, 0, 15, 0, 1, false, NULL, 0);
    LOG_INF("Logged RX_SUCCESS status");

    /* Log with specific slot index */
    sam_log_action(SAM_LOG_TX_DONE, 0, 42, 0, 1, false, NULL, 0);
    LOG_INF("Logged TX_DONE at slot 42");

    /* Log with slot difference */
    sam_log_action(SAM_LOG_RX_SUCCESS, 0, 50, 2, 1, false, NULL, 0);
    LOG_INF("Logged RX_SUCCESS with slot_idx_diff=2");

    /* Flush logs */
    size_t bytes_written;
    sam_log_flush("BASIC", 1, &bytes_written);
    LOG_INF("Basic logs flushed successfully");
}

/* Demonstrate logging with custom data */
static void showcase_custom_data(void) {
    LOG_INF("=== Custom Data Logging Demo ===");

    /* Log with 16 bytes of custom data */
    sam_log_action(SAM_LOG_RX_SUCCESS, 0, 100, 0, 1, false, custom_data_buffer, 16);
    LOG_INF("Logged RX_SUCCESS with 16 bytes of custom data");

    /* Log with 32 bytes of custom data */
    sam_log_action(SAM_LOG_TX_DONE, 0, 101, 0, 2, false, custom_data_buffer, 32);
    LOG_INF("Logged TX_DONE with 32 bytes of custom data");

    /* Flush logs */
    size_t bytes_written;
    sam_log_flush("CUSTOM", 2, &bytes_written);
    LOG_INF("Custom data logs flushed successfully");
}

/* Demonstrate sequence of logs that simulates a typical epoch */
static void showcase_epoch_simulation(void) {
    LOG_INF("=== Epoch Simulation Demo ===");

    uint32_t base_slot = 1000;
    uint8_t packet_data[4] = {0xDE, 0xAD, 0xBE, 0xEF};

    /* Simulate an epoch sequence */
    sam_log_action(SAM_LOG_RX_LISTEN_LATE, 0, base_slot, 0, 1, false, NULL, 0);
    sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 1, 0, 1, false, packet_data,
                   sizeof(packet_data));
    sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2, 0, 2, true, NULL, 0);
    sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 10, 0, 1, false, NULL, 0);
    sam_log_action(SAM_LOG_SKIP_SUCCESS, 0, base_slot + 11, 0, 5, false, NULL, 0);
    sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 12, 0, 1, false, NULL, 0);
    sam_log_action(SAM_LOG_TX_SCHED_LATE, 0, base_slot + 20, 2, 1, false, NULL, 0);
    sam_log_action(SAM_LOG_SYNCH_FAIL, 0, base_slot + 21, 0, 1, false, NULL, 0);

    /* Flush logs */
    size_t bytes_written;
    sam_log_flush("EPOCH", 3, &bytes_written);
    LOG_INF("Epoch simulation logs flushed successfully");
}

/* Demonstrate buffer overflow handling */
static void showcase_overflow_handling(void) {
    LOG_INF("=== Buffer Overflow Handling Demo ===");

    /* Create some custom data */
    uint8_t packet_data[4] = {0xAA, 0xBB, 0xCC, 0xDD};

    /* Fill the buffer with many entries to trigger overflow */
    LOG_INF("Adding 700 log entries to trigger overflow...");

    sam_log_action(SAM_LOG_TX_DONE, 0, 1999, 0, 1, true, packet_data, sizeof(packet_data));

    int i;
    for (i = 0; i < 300; i++) {
        /* Add a mix of simple and complex entries */
        if (i % 10 == 0) {
            /* Trigger slot index to be logged */
            i++;
            /* Log with custom data occasionally */
            sam_log_action(SAM_LOG_TX_DONE, 0, 2000 + i, 0, 1, false, packet_data,
                           sizeof(packet_data));
        } else {
            /* Simple status log for most entries */
            sam_log_action((i % 5 == 0) ? SAM_LOG_RX_SUCCESS : SAM_LOG_TX_DONE, 0, 2000 + i, 0, 1,
                           false, NULL, 0);
        }
    }
    while (i < 700) {
        /* Log with custom data occasionally */
        sam_log_action(SAM_LOG_TX_DONE, 0, 2000 + i, 0, 1, false, packet_data, sizeof(packet_data));
        i++;
    }

    /* Add one distinctive entry we should see in the end buffer */
    sam_log_action(SAM_LOG_SYNCH_DONE, 0, 5000, 0, 1, false, "FINAL ENTRY", 11);

    /* Flush the logs */
    size_t bytes_written;
    sam_log_flush("OVERFLOW", 4, &bytes_written);

    /* Show statistics */
    struct sam_log_stats stats;
    if (sam_log_get_stats(&stats) == 0) {
        LOG_INF("Overflow test complete, should see START and END logs");
    }
}

/* Application main entry point */
int main(void) {
    int ret;

    LOG_INF("SAM Logging Showcase Application");
    LOG_INF("================================");

    /* Initialize logging */
    ret = sam_log_init();
    if (ret != 0) {
        LOG_ERR("Failed to initialize SAM logging: %d", ret);
        return ret;
    }
    LOG_INF("SAM logging initialized successfully");

    /* Initialize test data */
    init_custom_data();

    /* Run demonstrations */
    showcase_basic_logging();
    k_sleep(K_MSEC(100));

    showcase_custom_data();
    k_sleep(K_MSEC(100));

    showcase_epoch_simulation();
    k_sleep(K_MSEC(100));

    showcase_overflow_handling();
    k_sleep(K_MSEC(100));

    LOG_INF("Showcase complete!");
    return 0;
}