#include <dw3000.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "deca_device_api.h"
#include "sam_log.h"

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
    sam_log_action(SAM_LOG_RX_SUCCESS, 0, 15, 0, 1, NULL, 0);
    LOG_INF("Logged RX_SUCCESS status");

    /* Log with specific slot index */
    sam_log_action(SAM_LOG_TX_DONE, 0, 42, 0, 1, NULL, 0);
    LOG_INF("Logged TX_DONE at slot 42");

    /* Log with slot difference */
    sam_log_action(SAM_LOG_RX_SUCCESS, 0, 50, 2, 1, NULL, 0);
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
    sam_log_action(SAM_LOG_RX_SUCCESS, 0, 100, 0, 1, custom_data_buffer, 16);
    LOG_INF("Logged RX_SUCCESS with 16 bytes of custom data");

    /* Log with 32 bytes of custom data */
    sam_log_action(SAM_LOG_TX_DONE, 0, 101, 0, 2, custom_data_buffer, 32);
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
    sam_log_action(SAM_LOG_RX_LISTEN_LATE, 0, base_slot, 0, 1, NULL, 0);
    sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 1, 0, 1, packet_data, sizeof(packet_data));
    sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2, 0, 2, NULL, 0);
    sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 10, 0, 1, NULL, 0);
    sam_log_action(SAM_LOG_SKIP_SUCCESS, 0, base_slot + 11, 0, 5, NULL, 0);
    sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 12, 0, 1, NULL, 0);
    sam_log_action(SAM_LOG_TX_SCHED_LATE, 0, base_slot + 20, 2, 1, NULL, 0);
    sam_log_action(SAM_LOG_SYNCH_FAIL, 0, base_slot + 21, 0, 1, NULL, 0);

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

    sam_log_action(SAM_LOG_TX_DONE, 0, 1999, 0, 1, packet_data, sizeof(packet_data));

    int i;
    for (i = 0; i < 300; i++) {
        /* Add a mix of simple and complex entries */
        if (i % 10 == 0) {
            /* Trigger slot index to be logged */
            i++;
            /* Log with custom data occasionally */
            sam_log_action(SAM_LOG_TX_DONE, 0, 2000 + i, 0, 1, packet_data, sizeof(packet_data));
        } else {
            /* Simple status log for most entries */
            sam_log_action((i % 5 == 0) ? SAM_LOG_RX_SUCCESS : SAM_LOG_TX_DONE, 0, 2000 + i, 0, 1,
                           NULL, 0);
        }
    }
    while (i < 700) {
        /* Log with custom data occasionally */
        sam_log_action(SAM_LOG_TX_DONE, 0, 2000 + i, 0, 1, packet_data, sizeof(packet_data));
        i++;
    }

    /* Add one distinctive entry we should see in the end buffer */
    sam_log_action(SAM_LOG_SYNCH_DONE, 0, 5000, 0, 1, "FINAL ENTRY", 11);

    /* Flush the logs */
    size_t bytes_written;
    sam_log_flush("OVERFLOW", 4, &bytes_written);

    /* Show statistics */
    struct sam_log_stats stats;
    if (sam_log_get_stats(&stats) == 0) {
        LOG_INF("Overflow test complete, should see START and END logs");
    }
}

static void showcase_dynamic_default_slots(void) {
    LOG_INF("=== Dynamic Default Slots Demo ===");

    int prev_slot_idx = 1;
    /* Log entries with changing default slots_to_use */
    for (uint8_t defaults = 2; defaults <= 5; defaults++) {
        for (int i = 0; i < 6; i++) {
            prev_slot_idx += defaults;
            sam_log_action(SAM_LOG_RX_SUCCESS, 0, prev_slot_idx, 0, defaults, NULL, 0);
        }
        LOG_INF("Logged 6 entries with slots_to_use=%u", defaults);
    }

    /* Flush logs */
    size_t bytes_written;
    sam_log_flush("DYNAMIC_SLOTS", 5, &bytes_written);
    LOG_INF("Dynamic default slots logs flushed successfully");
}

/*
 * Demonstrate real-world epoch behavior from epoch 1017 trace.
 *
 * Each physical node simulates exactly one logical node from the deployment.
 *
 * Physical Node → Logical Node mapping:
 *   Node 54 (part_id 283165229) → Logical Node  10
 *   Node 76 (part_id 283170447) → Logical Node   4
 *   Node 70 (part_id 283202460) → Logical Node  27
 *   Node 58 (part_id 283279897) → Logical Node  15
 *   Node 72 (part_id 283281171) → Logical Node 109
 *   Node 74 (part_id 283296289) → Logical Node   2
 *   Node 64 (part_id 1356895520) → Logical Node  19
 *   Node 71 (part_id 1356896676) → Logical Node  36
 *   Node 52 (part_id 1356940854) → Logical Node   7
 *   Node 50 (part_id 2430637345) → Logical Node   5
 *   Node 63 (part_id 2430648359) → Logical Node  18
 *   Node 61 (part_id 2430685849) → Logical Node  16
 *   Node 53 (part_id 2430687019) → Logical Node   9
 *   Node 77 (part_id 3504391685) → Logical Node 119
 *   Node 65 (part_id 3504392353) → Logical Node  26
 *   Node 56 (part_id 3504395021) → Logical Node  12
 *   Node 75 (part_id 3504396712) → Logical Node   3
 *   Node 73 (part_id 3504409141) → Logical Node 118
 *   Node 51 (part_id 3504425116) → Logical Node   6
 *   Node 55 (part_id 3504440328) → Logical Node  11
 *   Node 62 (part_id 3504505384) → Logical Node  17
 *   Node 57 (part_id 3504507569) → Logical Node  14
 */
static void showcase_epoch_1017_realworld(void) {
    LOG_INF("=== Epoch 1017 Real-World Demo ===");
    LOG_INF("Simulating multi-node network behavior from actual deployment");

    uint32_t base_slot = 0;

    /* Initialize DW3000 and get node ID */
    dw3000_init();
    dwt_initialise(DWT_READ_OTP_PID);
    uint32_t node_id = dwt_getpartid();
    LOG_INF("My node ID (part_id): %u", node_id);

    if (node_id == 2430637345) {
        /* Physical Node 50 → Simulates Logical Node 5 */
        /* Actions: 1x RX_ERROR, 3x RX_SUCCESS, 20x RX_TIMEOUT, 3x SYNCH_DONE, 11x TX_DONE */
        LOG_INF("Node 50 (logical 5): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 297, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 561, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);

        /* Gap: 231 minislots */
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1551, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 2475, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2508, 0, 33, NULL, 0);

        LOG_INF("Node 50: Completed 38 actions");
    } else if (node_id == 3504425116) {
        /* Physical Node 51 → Simulates Logical Node 6 */
        /* Actions: 2x RX_ERROR, 21x RX_TIMEOUT, 3x SYNCH_DONE, 12x TX_DONE */
        LOG_INF("Node 51 (logical 6): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 297, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1287, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2343, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2475, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2508, 0, 33, NULL, 0);

        LOG_INF("Node 51: Completed 38 actions");
    } else if (node_id == 1356940854) {
        /* Physical Node 52 → Simulates Logical Node 7 */
        /* Actions: 1x RX_ERROR, 22x RX_TIMEOUT, 3x SYNCH_DONE, 12x TX_DONE */
        LOG_INF("Node 52 (logical 7): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);

        /* Gap: 231 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);

        /* Gap: 231 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2343, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2475, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2508, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2970, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 3003, 0, 33, NULL, 0);

        LOG_INF("Node 52: Completed 38 actions");
    } else if (node_id == 2430687019) {
        /* Physical Node 53 → Simulates Logical Node 9 */
        /* Actions: 23x RX_TIMEOUT, 3x SYNCH_DONE, 12x TX_DONE */
        LOG_INF("Node 53 (logical 9): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 297, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1287, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2343, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2475, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2508, 0, 33, NULL, 0);

        LOG_INF("Node 53: Completed 38 actions");
    } else if (node_id == 283165229) {
        /* Physical Node 54 → Simulates Logical Node 10 */
        /* Actions: 23x RX_TIMEOUT, 3x SYNCH_DONE, 12x TX_DONE */
        LOG_INF("Node 54 (logical 10): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 297, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1287, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2343, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2475, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2508, 0, 33, NULL, 0);

        LOG_INF("Node 54: Completed 38 actions");
    } else if (node_id == 3504440328) {
        /* Physical Node 55 → Simulates Logical Node 11 */
        /* Actions: 2x RX_SUCCESS, 23x RX_TIMEOUT, 3x SYNCH_DONE, 10x TX_DONE */
        LOG_INF("Node 55 (logical 11): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 297, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 561, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1287, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1551, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2343, 0, 33, NULL, 0);

        LOG_INF("Node 55: Completed 38 actions");
    } else if (node_id == 3504395021) {
        /* Physical Node 56 → Simulates Logical Node 12 */
        /* Actions: 23x RX_TIMEOUT, 3x SYNCH_DONE, 12x TX_DONE */
        LOG_INF("Node 56 (logical 12): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 297, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1287, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2343, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2475, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2508, 0, 33, NULL, 0);

        LOG_INF("Node 56: Completed 38 actions");
    } else if (node_id == 3504507569) {
        /* Physical Node 57 → Simulates Logical Node 14 */
        /* Actions: 1x RX_ERROR, 23x RX_TIMEOUT, 3x SYNCH_DONE, 11x TX_DONE */
        LOG_INF("Node 57 (logical 14): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 297, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1287, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1320, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2343, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2475, 0, 33, NULL, 0);

        LOG_INF("Node 57: Completed 38 actions");
    } else if (node_id == 283279897) {
        /* Physical Node 58 → Simulates Logical Node 15 */
        /* Actions: 2x RX_ERROR, 24x RX_TIMEOUT, 3x SYNCH_DONE, 9x TX_DONE */
        LOG_INF("Node 58 (logical 15): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 297, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1287, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1320, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2343, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2376, 0, 33, NULL, 0);

        LOG_INF("Node 58: Completed 38 actions");
    } else if (node_id == 2430685849) {
        /* Physical Node 61 → Simulates Logical Node 16 */
        /* Actions: 1x RX_ERROR, 25x RX_TIMEOUT, 3x SYNCH_DONE, 9x TX_DONE */
        LOG_INF("Node 61 (logical 16): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 264, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 297, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 330, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1287, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1320, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2343, 0, 33, NULL, 0);

        LOG_INF("Node 61: Completed 38 actions");
    } else if (node_id == 3504505384) {
        /* Physical Node 62 → Simulates Logical Node 17 */
        /* Actions: 1x RX_ERROR, 26x RX_TIMEOUT, 3x SYNCH_DONE, 8x TX_DONE */
        LOG_INF("Node 62 (logical 17): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 264, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 297, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 330, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 1254, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1287, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1320, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1353, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);

        LOG_INF("Node 62: Completed 38 actions");
    } else if (node_id == 2430648359) {
        /* Physical Node 63 → Simulates Logical Node 18 */
        /* Actions: 2x RX_ERROR, 26x RX_TIMEOUT, 2x SYNCH_DONE, 8x TX_DONE */
        LOG_INF("Node 63 (logical 18): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 264, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 297, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 330, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 363, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 396, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1254, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1287, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1320, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1353, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1386, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);

        LOG_INF("Node 63: Completed 38 actions");
    } else if (node_id == 1356895520) {
        /* Physical Node 64 → Simulates Logical Node 19 */
        /* Actions: 28x RX_TIMEOUT, 2x SYNCH_DONE, 8x TX_DONE */
        LOG_INF("Node 64 (logical 19): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 264, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 297, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 330, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 363, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1254, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1287, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1320, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1353, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1386, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2244, 0, 33, NULL, 0);

        LOG_INF("Node 64: Completed 38 actions");
    } else if (node_id == 3504392353) {
        /* Physical Node 65 → Simulates Logical Node 26 */
        /* Actions: 2x RX_ERROR, 3x RX_SUCCESS, 18x RX_TIMEOUT, 3x SYNCH_DONE, 12x TX_DONE */
        LOG_INF("Node 65 (logical 26): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);

        /* Gap: 231 minislots */
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 528, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 561, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 594, 0, 33, NULL, 0);

        /* Gap: 396 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1221, 0, 33, NULL, 0);

        /* Gap: 264 minislots */
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1551, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 2475, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2508, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2541, 0, 33, NULL, 0);

        LOG_INF("Node 65: Completed 38 actions");
    } else if (node_id == 283202460) {
        /* Physical Node 70 → Simulates Logical Node 27 */
        /* Actions: 23x RX_TIMEOUT, 3x SYNCH_DONE, 12x TX_DONE */
        LOG_INF("Node 70 (logical 27): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);

        /* Gap: 231 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);

        /* Gap: 231 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2475, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2508, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2970, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 3003, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 3036, 0, 33, NULL, 0);

        LOG_INF("Node 70: Completed 38 actions");
    } else if (node_id == 1356896676) {
        /* Physical Node 71 → Simulates Logical Node 36 */
        /* Actions: 23x RX_TIMEOUT, 3x SYNCH_DONE, 12x TX_DONE */
        LOG_INF("Node 71 (logical 36): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);

        /* Gap: 231 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);

        /* Gap: 231 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2475, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2508, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2970, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 3003, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 3036, 0, 33, NULL, 0);

        LOG_INF("Node 71: Completed 38 actions");
    } else if (node_id == 283281171) {
        /* Physical Node 72 → Simulates Logical Node 109 */
        /* Actions: 3x RX_ERROR, 14x RX_TIMEOUT, 4x SYNCH_DONE, 16x TX_DONE */
        LOG_INF("Node 72 (logical 109): Replaying 37 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 198, 0, 33, NULL, 0);

        /* Gap: 297 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1188, 0, 33, NULL, 0);

        /* Gap: 297 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2211, 0, 33, NULL, 0);

        /* Gap: 264 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2475, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2508, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2970, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 3003, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 3036, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 3069, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 3102, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3135, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3168, 0, 33, NULL, 0);

        /* Gap: 297 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3465, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3498, 0, 33, NULL, 0);

        LOG_INF("Node 72: Completed 37 actions");
    } else if (node_id == 3504409141) {
        /* Physical Node 73 → Simulates Logical Node 118 */
        /* Actions: 5x RX_SUCCESS, 3x RX_TIMEOUT, 6x SYNCH_DONE, 22x TX_DONE */
        LOG_INF("Node 73 (logical 118): Replaying 36 actions");

        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 66, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 561, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1056, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1551, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2046, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 2475, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2508, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2541, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2970, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3003, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3036, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 3465, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3498, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3531, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 3960, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3993, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 4026, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 4455, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 4488, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 4521, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 4554, 0, 33, NULL, 0);

        /* Gap: 396 minislots */
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 4950, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 4983, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 5016, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 5445, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 5478, 0, 33, NULL, 0);

        LOG_INF("Node 73: Completed 36 actions");
    } else if (node_id == 283296289) {
        /* Physical Node 74 → Simulates Logical Node 2 */
        /* Actions: 23x RX_TIMEOUT, 3x SYNCH_DONE, 12x TX_DONE */
        LOG_INF("Node 74 (logical 2): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);

        /* Gap: 231 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);

        /* Gap: 231 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2475, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2508, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2970, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 3003, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 3036, 0, 33, NULL, 0);

        LOG_INF("Node 74: Completed 38 actions");
    } else if (node_id == 3504396712) {
        /* Physical Node 75 → Simulates Logical Node 3 */
        /* Actions: 23x RX_TIMEOUT, 3x SYNCH_DONE, 12x TX_DONE */
        LOG_INF("Node 75 (logical 3): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);

        /* Gap: 231 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1287, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2343, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2475, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2508, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2970, 0, 33, NULL, 0);

        LOG_INF("Node 75: Completed 38 actions");
    } else if (node_id == 283170447) {
        /* Physical Node 76 → Simulates Logical Node 4 */
        /* Actions: 2x RX_ERROR, 3x RX_SUCCESS, 20x RX_TIMEOUT, 3x SYNCH_DONE, 10x TX_DONE */
        LOG_INF("Node 76 (logical 4): Replaying 38 actions");

        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 33, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 66, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 99, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 132, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 165, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 198, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 231, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 264, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 297, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 561, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1023, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1056, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1089, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1122, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1155, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 1188, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 1221, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1254, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1287, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1551, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2013, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2046, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2079, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2112, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2145, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2178, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 2211, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 2244, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2277, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2310, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 2475, 0, 33, NULL, 0);

        LOG_INF("Node 76: Completed 38 actions");
    } else if (node_id == 3504391685) {
        /* Physical Node 77 → Simulates Logical Node 119 */
        /* Actions: 1x RX_ERROR, 7x RX_SUCCESS, 5x RX_TIMEOUT, 27x TX_DONE */
        LOG_INF("Node 77 (logical 119): Replaying 40 actions");

        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 0, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 33, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 495, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 528, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 561, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 990, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1023, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 1485, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1518, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1551, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 1980, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2013, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_ERROR, 0, base_slot + 2475, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 2508, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2541, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2574, 0, 33, NULL, 0);

        /* Gap: 396 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 2970, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3003, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 3465, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3498, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3531, 0, 33, NULL, 0);

        /* Gap: 429 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3960, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3993, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 4455, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 4488, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 4521, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 4554, 0, 33, NULL, 0);

        /* Gap: 396 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 4950, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 4983, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 5445, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 5478, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 5511, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 5544, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 5577, 0, 33, NULL, 0);

        /* Gap: 363 minislots */
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 5940, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 5973, 0, 33, NULL, 0);

        /* Gap: 462 minislots */
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 6435, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_TIMEOUT, 0, base_slot + 6468, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 6501, 0, 33, NULL, 0);
        sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 6534, 0, 33, NULL, 0);

        LOG_INF("Node 77: Completed 40 actions");
    } else {
        LOG_WRN("Unknown node_id: %u - no behavior configured", node_id);
        LOG_WRN("Known node IDs: see function header comment");
        return;
    }

    /* Flush logs */
    size_t bytes_written;
    sam_log_flush("EPOCH_1017", 1017, &bytes_written);
    LOG_INF("Epoch 1017 simulation complete - logs flushed: %zu bytes", bytes_written);
}

/* Application main entry point */
int main(void) {
    int ret;

    LOG_INF("SAM Logging Showcase Application");
    LOG_INF("================================");

    /* Initialize logging */
    ret = sam_log_init(5);
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

    showcase_dynamic_default_slots();
    k_sleep(K_MSEC(100));

    showcase_epoch_1017_realworld();
    k_sleep(K_MSEC(100));

    LOG_INF("Showcase complete!");
    return 0;
}