#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "sam_log.h"

LOG_MODULE_REGISTER(main, CONFIG_LOG_DEFAULT_LEVEL);

/* Buffer for test custom data */
static uint8_t custom_data_buffer[256];

/* Test initialization */
static void test_init(void) {
    int ret;
    struct sam_log_stats stats;

    LOG_INF("Testing initialization");

    ret = sam_log_init();
    if (ret != 0) {
        LOG_ERR("Failed to initialize SAM logging: %d", ret);
        return;
    }

    sam_log_get_stats(&stats);
    LOG_INF("After init - logged: %u, dropped: %u", stats.actions_logged, stats.actions_dropped);

    LOG_INF("Initialization test complete");
}

/* Test basic logging functionality */
static void test_basic_logging(void) {
    int ret;
    struct sam_log_stats stats;
    size_t bytes_written;

    LOG_INF("Testing basic logging");

    /* Log a simple status-only action */
    ret = sam_log_action_status(SAM_LOG_RX_SUCCESS);
    if (ret != 0) {
        LOG_ERR("Failed to log simple action: %d", ret);
    }

    /* Log an action with slot_idx */
    ret = sam_log_action(SAM_LOG_TX_DONE, 0, 42, 0, 1, false, NULL, 0);
    if (ret != 0) {
        LOG_ERR("Failed to log action with slot_idx: %d", ret);
    }

    /* Get statistics */
    sam_log_get_stats(&stats);
    LOG_INF("After basic logging - logged: %u, dropped: %u", stats.actions_logged,
            stats.actions_dropped);

    /* Flush logs */
    ret = sam_log_flush("BASIC", 0, &bytes_written);
    if (ret != 0) {
        LOG_ERR("Failed to flush logs: %d", ret);
    }

    LOG_INF("Basic logging test complete");
}

/* Test custom data handling */
static void test_custom_data(void) {
    int ret;
    struct sam_log_stats stats;
    size_t bytes_written;

    LOG_INF("Testing custom data");

    /* Initialize test data */
    for (int i = 0; i < sizeof(custom_data_buffer); i++) {
        custom_data_buffer[i] = i & 0xFF;
    }

    /* Log with small custom data */
    ret = sam_log_action(SAM_LOG_RX_SUCCESS, 0, 100, 0, 1, false, custom_data_buffer, 16);
    if (ret != 0) {
        LOG_ERR("Failed to log with small custom data: %d", ret);
    }

    /* Log with medium custom data */
    ret = sam_log_action(SAM_LOG_TX_DONE, 0, 101, 0, 1, false, custom_data_buffer, 64);
    if (ret != 0) {
        LOG_ERR("Failed to log with medium custom data: %d", ret);
    }

    /* Log with large custom data */
    ret = sam_log_action(SAM_LOG_SYNCH_DONE, 0, 102, 0, 1, false, custom_data_buffer, 128);
    if (ret != 0) {
        LOG_ERR("Failed to log with large custom data: %d", ret);
    }

    /* Get statistics */
    sam_log_get_stats(&stats);
    LOG_INF("After custom data - logged: %u, custom: %u", stats.actions_logged,
            stats.custom_fields_logged);

    /* Flush logs */
    ret = sam_log_flush("CUSTOM", 0, &bytes_written);
    if (ret != 0) {
        LOG_ERR("Failed to flush logs: %d", ret);
    }

    LOG_INF("Custom data test complete");
}

/* Test all fields */
static void test_all_fields(void) {
    int ret;
    size_t bytes_written;

    LOG_INF("Testing all fields");

    /* Test with all fields set */
    ret = sam_log_action(SAM_LOG_RX_SUCCESS, 1234, 200, 5, 3, true, custom_data_buffer, 32);
    if (ret != 0) {
        LOG_ERR("Failed to log with all fields: %d", ret);
    }

    /* Test custom status */
    ret = sam_log_action(SAM_LOG_UNKNOWN, 9876, 201, 0, 1, false, NULL, 0);
    if (ret != 0) {
        LOG_ERR("Failed to log with custom status: %d", ret);
    }

    /* Flush logs */
    ret = sam_log_flush("ALLFIELDS", 0, &bytes_written);
    if (ret != 0) {
        LOG_ERR("Failed to flush logs: %d", ret);
    }

    LOG_INF("All fields test complete");
}

/* Test buffer overflow */
static void test_buffer_overflow(void) {
    int ret;
    struct sam_log_stats stats;
    size_t bytes_written;

    LOG_INF("Testing buffer overflow");

    /* Reset stats */
    sam_log_init();

    /* Log many actions to overflow the buffer */
    for (int i = 0; i < 200; i++) {
        ret = sam_log_action(SAM_LOG_RX_SUCCESS, 0, 300 + i, 0, 1, false, custom_data_buffer, 32);
        if (ret != 0 && i < 50) {
            LOG_ERR("Failed to log action during overflow test: %d", ret);
        }
    }

    /* Get statistics */
    sam_log_get_stats(&stats);
    LOG_INF("After overflow - logged: %u, dropped: %u", stats.actions_logged,
            stats.actions_dropped);

    /* Flush logs */
    ret = sam_log_flush("OVERFLOW", 0, &bytes_written);
    if (ret != 0) {
        LOG_ERR("Failed to flush logs: %d", ret);
    }

    LOG_INF("Buffer overflow test complete");
}

/* Test all supported statuses */
static void test_all_statuses(void) {
    int ret;
    size_t bytes_written;

    LOG_INF("Testing all status values");

    /* Log all possible status values */
    sam_log_action_status(SAM_LOG_RX_SUCCESS);
    sam_log_action_status(SAM_LOG_RX_TIMEOUT);
    sam_log_action_status(SAM_LOG_RX_ERROR);
    sam_log_action_status(SAM_LOG_RX_MALFORMED);
    sam_log_action_status(SAM_LOG_RX_LISTEN_LATE);
    sam_log_action_status(SAM_LOG_RX_LISTEN_FAIL);
    sam_log_action_status(SAM_LOG_TIMER_EVENT);
    sam_log_action_status(SAM_LOG_TX_DONE);
    sam_log_action_status(SAM_LOG_TX_SCHED_LATE);
    sam_log_action_status(SAM_LOG_TX_SCHED_FAIL);
    sam_log_action_status(SAM_LOG_SYNCH_DONE);
    sam_log_action_status(SAM_LOG_SYNCH_FAIL);
    sam_log_action_status(SAM_LOG_SKIP_SUCCESS);
    sam_log_action_status(SAM_LOG_RESTART_LATE);
    sam_log_action_status(SAM_LOG_RESTART_FAIL);
    sam_log_action_status(SAM_LOG_UNKNOWN);

    /* Flush logs */
    ret = sam_log_flush("STATUSES", 0, &bytes_written);
    if (ret != 0) {
        LOG_ERR("Failed to flush logs: %d", ret);
    }

    LOG_INF("All statuses test complete");
}

/* Simulate a realistic epoch sequence */
static void test_simulate_epoch(void) {
    int ret;
    size_t bytes_written;
    uint32_t base_slot = 1000;
    uint8_t custom_data[4] = {0xDE, 0xAD, 0xBE, 0xEF};

    LOG_INF("Simulating epoch sequence");

    /* Initialize for a clean test */
    sam_log_init();

    /* Start with RX listen */
    sam_log_action(SAM_LOG_RX_LISTEN_LATE, 0, base_slot, 0, 1, false, NULL, 0);

    /* Successful RX */
    sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 2, 0, 1, false, custom_data,
                   sizeof(custom_data));

    /* TX with larger slot use */
    sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3, 0, 2, true, NULL, 0);

    /* Sync */
    sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 10, 0, 1, false, NULL, 0);

    /* Skip slots */
    sam_log_action(SAM_LOG_SKIP_SUCCESS, 0, base_slot + 11, 0, 5, false, NULL, 0);

    /* RX timeout */
    sam_log_action_status(SAM_LOG_RX_TIMEOUT);

    /* TX late */
    sam_log_action(SAM_LOG_TX_SCHED_LATE, 0, base_slot + 17, 2, 1, false, NULL, 0);

    /* End sync */
    sam_log_action(SAM_LOG_SYNCH_FAIL, 0, base_slot + 20, -1, 1, false, custom_data,
                   sizeof(custom_data));

    /* Flush logs */
    ret = sam_log_flush("EPOCH", 0, &bytes_written);
    if (ret != 0) {
        LOG_ERR("Failed to flush logs: %d", ret);
    }

    LOG_INF("Epoch simulation complete");
}

int main(void) {
    LOG_INF("SAM Logging Test Application");

    /* Run all tests */
    test_init();
    k_sleep(K_MSEC(100));

    test_basic_logging();
    k_sleep(K_MSEC(100));

    test_custom_data();
    k_sleep(K_MSEC(100));

    test_all_fields();
    k_sleep(K_MSEC(100));

    test_buffer_overflow();
    k_sleep(K_MSEC(100));

    test_all_statuses();
    k_sleep(K_MSEC(100));

    test_simulate_epoch();
    k_sleep(K_MSEC(100));

    LOG_INF("All tests complete");

    while (1) {
        k_sleep(K_SECONDS(1));
    }

    return 0;
}