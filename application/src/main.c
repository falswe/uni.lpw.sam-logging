#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include "sam_log.h"

LOG_MODULE_REGISTER(main, CONFIG_LOG_DEFAULT_LEVEL);

/* Simulate a simple SAM epoch with various actions */
static void simulate_epoch(int epoch_num)
{
    uint32_t base_slot = epoch_num * 100;
    struct sam_log_stats stats;
    size_t bytes_written;
    
    LOG_INF("Starting epoch %d", epoch_num);
    
    /* First, simulate some RX actions */
    sam_log_action(SAM_LOG_RX_LISTEN_LATE, 0, base_slot, 0, 1, false, NULL, 0);
    
    /* Simulate a successful RX with custom data */
    uint8_t custom_data[4] = {0x01, 0x02, 0x03, 0x04};
    sam_log_action(SAM_LOG_RX_SUCCESS, 0, base_slot + 2, 0, 1, false, custom_data, sizeof(custom_data));
    
    /* Simulate a TX action with larger slot use */
    sam_log_action(SAM_LOG_TX_DONE, 0, base_slot + 3, 0, 2, true, NULL, 0);
    
    /* Simulate a synchronization */
    sam_log_action(SAM_LOG_SYNCH_DONE, 0, base_slot + 10, 0, 1, false, NULL, 0);
    
    /* Simulate a sync fail with custom error data */
    uint8_t error_data[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    sam_log_action(SAM_LOG_SYNCH_FAIL, 0, base_slot + 15, -2, 1, false, error_data, sizeof(error_data));
    
    /* Use the simple status-only logging */
    sam_log_action_status(SAM_LOG_RX_TIMEOUT);
    sam_log_action_status(SAM_LOG_RX_ERROR);
    
    /* Skip some slots */
    sam_log_action(SAM_LOG_SKIP_SUCCESS, 0, base_slot + 20, 0, 10, false, NULL, 0);
    
    /* Get and display stats */
    sam_log_get_stats(&stats);
    LOG_INF("Actions logged: %u, dropped: %u", stats.actions_logged, stats.actions_dropped);
    
    /* Flush logs at end of epoch */
    char epoch_name[16];
    snprintf(epoch_name, sizeof(epoch_name), "E%d", epoch_num);
    sam_log_flush(epoch_name, 0, &bytes_written);
    
    LOG_INF("Epoch %d complete", epoch_num);
    k_sleep(K_MSEC(100));
}

int main(void)
{
    int ret;
    
    LOG_INF("SAM Logging Test Application");
    
    /* Initialize SAM logging */
    ret = sam_log_init();
    if (ret != 0) {
        LOG_ERR("Failed to initialize SAM logging: %d", ret);
        return 1;
    }
    
    LOG_INF("SAM logging initialized");
    
    /* Simulate several epochs */
    for (int i = 0; i < 5; i++) {
        simulate_epoch(i);
    }
    
    LOG_INF("Test complete");
    
    while (1) {
        k_sleep(K_SECONDS(1));
    }

    return 0;
}