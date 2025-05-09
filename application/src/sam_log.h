#ifndef _SAM_LOG_H_
#define _SAM_LOG_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Buffer size configuration */
#define SAM_LOG_ACTIONS_BUF_SIZE 128
#define SAM_LOG_CUSTOM_BUF_SIZE 128

/* Status values */
enum sam_log_status {
    SAM_LOG_RX_SUCCESS = 0x00,
    SAM_LOG_RX_TIMEOUT = 0x01,
    SAM_LOG_RX_ERROR = 0x02,
    SAM_LOG_RX_MALFORMED = 0x03,
    SAM_LOG_RX_LISTEN_LATE = 0x04,
    SAM_LOG_RX_LISTEN_FAIL = 0x05,
    SAM_LOG_TIMER_EVENT = 0x06,
    SAM_LOG_TX_DONE = 0x07,
    SAM_LOG_TX_SCHED_LATE = 0x08,
    SAM_LOG_TX_SCHED_FAIL = 0x09,
    SAM_LOG_SYNCH_DONE = 0x0E,
    SAM_LOG_SYNCH_FAIL = 0x0F,
    SAM_LOG_SKIP_SUCCESS = 0x10,
    SAM_LOG_RESTART_LATE = 0x11,
    SAM_LOG_RESTART_FAIL = 0x12,
    SAM_LOG_UNKNOWN = 0x1E,
};

/* Structure for logging statistics */
struct sam_log_stats {
    uint32_t actions_logged;
    uint32_t actions_dropped;
    uint32_t custom_fields_logged;
    uint32_t custom_fields_dropped;
};

/**
 * Initialize the logging subsystem
 *
 * @return 0 on success, negative error code on failure
 */
int sam_log_init(void);

/**
 * Log an action with all possible fields
 *
 * @param status Status code of the action
 * @param custom_status Custom status value (used when status == SAM_LOG_UNKNOWN)
 * @param slot_idx Slot index where the action occurred
 * @param slot_idx_diff Difference between expected and actual slot index
 * @param slots_to_use Number of slots used by this action
 * @param set_default_slots Whether to set this as the default slots to use
 * @param custom_data Pointer to custom data to include with the action
 * @param custom_data_len Length of the custom data in bytes
 * @return 0 on success, negative error code on failure
 */
int sam_log_action(enum sam_log_status status, uint16_t custom_status, uint32_t slot_idx,
                   int16_t slot_idx_diff, uint8_t slots_to_use, bool set_default_slots,
                   const void *custom_data, uint16_t custom_data_len);

/**
 * Get logging statistics
 *
 * @param stats Pointer to a statistics structure to fill
 * @return 0 on success, negative error code on failure
 */
int sam_log_get_stats(struct sam_log_stats *stats);

/**
 * Flush logs and output as string
 *
 * @param log_name Name to identify the log section
 * @param epoch_id ID of the current epoch
 * @param bytes_written Pointer to store the number of bytes written
 * @return 0 on success, negative error code on failure
 */
int sam_log_flush(char *log_name, uint32_t epoch_id, size_t *bytes_written);

#endif /* _SAM_LOG_H_ */