#ifndef _SAM_LOG_H_
#define _SAM_LOG_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

/* Header bit definitions */
#define SAM_LOG_HDR_SLOT_IDX (1 << 0)
#define SAM_LOG_HDR_SLOTS_TO_USE (1 << 1)
#define SAM_LOG_HDR_SLOT_IDX_DIFF (1 << 2)
#define SAM_LOG_HDR_SCAN (1 << 3)
#define SAM_LOG_HDR_CUSTOM_FIELDS (1 << 4)
#define SAM_LOG_HDR_DEFAULT_SLOTS_TO_USE (1 << 5)

/* Structure for logging statistics */
struct sam_log_stats {
    uint32_t actions_logged;
    uint32_t actions_dropped;
    uint32_t custom_fields_logged;
    uint32_t custom_fields_dropped;
};

/**
 * Initialize the logging subsystem
 */
int sam_log_init(void);

/**
 * Log an action with all possible fields
 */
int sam_log_action(enum sam_log_status status, uint16_t custom_status, uint32_t slot_idx,
                   int16_t slot_idx_diff, uint8_t slots_to_use, bool set_default_slots,
                   const void *custom_data, uint16_t custom_data_len);

/**
 * Get logging statistics
 */
int sam_log_get_stats(struct sam_log_stats *stats);

/**
 * Flush logs and output as string
 */
int sam_log_flush(char *log_name, uint32_t epoch_id, size_t *bytes_written);

#endif /* _SAM_LOG_H_ */