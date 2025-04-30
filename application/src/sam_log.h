#ifndef _SAM_LOG_H_
#define _SAM_LOG_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Status values */
enum sam_log_status {
  SAM_LOG_RX_SUCCESS             = 0x00,
  SAM_LOG_RX_TIMEOUT             = 0x01,
  SAM_LOG_RX_ERROR               = 0x02,
  SAM_LOG_RX_MALFORMED           = 0x03,
  SAM_LOG_RX_LISTEN_LATE         = 0x04,
  SAM_LOG_RX_LISTEN_FAIL         = 0x05,
  SAM_LOG_TIMER_EVENT            = 0x06, /* not used for now */
  SAM_LOG_TX_DONE                = 0x07,
  SAM_LOG_TX_SCHED_LATE          = 0x08,
  SAM_LOG_TX_SCHED_FAIL          = 0x09,
  SAM_LOG_SYNCH_DONE             = 0x0E,
  SAM_LOG_SYNCH_FAIL             = 0x0F,
  SAM_LOG_SKIP_SUCCESS           = 0x10, /* how many skipped? slots_to_use */
  SAM_LOG_RESTART_LATE           = 0x11, /* not used for now */
  SAM_LOG_RESTART_FAIL           = 0x12, /* not used for now */
  SAM_LOG_UNKNOWN                = 0x1E,
};

/* Header bit definitions */
#define SAM_LOG_HDR_SLOT_IDX             (1<<0)
#define SAM_LOG_HDR_SLOTS_TO_USE         (1<<1)
#define SAM_LOG_HDR_SLOT_IDX_DIFF        (1<<2)
#define SAM_LOG_HDR_SCAN                 (1<<3)  /* RX action w/ unlimited timeout */
#define SAM_LOG_HDR_CUSTOM_FIELDS        (1<<4)
#define SAM_LOG_HDR_DEFAULT_SLOTS_TO_USE (1<<5)

/* Bitmasks for m_hdr + status + reserved bits (first byte of every action) */
#define CUSTOM_STATUS_BITMASK                   (SAM_LOG_UNKNOWN << 2)
#define EXTENDED_HDR_BITMASK                    0x80

/* Structure for logging statistics */
struct sam_log_stats {
    uint32_t actions_logged;         /* Total actions logged */
    uint32_t actions_dropped;        /* Actions dropped due to buffer full */
    uint32_t custom_fields_logged;   /* Custom fields logged */
    uint32_t custom_fields_dropped;  /* Custom fields dropped */
};

/**
 * @brief Initialize the logging subsystem
 * 
 * @return int 0 on success, negative error code on failure
 */
int sam_log_init(void);

/**
 * @brief Log an action with all possible fields
 * 
 * @param status Status of the action
 * @param custom_status Custom status for custom actions
 * @param slot_idx Slot index of the action (actual slot where action occurred)
 * @param slot_idx_diff Difference from expected slot index
 * @param slots_to_use Number of slots used by the action (actual value)
 * @param set_default_slots Whether to set this slots_to_use as default
 * @param custom_data Pointer to custom data to be logged
 * @param custom_data_len Length of the custom data
 * @return int 0 on success, negative error code on failure
 */
int sam_log_action(enum sam_log_status status, uint16_t custom_status, 
                   uint32_t slot_idx, int16_t slot_idx_diff, 
                   uint8_t slots_to_use, bool set_default_slots,
                   const void *custom_data, uint16_t custom_data_len);

/**
 * @brief Log an action with only the status field
 * 
 * @param status Status of the action
 * @return int 0 on success, negative error code on failure
 */
int sam_log_action_status(enum sam_log_status status);

/**
 * @brief Get logging statistics
 * 
 * @param stats Pointer to statistics structure to be filled
 * @return int 0 on success, negative error code on failure
 */
int sam_log_get_stats(struct sam_log_stats *stats);

/**
 * @brief Flush logs and output as string
 * 
 * @param log_name Name identifier for this log
 * @param epoch_id Epoch ID or sequence number
 * @param bytes_written Pointer to store number of bytes written (can be NULL)
 * @return int 0 on success, negative error code on failure
 */
int sam_log_flush(char *log_name, uint32_t epoch_id, size_t *bytes_written);

#endif /* _SAM_LOG_H_ */