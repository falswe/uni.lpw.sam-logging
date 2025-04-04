#ifndef SAM_LOG_H_
#define SAM_LOG_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h> // For size_t
#include <zephyr/kernel.h> // For errno codes like ENOSPC
#include <zephyr/ring_buffer.h>

// --- Status Codes ---
// (Ensure this matches your actual definition)
enum sam_log_status {
  SAM_LOG_RX_SUCCESS                 =  0,
  SAM_LOG_RX_TIMEOUT                 =  1,
  SAM_LOG_RX_ERROR                   =  2,
  SAM_LOG_RX_MALFORMED               =  3,
  SAM_LOG_RX_LISTEN_LATE             =  4,
  SAM_LOG_RX_LISTEN_FAIL             =  5,
  SAM_LOG_TIMER_EVENT                =  6,
  SAM_LOG_TX_DONE                    =  7,
  SAM_LOG_TX_SCHED_LATE              =  8,
  SAM_LOG_TX_SCHED_FAIL              =  9,
  // ... add others as needed ...
  SAM_LOG_SYNCH_DONE                 = 14,
  SAM_LOG_SKIP_SUCCESS               = 15,
  SAM_LOG_RESTART_LATE               = 16,
  SAM_LOG_RESTART_FAIL               = 17,
  SAM_LOG_UNKNOWN                    = 18,
  // ... value 30 reserved for custom status trigger ...
  SAM_LOG_MAX // Keep track of the number of statuses
};

/**
 * @brief Status code indicating the custom_status field is relevant and should
 * be included in the final output stream.
 */
#define SAM_LOG_STATUS_CUSTOM             (0x1E) // = 30


// --- Header Mask Definitions ('hdr' field bits) ---
// Indicate if corresponding field is potentially PRESENT in FINAL bit-packed OUTPUT stream.

/** @brief Bit in 'hdr': Indicates slot_idx is potentially present in the output stream. */
#define SAM_LOG_HDR_MASK_SLOT_IDX         (1 << 0) // = 0x01
/** @brief Bit in 'hdr': Indicates slots_to_use is potentially present in the output stream. */
#define SAM_LOG_HDR_MASK_SLOTS_TO_USE     (1 << 1) // = 0x02
/** @brief Bit in 'hdr': Indicates slot_idx_diff is potentially present in the output stream. */
#define SAM_LOG_HDR_MASK_SLOT_IDX_DIFF    (1 << 2) // = 0x04
/** @brief Bit in 'hdr': Indicates related scan information is relevant (meaning TBD). */
#define SAM_LOG_HDR_MASK_SCAN             (1 << 3) // = 0x08
/** @brief Bit in 'hdr': Indicates sync success info is relevant (meaning TBD). */
#define SAM_LOG_HDR_MASK_SYNC_SUCCESS     (1 << 4) // = 0x10
/** @brief Bit in 'hdr': If set, the slots_to_use value becomes the new default for the encoder. */
#define SAM_LOG_HDR_MASK_SET_DEFAULT_SLOTS (1 << 5) // = 0x20
/** @brief Bit in 'hdr': Indicates custom fields are potentially present in the output stream. */
#define SAM_LOG_HDR_MASK_CUSTOM_FIELDS    (1 << 6) // = 0x40
// Bit 7 (0x80) is currently unused/reserved.


// --- Default Values (for Encoder Logic) ---

/** @brief The initial default value for slots_to_use tracked by the encoder. */
#define SAM_LOG_DEFAULT_SLOTS_TO_USE      (4)
/** @brief The default value for slot_idx used by encoder for omission check. */
#define SAM_LOG_DEFAULT_SLOT_IDX          (0xFFFFFFFF)


// --- Ringbuffer Configuration ---

/** @brief The capacity (in entries) of the first ("start") logging instance's action buffer. */
#define SAM_LOG_START_LOG_CAPACITY        (32)
// Note: Define buffer sizes in sam_log.c based on this capacity and struct size.
// Also need sizes for the custom data buffers and end buffers.


// --- Log Entry Structure (Ring Buffer Format) ---

/**
 * @brief Structure for storing log entry metadata in the primary ring buffer.
 * Uses packed attribute to minimize padding.
 */
struct sam_log_rb_entry {
    uint8_t status;           // See enum sam_log_status
    uint16_t custom_status;    // Custom code, only relevant if status == SAM_LOG_STATUS_CUSTOM
    uint8_t hdr;              // Header flags (SAM_LOG_HDR_MASK_*)
    uint32_t slot_idx;         // Slot index of action
    int16_t slot_idx_diff;     // Signed difference from expected slot
    uint8_t slots_to_use;      // Slots used by this action
    uint16_t total_custom_len; // Bytes of associated data in custom ring buffer
} __attribute__((packed)); // Ensure no padding


// --- Public API ---

/**
 * @brief Initializes the SAM logging subsystem (ring buffers).
 *
 * @return 0 on success, negative errno code on failure.
 */
int sam_log_init(void);

/**
 * @brief Logs an action's result and associated metadata.
 *
 * This function prepares the log entry structure and attempts to add it
 * (along with any custom data) to the appropriate ring buffers.
 * It MUST be called from within the SAM action's critical section.
 *
 * @param status            The primary status result (enum sam_log_status).
 * @param custom_status     The custom status code (relevant if status == SAM_LOG_STATUS_CUSTOM).
 * @param slot_idx          The slot index associated with the action.
 * @param slot_idx_diff     The slot difference (actual - expected).
 * @param slots_to_use      The number of slots used by this action.
 * @param set_default_slots If true, this action's slots_to_use becomes the new default (sets flag in hdr).
 * @param custom_data       Pointer to custom data payload (can be NULL if no custom data).
 * @param custom_data_len   Length of the custom data payload in bytes (must be 0 if custom_data is NULL).
 *
 * @return 0 on success, negative errno code on failure (e.g., -ENOSPC if buffer full).
 */
int sam_log_action_result(
    enum sam_log_status status,
    uint16_t custom_status,
    uint32_t slot_idx,
    int16_t slot_idx_diff,
    uint8_t slots_to_use,
    bool set_default_slots,
    const void *custom_data,
    uint16_t custom_data_len
);


/**
 * @brief Reads logged data and outputs it in the final serialized format.
 *
 * @param output_buffer Pointer to the buffer where the serialized data will be written.
 * @param buffer_size   The maximum size of the output buffer.
 * @param[out] bytes_written Pointer to store the actual number of bytes written to output_buffer.
 *
 * @return 0 on success, negative errno code on failure.
 */
int sam_log_flush_and_encode(uint8_t *output_buffer, size_t buffer_size, size_t *bytes_written);


#endif // SAM_LOG_H_