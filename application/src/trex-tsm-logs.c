#include "trex-tsm-logs.h"

#include <stdio.h>
#include <string.h>

#include "ascii85.h"
#include "print-def.h"

#define LOG_PREFIX "tsml"
#define LOG_LEVEL LOG_WARN
#include "logging.h"

/**
 * Event status codes for time-slotted medium (TSM) operations.
 * These represent different outcomes that can occur during communication slots.
 */
enum tsm_log_status {
    RX_SUCCESS = 0,    // Packet received successfully
    RX_TIMEOUT = 1,    // Reception timed out (no packet)
    RX_ERROR = 2,      // Reception error occurred
    RX_MALFORMED = 3,  // Received packet was malformed
    TIMER_EVENT = 4,   // Timer expired
    TX_DONE = 5,       // Transmission completed
#if TARGET == evb1000
    // Frame sync events (hardware-specific)
    FS_EMPTY = 6,                    // Frame sync empty
    FS_DETECTED = 7,                 // Frame sync detected
    FS_DETECTED_AND_PROPAGATED = 8,  // Frame sync detected and propagated
    FS_ERROR = 9,                    // Frame sync error
#endif
    RX_WITH_SYNCH = 10,    // Received packet with synchronization
    SCAN_WITH_SYNCH = 11,  // Scan with synchronization
    UNKNOWN = 12,          // Unknown/invalid status
};

/**
 * Compressed log entry structure.
 * Total size: 9 bytes + 5 bits (maximum when all fields are present)
 *
 * Fields are conditionally included based on header flags to save space.
 */
struct tsm_log_t {
    // Header bit flag is added automatically by add_value()
    enum tsm_log_status status : 4;  // 4 bits: Event status code

    uint8_t hdr;                // 8 bits: Flags indicating which optional fields are present
    uint32_t minislot : 24;     // 24 bits: Time slot index (only if MASK_MINISLOTS flag set)
    int16_t minislot_idx_diff;  // 16 bits: Difference from expected slot (only if
                                // MASK_MINISLOTS_IDX_DIFF flag set)

    uint8_t minislots_to_use;  // 8 bits: Number of minislots to use (only if MASK_MINISLOTS_TO_USE
                               // flag set)
    uint16_t progress_minislots;  // 16 bits: Progress tracking (only if MASK_PROGRESS_MINISLOTS
                                  // flag set)
};

/**
 * State for bit-level buffer writing.
 * Tracks current write position within a byte (not byte-aligned).
 */
struct bitbuf_state_t {
    uint8_t* dest_buf;  // Pointer to current byte in destination buffer
    uint8_t offset;     // Bit offset within current byte (0-7)
};

// Maximum number of log entries to store
#ifndef TSM_LOGS_MAX
#define TSM_LOGS_MAX 192
#endif

#pragma message STRDEF(TSM_LOGS_MAX)

/**
 * Global state for the TSM logging system.
 */
static struct {
    uint8_t
        log_str[TSM_LOGS_MAX + 5];  // Buffer: 5 bytes header + up to TSM_LOGS_MAX bytes of log data
    uint16_t
        logged_slots;  // Number of slots actually logged (may be less than nslots if buffer full)
    uint16_t nslots;   // Total number of slots that occurred
    struct bitbuf_state_t bitbuf_state;  // Current bit-level write position
} tsm_log_state;

/**
 * Convert TREX status codes to TSM log status codes.
 * Handles synchronization flags and action types.
 */
static inline enum tsm_log_status convert_status(enum trex_status status, enum tsm_action action,
                                                 bool accept_sync) {
    switch (status) {
        case TREX_RX_SUCCESS:
            // Differentiate based on action type and synchronization
            if (action == TSM_ACTION_SCAN) {
                if (accept_sync) {
                    return SCAN_WITH_SYNCH;
                } else {
                    return SCAN_WITH_SYNCH;  // TODO: Should be changed to something else
                }
            } else if (accept_sync) {
                return RX_WITH_SYNCH;
            } else {
                return RX_SUCCESS;
            }
        case TREX_RX_TIMEOUT:
            return RX_TIMEOUT;
        case TREX_RX_ERROR:
            return RX_ERROR;
        case TREX_RX_MALFORMED:
            return RX_MALFORMED;
        case TREX_TIMER_EVENT:
            return TIMER_EVENT;
        case TREX_TX_DONE:
            return TX_DONE;
#if TARGET == evb1000
        // Hardware-specific frame sync events
        case TREX_FS_EMPTY:
            return FS_EMPTY;
        case TREX_FS_DETECTED:
            return FS_DETECTED;
        case TREX_FS_DETECTED_AND_PROPAGATED:
            return FS_DETECTED_AND_PROPAGATED;
        case TREX_FS_ERROR:
            return FS_ERROR;
#endif
        case TREX_NONE:
            WARN("Tried to log TREX_NONE");
            return UNKNOWN;
        default:
            WARN("Unknown trex_status value");
            return UNKNOWN;
    }
}

/**
 * Initialize the TSM logging system.
 * Clears all buffers and resets counters.
 */
void tsm_log_init() {
    memset(tsm_log_state.log_str, 0, sizeof(tsm_log_state.log_str) / sizeof(uint8_t));
    tsm_log_state.logged_slots = 0;
    tsm_log_state.nslots = 0;

    // Set write pointer to start after 5-byte header
    tsm_log_state.bitbuf_state.dest_buf = tsm_log_state.log_str + 5;
    tsm_log_state.bitbuf_state.offset = 0;
}

/**
 * Write a value to the bit buffer at an arbitrary bit offset.
 * This allows packing data at the bit level rather than byte boundaries.
 *
 * @param value     The value to write (will be masked to 'bits' bits)
 * @param bits      Number of bits to write (1-8)
 * @param dest_buf  Current buffer state
 * @return          Updated buffer state
 *
 * Example: Writing 4 bits starting at offset 3 in a byte
 *   Before: [xxxyy---][--------]
 *   After:  [xxxyyvvv][v-------]
 *   where x = old bits, y = old bits, v = new value bits
 */
static inline struct bitbuf_state_t add_on_offset(uint8_t value, uint8_t bits,
                                                  struct bitbuf_state_t dest_buf) {
    // Write high bits of value into remaining bits of current byte
    // Shift value left to align MSB, then shift right by offset to position correctly
    dest_buf.dest_buf[0] |= (value << (8 - bits)) >> dest_buf.offset;

    // If the value spans two bytes, write the low bits to the next byte
    if (bits + dest_buf.offset >= 8) {
        dest_buf.dest_buf[1] |= (value << (8 - bits)) << (8 - dest_buf.offset);
        dest_buf.dest_buf += 1;  // Move to next byte
    }

    // Update bit offset within current byte (wraps at 8)
    dest_buf.offset = (bits + dest_buf.offset) % 8;

    return dest_buf;
}

// Header bit masks indicating which optional fields are present
#define MASK_MINISLOTS 1                  // Bit 0: minislot field present
#define MASK_MINISLOTS_IDX_DIFF (1 << 1)  // Bit 1: minislot_idx_diff field present
#define MASK_MINISLOTS_TO_USE (1 << 2)    // Bit 2: minislots_to_use field present
#define MASK_PROGRESS_MINISLOTS (1 << 3)  // Bit 3: progress_minislots field present

/**
 * Serialize a log entry into the bit buffer.
 * Only includes fields that are flagged in the header to save space.
 *
 * Format:
 *   1 bit:  Header present flag (1 if hdr != 0)
 *   4 bits: Status code
 *   [8 bits: Header byte - only if header flag = 1]
 *   [24 bits: Minislot index - only if MASK_MINISLOTS set]
 *   [16 bits: Minislot diff - only if MASK_MINISLOTS_IDX_DIFF set]
 *   [8 bits: Minislots to use - only if MASK_MINISLOTS_TO_USE set]
 *   [16 bits: Progress - only if MASK_PROGRESS_MINISLOTS set]
 */
static inline struct bitbuf_state_t add_value(const struct tsm_log_t val,
                                              struct bitbuf_state_t dest_buf) {
    // Write mandatory fields
    dest_buf = add_on_offset(val.hdr != 0, 1, dest_buf);       // 1 bit: header present flag
    dest_buf = add_on_offset(val.status & 0x0f, 4, dest_buf);  // 4 bits: status

    // Write header byte if any optional fields are present
    if (val.hdr != 0) {
        dest_buf = add_on_offset(val.hdr, 8, dest_buf);
    }

    // Write optional fields based on header flags
    if (val.hdr & MASK_MINISLOTS) {
        // Write 24-bit minislot index (big-endian)
        dest_buf = add_on_offset((val.minislot >> 16) & 0xff, 8, dest_buf);
        dest_buf = add_on_offset((val.minislot >> 8) & 0xff, 8, dest_buf);
        dest_buf = add_on_offset((val.minislot) & 0xff, 8, dest_buf);
    }

    if (val.hdr & MASK_MINISLOTS_IDX_DIFF) {
        // Write 16-bit signed difference (big-endian)
        dest_buf = add_on_offset((val.minislot_idx_diff >> 8) & 0xff, 8, dest_buf);
        dest_buf = add_on_offset((val.minislot_idx_diff) & 0xff, 8, dest_buf);
    }

    if (val.hdr & MASK_MINISLOTS_TO_USE) {
        dest_buf = add_on_offset(val.minislots_to_use, 8, dest_buf);
    }

    if (val.hdr & MASK_PROGRESS_MINISLOTS) {
        // Write 16-bit progress (big-endian)
        dest_buf = add_on_offset((val.progress_minislots >> 8) & 0xff, 8, dest_buf);
        dest_buf = add_on_offset((val.progress_minislots) & 0xff, 8, dest_buf);
    }

    return dest_buf;
}

/**
 * Append a new log entry for a TSM slot event.
 *
 * @param status                Event status from TREX layer
 * @param action                Action being performed (scan, etc.)
 * @param accept_sync           Whether synchronization was accepted
 * @param minislot_idx          Current minislot index
 * @param minislots_to_use      Number of minislots configured for this operation
 * @param progress_minislots    Progress tracking value
 * @param minislot_idx_diff     Difference between expected and actual slot
 */
void tsm_log_append(enum trex_status status, enum tsm_action action, bool accept_sync,
                    uint32_t minislot_idx, uint8_t minislots_to_use, uint16_t progress_minislots,
                    int16_t minislot_idx_diff) {
    // Increment total slot count
    ++tsm_log_state.nslots;
    if (tsm_log_state.nslots == 0) {
        // Counter wrapped around (overflow)
        ERR("tsm_log_state.logged_slots overflow");
        return;
    }

    // Check if we have enough space for this entry
    // Maximum size: 9 bytes + 5 bits (77 bits total)
    // With maximum offset of 7 bits, this could span up to 11 bytes
    // Using > instead of >= for one extra byte of safety margin
    if (!(tsm_log_state.log_str + sizeof(tsm_log_state.log_str) / sizeof(uint8_t) -
              tsm_log_state.bitbuf_state.dest_buf >
          11)) {
        // Not enough space remaining in buffer
        return;
    }

    // Check if we've hit the maximum number of logged slots
    if (tsm_log_state.logged_slots + 1 <= TSM_LOGS_MAX) {
        ++tsm_log_state.logged_slots;
    } else {
        // Buffer full, can't log this entry
        return;
    }

    // Build the log entry
    struct tsm_log_t val = {
        .hdr = 0,  // Start with no optional fields
        .status = convert_status(status, action, accept_sync),
        .progress_minislots = progress_minislots,
        .minislots_to_use = minislots_to_use,
        .minislot = minislot_idx,
    };

    // For synchronization events, always include the minislot index
    if (val.status == RX_WITH_SYNCH || val.status == SCAN_WITH_SYNCH) {
        val.hdr |= MASK_MINISLOTS;

        // Don't log the diff during sync (expected diff, not an error)
        val.minislot_idx_diff = 0;
    }

    // Only include non-zero diff values (save space)
    if (val.minislot_idx_diff != 0) {
        val.hdr |= MASK_MINISLOTS_IDX_DIFF;
    }

    // Only include non-default values (save space)
    if (val.minislots_to_use != TSM_DEFAULT_MINISLOTS_GROUPING) {
        val.hdr |= MASK_MINISLOTS_TO_USE;
    }

    if (val.progress_minislots != TSM_DEFAULT_MINISLOTS_GROUPING) {
        val.hdr |= MASK_PROGRESS_MINISLOTS;
    }

    // Serialize entry into bit buffer
    tsm_log_state.bitbuf_state = add_value(val, tsm_log_state.bitbuf_state);
}

#undef MASK_MINISLOTS
#undef MASK_MINISLOTS_IDX_DIFF
#undef MASK_MINISLOTS_TO_USE
#undef MASK_PROGRESS_MINISLOTS

/**
 * Print the accumulated log buffer and reset the log.
 *
 * Encoding process:
 * 1. Write 5-byte header containing metadata
 * 2. Encode entire buffer (header + log data) to ASCII85
 * 3. Print the result
 * 4. Reset log for next collection period
 */
void tsm_log_print() {
    // Allocate output buffer for ASCII85 encoded data
    // ASCII85 expands data by 5/4, so we need (input_bytes / 4) * 5 bytes
    uint8_t out_buf[((sizeof(tsm_log_state.log_str) + 3) / 4) * 5 + 1];
    memset(out_buf, 0, sizeof(out_buf) / sizeof(uint8_t));

    // Write 5-byte header at start of log buffer
    tsm_log_state.log_str[0] = TSM_DEFAULT_MINISLOTS_GROUPING & 0xff;  // Default grouping value
    tsm_log_state.log_str[1] =
        (tsm_log_state.logged_slots >> 8) & 0xff;                   // High byte of logged slots
    tsm_log_state.log_str[2] = tsm_log_state.logged_slots & 0xff;   // Low byte of logged slots
    tsm_log_state.log_str[3] = (tsm_log_state.nslots >> 8) & 0xff;  // High byte of total slots
    tsm_log_state.log_str[4] = tsm_log_state.nslots & 0xff;         // Low byte of total slots

    // Encode binary log to ASCII85 for safe text transmission
    // Length: from start to current write position + 1 byte
    ascii85_encode(out_buf, sizeof(out_buf) / sizeof(uint8_t), tsm_log_state.log_str,
                   tsm_log_state.bitbuf_state.dest_buf + 1 - tsm_log_state.log_str + 1);

    // Print the encoded log with logging context
    printf("[" LOG_PREFIX " %lu]Slots: %s\n", logging_context, out_buf);

    // Reset the log for next collection period
    tsm_log_init();
}