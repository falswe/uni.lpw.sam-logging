#include "sam_log.h"

#include <errno.h>   // Include errno definitions like ENOSPC, EIO
#include <string.h>  // For strncpy
#include <zephyr/logging/log.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/byteorder.h>  // For sys_put_be16, sys_put_be32, etc.

// Register logging module for this file
LOG_MODULE_REGISTER(sam_log, CONFIG_SAM_LOG_LEVEL);  // Adjust CONFIG_SAM_LOG_LEVEL as needed

// --- Buffer Sizes ---
// Calculate based on capacity and struct size, add some leeway.
// Sizes need careful tuning based on expected max custom data and memory
// constraints.
#define ACTION_RB_START_SIZE (SAM_LOG_START_LOG_CAPACITY * sizeof(struct sam_log_action)) // TODO: This doesn't look right. We can't know the exact capacity, as the elements have varying sizes.
#define CUSTOM_RB_START_SIZE \
    (ACTION_RB_START_SIZE * 2)  // Example: Assume avg custom data is similar size to entry // TODO: Why should it be double the size?

// End buffers need a reasonable size for capturing events after start buffer is
// full
#define ACTION_RB_END_CAPACITY (64)  // Example capacity // TODO: Let's have this in sam_log.h too
#define ACTION_RB_END_SIZE (ACTION_RB_END_CAPACITY * sizeof(struct sam_log_action))
#define CUSTOM_RB_END_SIZE (ACTION_RB_END_SIZE * 2)  // Example sizing

// Output buffer size for flush operations
#define OUTPUT_BUFFER_SIZE (4096)  // Example - adjust based on expected output size
// --- Module Static Buffers ---
// Start Buffers (First N entries)
static uint8_t action_buf_start[ACTION_RB_START_SIZE];
static uint8_t custom_buf_start[CUSTOM_RB_START_SIZE];
RING_BUF_DECLARE(action_rb_start, ACTION_RB_START_SIZE);
RING_BUF_DECLARE(custom_rb_start, CUSTOM_RB_START_SIZE);

// End Buffers (Circular after start is full)
static uint8_t action_buf_end[ACTION_RB_END_SIZE];
static uint8_t custom_buf_end[CUSTOM_RB_END_SIZE];
RING_BUF_DECLARE(action_rb_end, ACTION_RB_END_SIZE);
RING_BUF_DECLARE(custom_rb_end, CUSTOM_RB_END_SIZE);

// Output buffer for serialized data
static uint8_t output_buffer[OUTPUT_BUFFER_SIZE]; // TODO: This should be a file stream

// --- Module State ---
static uint32_t sam_log_start_count = 0; // TODO: Does Zephyr have an API for that?
static bool sam_log_active_is_start = true;
static bool sam_log_initialized = false;
static char sam_log_name[8] = {0};  // Storage for log name

// --- Encoder Helper Definitions ---
/**
 * @brief Encoder state for tracking context during serialization.
 */
struct encoder_state {
    uint8_t default_slots_to_use;     // Current default for slots_to_use
    uint32_t last_sync_slot_idx;      // Last known synchronized slot index
    uint32_t expected_next_slot_idx;  // Expected next slot based on last slot + slots used
    bool has_sync_reference;          // Whether we have a valid sync reference
};

// Current bit positions as defined in design.md
#define BIT_POS_M_HDR 0
#define BIT_POS_STATUS 1
// If m_hdr = 0, only 6 bits total (1 for m_hdr, 5 for status)
#define MIN_ENCODED_BITS 6

// Bit positions relative to the start of extended fields (after m_hdr and status)
// TODO: Should be figured out dynamically.
#define BIT_POS_CUSTOM_STATUS 0
#define BIT_POS_HDR 16
#define BIT_POS_SLOT_IDX 24
#define BIT_POS_SLOT_IDX_DIFF 48
#define BIT_POS_SLOTS_TO_USE 64
#define BIT_POS_CUSTOM_LEN 72

/**
 * @brief Write bits to a byte buffer at specified bit position.
 *
 * @param buffer Output buffer to write to.
 * @param buffer_size Size of the output buffer in bytes.
 * @param bit_pos Current bit position in the buffer.
 * @param value Value to write.
 * @param num_bits Number of bits to write from the value.
 * @return New bit position after write, or negative errno on error.
 */
static int write_bits(uint8_t *buffer, size_t buffer_size, int bit_pos, uint64_t value,
                      int num_bits) {
    if (!buffer || bit_pos < 0) {
        return -EINVAL;
    }

    // Check if enough space in buffer
    int end_bit_pos = bit_pos + num_bits - 1;
    if ((end_bit_pos / 8) >= buffer_size) {
        LOG_ERR("Buffer overflow: need %d bytes, have %zu", (end_bit_pos / 8) + 1, buffer_size);
        return -ENOSPC;
    }

    // Write bits
    int current_byte = bit_pos / 8;
    int bit_offset = bit_pos % 8;

    // Mask out bits we don't want from the value
    uint64_t masked_value = value & ((1ULL << num_bits) - 1);

    // Write bits across potentially multiple bytes
    while (num_bits > 0) {
        int bits_to_write = MIN(8 - bit_offset, num_bits);
        uint8_t mask = ((1 << bits_to_write) - 1) << bit_offset;

        // Clear the bits we'll write to
        buffer[current_byte] &= ~mask;

        // Set those bits with our value
        buffer[current_byte] |= ((masked_value & ((1 << bits_to_write) - 1)) << bit_offset);

        // Move to next set of bits
        masked_value >>= bits_to_write;
        num_bits -= bits_to_write;
        current_byte++;
        bit_offset = 0;  // Start at beginning of next byte
    }

    return end_bit_pos + 1;  // New bit position
}

/**
 * @brief Initialize the encoder state with defaults.
 *
 * @param state Encoder state to initialize.
 */
static void encoder_init(struct encoder_state *state) {
    state->default_slots_to_use = SAM_LOG_DEFAULT_SLOTS_TO_USE;
    state->last_sync_slot_idx = 0;
    state->expected_next_slot_idx = 0;
    state->has_sync_reference = false;
}

/**
 * @brief Encode a single log entry into the output buffer.
 *
 * @param state Current encoder state (updated as a side effect).
 * @param entry The log entry to encode.
 * @param custom_data Pointer to any custom data associated with this entry.
 * @param output_buffer Buffer to write encoded data to.
 * @param buffer_size Size of the output buffer in bytes.
 * @param bit_pos Current bit position in the output buffer.
 * @param bytes_written Pointer to update with bytes written.
 * @return New bit position after encoding, or negative errno on error.
 */
static int encode_entry(struct encoder_state *state, struct sam_log_action *entry,
                        const uint8_t *custom_data, uint8_t *output_buffer, size_t buffer_size,
                        int bit_pos, size_t *bytes_written) {
    // --- Determine which fields to include ---
    bool include_custom_status = (entry->status == SAM_LOG_STATUS_CUSTOM);
    bool is_sync = (entry->status == SAM_LOG_SYNCH_DONE);

    // Determine if we need extended header (m_hdr = 1)
    bool need_m_hdr = false;
    uint8_t final_hdr = 0;

    // Check what fields we need to include
    bool include_slot_idx = false;
    bool include_slot_idx_diff = false;
    bool include_slots_to_use = false;
    bool include_custom_fields = false;

    // Special case for sync events - always include slot_idx
    if (is_sync) {
        include_slot_idx = true;
        need_m_hdr = true;
        final_hdr |= SAM_LOG_HDR_SLOT_IDX;

        // Update tracking state
        state->last_sync_slot_idx = entry->slot_idx;
        state->expected_next_slot_idx = entry->slot_idx + entry->slots_to_use;
        state->has_sync_reference = true;
    }
    // Otherwise check if slot_idx is different from expected
    else if (state->has_sync_reference && entry->slot_idx != state->expected_next_slot_idx) {
        include_slot_idx = true;
        need_m_hdr = true;
        final_hdr |= SAM_LOG_HDR_SLOT_IDX;
    }

    // Include slot_idx_diff if non-zero
    if (entry->slot_idx_diff != 0) {
        include_slot_idx_diff = true;
        need_m_hdr = true;
        final_hdr |= SAM_LOG_HDR_SLOT_IDX_DIFF;
    }

    // Include slots_to_use if different from default
    if (entry->slots_to_use != state->default_slots_to_use) {
        include_slots_to_use = true;
        need_m_hdr = true;
        final_hdr |= SAM_LOG_HDR_SLOTS_TO_USE;
    }

    // Check for custom fields
    if (entry->total_custom_len > 0) {
        include_custom_fields = true;
        need_m_hdr = true;
        final_hdr |= SAM_LOG_HDR_CUSTOM_FIELDS;
    }

    // Check if this sets a new default slots_to_use
    if (entry->hdr & SAM_LOG_HDR_DEFAULT_SLOTS_TO_USE) {
        need_m_hdr = true;
        final_hdr |= SAM_LOG_HDR_DEFAULT_SLOTS_TO_USE;
        state->default_slots_to_use = entry->slots_to_use;
    }

    // --- Encode the entry ---

    // 1. Start with m_hdr bit
    bit_pos = write_bits(output_buffer, buffer_size, bit_pos, need_m_hdr ? 1 : 0, 1);
    if (bit_pos < 0) {
        return bit_pos;  // Error
    }

    // 2. Encode status (5 bits)
    bit_pos = write_bits(output_buffer, buffer_size, bit_pos, entry->status, 5);
    if (bit_pos < 0) {
        return bit_pos;  // Error
    }

    // If m_hdr is not set, we're done
    if (!need_m_hdr) {
        // Update the expected next slot
        if (state->has_sync_reference) {
            state->expected_next_slot_idx += entry->slots_to_use;
        }
        *bytes_written = (bit_pos + 7) / 8;  // Round up to nearest byte
        return bit_pos;
    }

    // 3. Encode custom_status if status is SAM_LOG_STATUS_CUSTOM
    if (include_custom_status) {
        bit_pos = write_bits(output_buffer, buffer_size, bit_pos, entry->custom_status, 16);
        if (bit_pos < 0) {
            return bit_pos;  // Error
        }
    }

    // 4. Encode the header field
    bit_pos = write_bits(output_buffer, buffer_size, bit_pos, final_hdr, 8);
    if (bit_pos < 0) {
        return bit_pos;  // Error
    }

    // 5. Encode slot_idx if needed
    if (include_slot_idx) {
        bit_pos = write_bits(output_buffer, buffer_size, bit_pos, entry->slot_idx, 24);
        if (bit_pos < 0) {
            return bit_pos;  // Error
        }
    }

    // 6. Encode slot_idx_diff if needed
    if (include_slot_idx_diff) {
        // We need to handle negative values correctly (sign extension)
        uint16_t slot_diff_bits = (uint16_t)entry->slot_idx_diff;
        bit_pos = write_bits(output_buffer, buffer_size, bit_pos, slot_diff_bits, 16);
        if (bit_pos < 0) {
            return bit_pos;  // Error
        }
    }

    // 7. Encode slots_to_use if needed
    if (include_slots_to_use) {
        bit_pos = write_bits(output_buffer, buffer_size, bit_pos, entry->slots_to_use, 8);
        if (bit_pos < 0) {
            return bit_pos;  // Error
        }
    }

    // 8. Encode custom fields length if needed
    if (include_custom_fields) {
        bit_pos = write_bits(output_buffer, buffer_size, bit_pos, entry->total_custom_len, 16);
        if (bit_pos < 0) {
            return bit_pos;  // Error
        }

        // 9. Copy custom data
        // First ensure we're byte-aligned
        if (bit_pos % 8 != 0) {
            bit_pos = (bit_pos + 7) & ~7;  // Round up to next byte boundary
        }

        // Check if enough space for custom data
        size_t current_byte = bit_pos / 8;
        if (current_byte + entry->total_custom_len > buffer_size) {
            LOG_ERR("Buffer overflow for custom data: need %zu bytes, have %zu",
                    current_byte + entry->total_custom_len, buffer_size);
            return -ENOSPC;
        }

        // Copy custom data
        memcpy(&output_buffer[current_byte], custom_data, entry->total_custom_len);
        bit_pos += entry->total_custom_len * 8;  // Update bit position
    }

    // Update the expected next slot
    if (state->has_sync_reference) {
        state->expected_next_slot_idx = entry->slot_idx + entry->slots_to_use;
    }

    *bytes_written = (bit_pos + 7) / 8;  // Round up to nearest byte
    return bit_pos;
}

// --- Public API Implementations ---

int sam_log_init(const char *log_name) {
    // Initialize ring buffers (consider using ring_buf_init if dynamic)
    // Note: RING_BUF_DECLARE handles static initialization. Reset state vars.
    ring_buf_reset(&action_rb_start);
    ring_buf_reset(&custom_rb_start);
    ring_buf_reset(&action_rb_end);
    ring_buf_reset(&custom_rb_end);

    // Store the log name
    if (log_name) {
        strncpy(sam_log_name, log_name, sizeof(sam_log_name) - 1); // TODO: Do we need log_name_size?
        sam_log_name[sizeof(sam_log_name) - 1] = '\0';  // Ensure null termination
    } else {
        strncpy(sam_log_name, "sam_log", sizeof(sam_log_name) - 1);
    }

    sam_log_start_count = 0;
    sam_log_active_is_start = true;
    sam_log_initialized = true;
    LOG_INF("SAM Logging '%s' initialized.", sam_log_name);
    return 0;
}

int sam_log_action_put(enum sam_log_status status, uint16_t custom_status, uint32_t slot_idx,
                       int16_t slot_idx_diff, uint8_t slots_to_use, bool set_default_slots,
                       const void *custom_data, uint16_t custom_data_len) {
    if (!sam_log_initialized) {
        LOG_ERR("Logging system not initialized!");
        return -EPERM;  // Operation not permitted
    }

    // --- Prepare Entry ---
    uint8_t hdr_flags = 0;

    // Set hdr flags based on data (simplified logic for example)
    if (slot_idx != SAM_LOG_DEFAULT_SLOT_IDX) {
        hdr_flags |= SAM_LOG_HDR_SLOT_IDX;
    }
    if (slot_idx_diff != 0) {
        hdr_flags |= SAM_LOG_HDR_SLOT_IDX_DIFF;
    }
    // Always indicate slots_to_use data might be relevant for encoder
    hdr_flags |= SAM_LOG_HDR_SLOTS_TO_USE;
    // Handle SCAN/SYNC flags if/when defined
    if (set_default_slots) {
        hdr_flags |= SAM_LOG_HDR_DEFAULT_SLOTS_TO_USE;
    }
    if (custom_data != NULL && custom_data_len > 0) {
        hdr_flags |= SAM_LOG_HDR_CUSTOM_FIELDS;
    } else {
        custom_data_len = 0;
    }  // Ensure length is 0 if data is NULL

    struct sam_log_action entry;
    entry.status = (uint8_t)status;
    // Store custom status directly, encoder filters on output based on status
    entry.custom_status = custom_status;
    entry.hdr = hdr_flags;
    entry.slot_idx = slot_idx;
    entry.slot_idx_diff = slot_idx_diff;
    entry.slots_to_use = slots_to_use;
    entry.total_custom_len = custom_data_len;

    // --- Ring Buffer Logic ---
    struct ring_buf *active_action_rb;
    struct ring_buf *active_custom_rb;
    bool can_overwrite = true;

    // 1. Determine Active Buffers & Overwrite Policy
    if (sam_log_active_is_start) {
        active_action_rb = &action_rb_start;
        active_custom_rb = &custom_rb_start;
        if (sam_log_start_count >= SAM_LOG_START_LOG_CAPACITY) {
            // Should have already switched, but double-check
            sam_log_active_is_start = false;
            LOG_WRN("State Correction: Switching to end buffer.");
            // Fall through to use end buffer now
            active_action_rb = &action_rb_end;
            active_custom_rb = &custom_rb_end;
            can_overwrite = true;  // End buffer always overwrites
        }
        // Check if *about* to become full and thus not overwritable *next time*
        // This logic seems complex. Simpler: If start buffer full -> switch, end
        // buffer always overwrites. Let's stick to: if active_is_start, we add,
        // then check if count hit limit.
        can_overwrite = true;  // Can always attempt to overwrite start buffer
                               // *until* capacity hit.

    } else {  // Already using end buffer
        active_action_rb = &action_rb_end;
        active_custom_rb = &custom_rb_end;
        can_overwrite = true;  // End buffer always overwrites
    }

    // 2. Check Available Space
    size_t required_action_space = sizeof(struct sam_log_action);
    size_t required_custom_space = entry.total_custom_len;
    bool needs_space = false;

    if (ring_buf_space_get(active_action_rb) < required_action_space ||
        ring_buf_space_get(active_custom_rb) < required_custom_space) {
        needs_space = true;
    }

    // 3. Handle "Full" Buffer / Make Space
    if (needs_space) {
        // If we need space and are trying to write to the start buffer *at its
        // capacity limit*, fail.
        if (sam_log_active_is_start && sam_log_start_count >= SAM_LOG_START_LOG_CAPACITY) {
            LOG_WRN("Start log buffer full (%u entries). Cannot add more. Discarding.",
                    sam_log_start_count);
            // Switch now definitely
            sam_log_active_is_start = false;
            return -ENOSPC;  // Indicate failure due to start buffer policy
        }

        // Otherwise, we are allowed to overwrite the oldest entry (either in start
        // buffer before full, or in end buffer)
        struct sam_log_action oldest_entry;
        size_t oldest_entry_size = sizeof(struct sam_log_action);
        int ret_get_old =
            ring_buf_get(active_action_rb, (uint8_t *)&oldest_entry, oldest_entry_size);

        if (ret_get_old != oldest_entry_size) {
            if (ret_get_old == 0 && ring_buf_is_empty(active_action_rb)) {
                LOG_WRN(
                    "Tried to make space in supposedly non-empty buffer, but it was "
                    "empty.");
                // Recheck space below, might be okay now if custom buffer was the
                // issue.
            } else {
                LOG_ERR("Failed to get oldest action entry, ret=%d", ret_get_old);
                return -EIO;
            }
        } else {
            // Discard corresponding custom data
            if (oldest_entry.total_custom_len > 0) {
                uint16_t len_to_remove = oldest_entry.total_custom_len;
                // Discard efficiently
                uint8_t dummy_buf[16];  // Small temp buffer for discard
                size_t removed_total = 0;
                while (removed_total < len_to_remove) {
                    size_t get_len = MIN(len_to_remove - removed_total, sizeof(dummy_buf));
                    int ret_skip_custom = ring_buf_get(active_custom_rb, dummy_buf, get_len);
                    if (ret_skip_custom != get_len) {
                        LOG_ERR(
                            "Failed to remove %u (expected %u) bytes from custom log, "
                            "ret=%d. Buffers potentially desynced!",
                            ret_skip_custom, len_to_remove, ret_skip_custom);
                        return -EIO;  // Indicate inconsistency
                    }
                    removed_total += ret_skip_custom;
                }
            }
            // Decrement start count if removing from start buffer
            if (active_action_rb == &action_rb_start) {
                if (sam_log_start_count > 0)
                    sam_log_start_count--;  // Should always be > 0 if we removed one
            }
        }

        // Re-check space after attempting removal
        if (ring_buf_space_get(active_action_rb) < required_action_space ||
            ring_buf_space_get(active_custom_rb) < required_custom_space) {
            LOG_WRN(
                "Log entry size (%zu action, %u custom) exceeds space after freeing "
                "oldest.",
                required_action_space, required_custom_space);
            return -ENOSPC;
        }
    }

    // 4. Put New Data
    int ret_put_action = ring_buf_put(active_action_rb, (uint8_t *)&entry, required_action_space);
    if (ret_put_action != required_action_space) {
        LOG_ERR("Failed to put action entry despite space check, ret=%d", ret_put_action);
        return -EIO;
    }

    if (required_custom_space > 0) {
        int ret_put_custom = ring_buf_put(active_custom_rb, custom_data, required_custom_space);
        if (ret_put_custom != required_custom_space) {
            LOG_ERR(
                "CRITICAL: Failed to put custom data (len %u), ret=%d. LOGS "
                "INCONSISTENT!",
                required_custom_space, ret_put_custom);
            // Attempt recovery? Maybe remove the action entry just added? Complex.
            // For now, log error and return failure. The action entry remains
            // orphaned.
            return -EIO;
        }
    }

    // 5. Update State for "2 Instances" Logic
    if (sam_log_active_is_start) {
        sam_log_start_count++;
        // Check if we *just* hit the limit
        if (sam_log_start_count >= SAM_LOG_START_LOG_CAPACITY) {
            sam_log_active_is_start = false;  // Switch to end buffer for NEXT log entry
            LOG_INF("Log start buffer now full (%u entries). Switching to end buffer.",
                    sam_log_start_count);
        }
    }

    return 0;  // Success
}

int sam_log_flush(size_t buffer_size, size_t *bytes_written) {
    if (!sam_log_initialized) {
        LOG_ERR("Logging system not initialized!");
        return -EPERM;
    }

    if (!bytes_written) {
        LOG_ERR("Invalid parameters");
        return -EINVAL;
    }

    // Check if buffer_size is too large for our static buffer
    if (buffer_size > OUTPUT_BUFFER_SIZE) {
        LOG_WRN("Requested buffer size %zu larger than available buffer %d, limiting size",
                buffer_size, OUTPUT_BUFFER_SIZE);
        buffer_size = OUTPUT_BUFFER_SIZE;
    }

    *bytes_written = 0;

    // Initialize encoder state
    struct encoder_state encoder;
    encoder_init(&encoder);

    // Clear output buffer
    memset(output_buffer, 0, buffer_size);

    // Start bit position for encoding
    int bit_pos = 0;

    // --- Process Start Buffer Entries ---
    struct sam_log_action entry;
    size_t entry_size = sizeof(struct sam_log_action);
    uint8_t custom_data_buffer[256];  // Temporary buffer for custom data

    // Determine how many entries are in the start buffer
    size_t start_entries = ring_buf_size_get(&action_rb_start) / entry_size;
    LOG_INF("Processing %zu entries from start buffer", start_entries);

    for (size_t i = 0; i < start_entries; i++) {
        // Get an entry
        int ret = ring_buf_peek(&action_rb_start, (uint8_t *)&entry, entry_size, i * entry_size);
        if (ret != entry_size) {
            LOG_ERR("Failed to peek entry %zu from start buffer, ret=%d", i, ret);
            break;
        }

        // Get any associated custom data
        uint16_t custom_len = entry.total_custom_len;
        if (custom_len > 0) {
            if (custom_len > sizeof(custom_data_buffer)) {
                LOG_ERR("Custom data too large: %u bytes", custom_len);
                return -ENOSPC;
            }

            // Calculate offset in custom buffer based on sum of previous lengths
            size_t custom_offset = 0;
            for (size_t j = 0; j < i; j++) {
                struct sam_log_action prev_entry;
                ret = ring_buf_peek(&action_rb_start, (uint8_t *)&prev_entry, entry_size,
                                    j * entry_size);
                if (ret != entry_size) {
                    LOG_ERR("Failed to peek previous entry for custom offset calculation");
                    return -EIO;
                }
                custom_offset += prev_entry.total_custom_len;
            }

            // Get custom data from the corresponding position
            ret = ring_buf_peek(&custom_rb_start, custom_data_buffer, custom_len, custom_offset);
            if (ret != custom_len) {
                LOG_ERR("Failed to peek custom data, ret=%d expected=%u", ret, custom_len);
                return -EIO;
            }
        }

        // Encode this entry
        size_t bytes_encoded = 0;
        bit_pos = encode_entry(&encoder, &entry, custom_data_buffer, output_buffer, buffer_size,
                               bit_pos, &bytes_encoded);
        if (bit_pos < 0) {
            LOG_ERR("Error encoding entry: %d", bit_pos);
            return bit_pos;
        }

        *bytes_written = MAX(*bytes_written, bytes_encoded);
    }

    // --- Process End Buffer Entries ---
    size_t end_entries = ring_buf_size_get(&action_rb_end) / entry_size;
    LOG_INF("Processing %zu entries from end buffer", end_entries);

    for (size_t i = 0; i < end_entries; i++) {
        // Get an entry
        int ret = ring_buf_peek(&action_rb_end, (uint8_t *)&entry, entry_size, i * entry_size);
        if (ret != entry_size) {
            LOG_ERR("Failed to peek entry %zu from end buffer, ret=%d", i, ret);
            break;
        }

        // Get any associated custom data
        uint16_t custom_len = entry.total_custom_len;
        if (custom_len > 0) {
            if (custom_len > sizeof(custom_data_buffer)) {
                LOG_ERR("Custom data too large: %u bytes", custom_len);
                return -ENOSPC;
            }

            // Calculate offset in custom buffer based on sum of previous lengths
            size_t custom_offset = 0;
            for (size_t j = 0; j < i; j++) {
                struct sam_log_action prev_entry;
                ret = ring_buf_peek(&action_rb_end, (uint8_t *)&prev_entry, entry_size,
                                    j * entry_size);
                if (ret != entry_size) {
                    LOG_ERR("Failed to peek previous entry for custom offset calculation");
                    return -EIO;
                }
                custom_offset += prev_entry.total_custom_len;
            }

            // Get custom data from the corresponding position
            ret = ring_buf_peek(&custom_rb_end, custom_data_buffer, custom_len, custom_offset);
            if (ret != custom_len) {
                LOG_ERR("Failed to peek custom data, ret=%d expected=%u", ret, custom_len);
                return -EIO;
            }
        }

        // Encode this entry
        size_t bytes_encoded = 0;
        bit_pos = encode_entry(&encoder, &entry, custom_data_buffer, output_buffer, buffer_size,
                               bit_pos, &bytes_encoded);
        if (bit_pos < 0) {
            LOG_ERR("Error encoding entry: %d", bit_pos);
            return bit_pos;
        }

        *bytes_written = MAX(*bytes_written, bytes_encoded);
    }

    // Make sure the byte count is correct (should be ceiling of bit_pos / 8)
    *bytes_written = (bit_pos + 7) / 8;

    // Log the serialized data
    LOG_PRINTK("LOG[%s] %zu %.*s\n", sam_log_name, *bytes_written, (int)*bytes_written,
               output_buffer);

    LOG_INF("Encoded %zu start entries and %zu end entries into %zu bytes", start_entries,
            end_entries, *bytes_written);

    // Clear buffers after successful encoding
    ring_buf_reset(&action_rb_start);
    ring_buf_reset(&custom_rb_start);
    ring_buf_reset(&action_rb_end);
    ring_buf_reset(&custom_rb_end);
    sam_log_start_count = 0;
    sam_log_active_is_start = true;

    return 0;
}