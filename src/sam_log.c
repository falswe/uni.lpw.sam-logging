#include "sam_log.h"

#include <errno.h>  // Include errno definitions like ENOSPC, EIO
#include <zephyr/logging/log.h>
#include <zephyr/sys/__assert.h>

// Register logging module for this file
LOG_MODULE_REGISTER(sam_log, CONFIG_SAM_LOG_LEVEL);  // Adjust CONFIG_SAM_LOG_LEVEL as needed

// --- Buffer Sizes ---
// Calculate based on capacity and struct size, add some leeway.
// Sizes need careful tuning based on expected max custom data and memory
// constraints.
#define ACTION_RB_START_SIZE (SAM_LOG_START_LOG_CAPACITY * sizeof(struct sam_log_rb_entry))
#define CUSTOM_RB_START_SIZE \
    (ACTION_RB_START_SIZE * 2)  // Example: Assume avg custom data is similar size to entry

// End buffers need a reasonable size for capturing events after start buffer is
// full
#define ACTION_RB_END_CAPACITY (64)  // Example capacity
#define ACTION_RB_END_SIZE (ACTION_RB_END_CAPACITY * sizeof(struct sam_log_rb_entry))
#define CUSTOM_RB_END_SIZE (ACTION_RB_END_SIZE * 2)  // Example sizing

// --- Ring Buffer Definitions ---
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

// --- Module State ---
static uint32_t sam_log_start_count = 0;
static bool sam_log_active_is_start = true;
static bool sam_log_initialized = false;

// --- Public API Implementations ---

int sam_log_init(void) {
    // Initialize ring buffers (consider using ring_buf_init if dynamic)
    // Note: RING_BUF_DECLARE handles static initialization. Reset state vars.
    ring_buf_reset(&action_rb_start);
    ring_buf_reset(&custom_rb_start);
    ring_buf_reset(&action_rb_end);
    ring_buf_reset(&custom_rb_end);

    sam_log_start_count = 0;
    sam_log_active_is_start = true;
    sam_log_initialized = true;
    LOG_INF("SAM Logging initialized.");
    return 0;
}

int sam_log_action_result(enum sam_log_status status, uint16_t custom_status, uint32_t slot_idx,
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
        hdr_flags |= SAM_LOG_HDR_MASK_SLOT_IDX;
    }
    if (slot_idx_diff != 0) {
        hdr_flags |= SAM_LOG_HDR_MASK_SLOT_IDX_DIFF;
    }
    // Always indicate slots_to_use data might be relevant for encoder
    hdr_flags |= SAM_LOG_HDR_MASK_SLOTS_TO_USE;
    // Handle SCAN/SYNC flags if/when defined
    if (set_default_slots) {
        hdr_flags |= SAM_LOG_HDR_MASK_SET_DEFAULT_SLOTS;
    }
    if (custom_data != NULL && custom_data_len > 0) {
        hdr_flags |= SAM_LOG_HDR_MASK_CUSTOM_FIELDS;
    } else {
        custom_data_len = 0;
    }  // Ensure length is 0 if data is NULL

    struct sam_log_rb_entry entry;
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
    size_t required_action_space = sizeof(struct sam_log_rb_entry);
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
        struct sam_log_rb_entry oldest_entry;
        size_t oldest_entry_size = sizeof(struct sam_log_rb_entry);
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

int sam_log_flush_and_encode(uint8_t *output_buffer, size_t buffer_size, size_t *bytes_written) {
    if (!sam_log_initialized) {
        LOG_ERR("Logging system not initialized!");
        return -EPERM;
    }

    // --- THIS IS A PLACEHOLDER ---
    // The actual implementation requires:
    // 1. An encoder state machine/context to track current default slots_to_use.
    // 2. Logic to read entries sequentially from:
    //    a. action_rb_start + custom_rb_start (all entries)
    //    b. action_rb_end + custom_rb_end (all entries)
    // 3. For each entry read:
    //    a. Check status, hdr flags, values against defaults.
    //    b. Decide which fields to include in the bit-packed output.
    //    c. Pack the required fields bit-by-bit into the output_buffer.
    //    d. Handle output buffer overflow.
    //    e. Read corresponding custom data and append it (if needed).
    //    f. Update encoder state (e.g., default slots_to_use if
    //    MASK_SET_DEFAULT_SLOTS is set).
    // 4. Reset ring buffers after successful flush? (Optional policy decision)

    LOG_WRN("sam_log_flush_and_encode() is not fully implemented!");
    *bytes_written = 0;

    // Example: Simple placeholder just dumping struct count
    size_t start_entries = ring_buf_size_get(&action_rb_start) / sizeof(struct sam_log_rb_entry);
    size_t end_entries = ring_buf_size_get(&action_rb_end) / sizeof(struct sam_log_rb_entry);
    LOG_INF("Log Flush Placeholder: Start entries=%zu, End entries=%zu", start_entries,
            end_entries);

    // Placeholder: Clear buffers after "flush"
    ring_buf_reset(&action_rb_start);
    ring_buf_reset(&custom_rb_start);
    ring_buf_reset(&action_rb_end);
    ring_buf_reset(&custom_rb_end);
    sam_log_start_count = 0;
    sam_log_active_is_start = true;

    return -ENOSYS;  // Function not implemented fully
}