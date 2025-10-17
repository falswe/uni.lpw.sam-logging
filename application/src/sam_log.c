#include "../include/sam_log.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/ring_buffer.h>

#include "z85.h"

LOG_MODULE_REGISTER(sam_log, CONFIG_LOG_DEFAULT_LEVEL);

/* Buffer size configuration */
#define SAM_LOG_SERIALIZE_BUF_SIZE (SAM_LOG_ACTIONS_BUF_SIZE + SAM_LOG_CUSTOM_BUF_SIZE)

/* Bit field sizes according to the specification */
#define SAM_LOG_BIT_SIZE_M_HDR 1
#define SAM_LOG_BIT_SIZE_STATUS 5
#define SAM_LOG_BIT_SIZE_CUSTOM_STATUS 10
#define SAM_LOG_BIT_SIZE_HDR 8
#define SAM_LOG_BIT_SIZE_SLOT_IDX 24
#define SAM_LOG_BIT_SIZE_SLOT_IDX_DIFF 16
#define SAM_LOG_BIT_SIZE_SLOTS_TO_USE 8
#define SAM_LOG_BIT_SIZE_TOTAL_CUSTOM_LEN 16

/* First byte masks */
#define SAM_LOG_MASK_M_HDR 0x80
#define SAM_LOG_MASK_STATUS 0x7C
#define SAM_LOG_MASK_CUSTOM_STATUS_HIGH 0x03

/* Header bit definitions */
#define SAM_LOG_HDR_SLOT_IDX (1 << 0)
#define SAM_LOG_HDR_SLOTS_TO_USE (1 << 1)
#define SAM_LOG_HDR_SLOT_IDX_DIFF (1 << 2)
#define SAM_LOG_HDR_SCAN (1 << 3)
#define SAM_LOG_HDR_CUSTOM_FIELDS (1 << 4)
#define SAM_LOG_HDR_DEFAULT_SLOTS_TO_USE (1 << 5)

/* Derived byte sizes to avoid magic numbers */
#define SAM_LOG_BYTE_SIZE_CUSTOM_STATUS ((SAM_LOG_BIT_SIZE_CUSTOM_STATUS + 7) / 8)
#define SAM_LOG_BYTE_SIZE_HDR ((SAM_LOG_BIT_SIZE_HDR + 7) / 8)
#define SAM_LOG_BYTE_SIZE_SLOT_IDX ((SAM_LOG_BIT_SIZE_SLOT_IDX + 7) / 8)
#define SAM_LOG_BYTE_SIZE_SLOT_IDX_DIFF ((SAM_LOG_BIT_SIZE_SLOT_IDX_DIFF + 7) / 8)
#define SAM_LOG_BYTE_SIZE_SLOTS_TO_USE ((SAM_LOG_BIT_SIZE_SLOTS_TO_USE + 7) / 8)
#define SAM_LOG_BYTE_SIZE_TOTAL_CUSTOM_LEN ((SAM_LOG_BIT_SIZE_TOTAL_CUSTOM_LEN + 7) / 8)

/* Bit shifts */
#define SAM_LOG_SHIFT_M_HDR 7
#define SAM_LOG_SHIFT_STATUS 2

/* Constants for action processing */
#define SAM_LOG_MAX_ACTION_HEADER_SIZE 11
#define SAM_LOG_CUSTOM_STATUS_MASK 0x3FF /* 10-bit mask (0b1111111111) */
#define SAM_LOG_DEFAULT_SLOTS_TO_USE 1

/* Structure representing a serialized action */
struct sam_log_packed_action {
    uint8_t m_hdr : SAM_LOG_BIT_SIZE_M_HDR;
    uint8_t status : SAM_LOG_BIT_SIZE_STATUS;
    uint16_t custom_status : SAM_LOG_BIT_SIZE_CUSTOM_STATUS;
    uint8_t hdr : SAM_LOG_BIT_SIZE_HDR;
    uint32_t slot_idx : SAM_LOG_BIT_SIZE_SLOT_IDX;
    int16_t slot_idx_diff : SAM_LOG_BIT_SIZE_SLOT_IDX_DIFF;
    uint8_t slots_to_use : SAM_LOG_BIT_SIZE_SLOTS_TO_USE;
    uint16_t total_custom_len : SAM_LOG_BIT_SIZE_TOTAL_CUSTOM_LEN;
} __attribute__((packed));

/* Context structure */
struct sam_log_ctx {
    struct ring_buf start_actions;
    struct ring_buf start_custom;
    struct ring_buf end_actions;
    struct ring_buf end_custom;
    bool logging_enabled;
    bool start_buffer_full;
    uint8_t default_slots_to_use;
    uint32_t current_slot_idx;
    uint8_t last_deleted_default_slots_to_use;
    uint32_t last_deleted_slot_idx;
    struct sam_log_stats stats;
};

/* Buffers for ring buffers */
static uint8_t start_actions_buf[SAM_LOG_ACTIONS_BUF_SIZE];
static uint8_t end_actions_buf[SAM_LOG_ACTIONS_BUF_SIZE];
static uint8_t start_custom_buf[SAM_LOG_CUSTOM_BUF_SIZE];
static uint8_t end_custom_buf[SAM_LOG_CUSTOM_BUF_SIZE];

/* Global context */
static struct sam_log_ctx log_ctx;

/* Serialization buffer */
static uint8_t serialize_buf[SAM_LOG_SERIALIZE_BUF_SIZE];

/* Serialize an action to a byte array */
static size_t serialize_action(const struct sam_log_packed_action *action, uint8_t *buf,
                               size_t bufsize) {
    size_t pos = 0;

    if (bufsize < 1) {
        return 0;
    }

    /* Check if we need to store custom status */
    bool has_custom_status = (action->status == SAM_LOG_UNKNOWN);

    /*
     * First byte:
     * - m_hdr: 1 bit (MSB)
     * - status: 5 bits (next 5 bits)
     * - custom_status (MSB): 2 bits (LSB of first byte, only when status == SAM_LOG_UNKNOWN)
     */
    if (has_custom_status) {
        /* First 2 bits of custom_status go into first byte's LSBs */
        uint16_t custom_status = action->custom_status & SAM_LOG_CUSTOM_STATUS_MASK;
        buf[pos++] = ((action->m_hdr & 0x01) << SAM_LOG_SHIFT_M_HDR) |
                     ((action->status & 0x1F) << SAM_LOG_SHIFT_STATUS) |
                     ((custom_status >> 8) & SAM_LOG_MASK_CUSTOM_STATUS_HIGH);

        /* Make sure we have space for the second byte */
        if (pos + 1 > bufsize) {
            return 0;
        }

        /* Remaining 8 bits of custom_status go into second byte */
        buf[pos++] = custom_status & 0xFF;
    } else {
        /* Regular status without custom status */
        buf[pos++] = ((action->m_hdr & 0x01) << SAM_LOG_SHIFT_M_HDR) |
                     ((action->status & 0x1F) << SAM_LOG_SHIFT_STATUS);
    }

    /* Extended header fields */
    if (action->m_hdr) {
        if (pos + 1 > bufsize) {
            return 0;
        }

        /* Header byte */
        buf[pos++] = action->hdr;

        /* Slot index if needed */
        if (action->hdr & SAM_LOG_HDR_SLOT_IDX) {
            if (pos + SAM_LOG_BYTE_SIZE_SLOT_IDX > bufsize) {
                return 0;
            }
            buf[pos++] = (action->slot_idx >> 16) & 0xFF;
            buf[pos++] = (action->slot_idx >> 8) & 0xFF;
            buf[pos++] = action->slot_idx & 0xFF;
        }

        /* Slot diff if needed */
        if (action->hdr & SAM_LOG_HDR_SLOT_IDX_DIFF) {
            if (pos + SAM_LOG_BYTE_SIZE_SLOT_IDX_DIFF > bufsize) {
                return 0;
            }
            buf[pos++] = (action->slot_idx_diff >> 8) & 0xFF;
            buf[pos++] = action->slot_idx_diff & 0xFF;
        }

        /* Slots to use if needed */
        if (action->hdr & SAM_LOG_HDR_SLOTS_TO_USE) {
            if (pos + SAM_LOG_BYTE_SIZE_SLOTS_TO_USE > bufsize) {
                return 0;
            }
            buf[pos++] = action->slots_to_use;
        }

        /* Custom data length if needed */
        if (action->hdr & SAM_LOG_HDR_CUSTOM_FIELDS) {
            if (pos + SAM_LOG_BYTE_SIZE_TOTAL_CUSTOM_LEN > bufsize) {
                return 0;
            }
            buf[pos++] = (action->total_custom_len >> 8) & 0xFF;
            buf[pos++] = action->total_custom_len & 0xFF;
        }
    }

    return pos;
}

/* Reset context variables to initial state */
static void reset_log_context(void) {
    log_ctx.logging_enabled = true;
    log_ctx.start_buffer_full = false;
    log_ctx.default_slots_to_use = SAM_LOG_DEFAULT_SLOTS_TO_USE;
    log_ctx.current_slot_idx = 0;
    log_ctx.last_deleted_default_slots_to_use = SAM_LOG_DEFAULT_SLOTS_TO_USE;
    log_ctx.last_deleted_slot_idx = 0;
    memset(&log_ctx.stats, 0, sizeof(struct sam_log_stats));
}

/* Initialize the logging subsystem */
int sam_log_init(void) {
    /* Initialize ring buffers */
    ring_buf_init(&log_ctx.start_actions, sizeof(start_actions_buf), start_actions_buf);
    ring_buf_init(&log_ctx.start_custom, sizeof(start_custom_buf), start_custom_buf);
    ring_buf_init(&log_ctx.end_actions, sizeof(end_actions_buf), end_actions_buf);
    ring_buf_init(&log_ctx.end_custom, sizeof(end_custom_buf), end_custom_buf);

    /* Initialize context */
    reset_log_context();

    return 0;
}

/* Add an action to a buffer */
static int add_to_buffer(struct ring_buf *action_buf, struct ring_buf *custom_buf,
                         uint8_t *serialized_action, size_t action_len, const void *custom_data,
                         uint16_t custom_data_len) {
    int ret;

    /* Check space availability */
    if (ring_buf_space_get(action_buf) < action_len ||
        (custom_data_len > 0 && ring_buf_space_get(custom_buf) < custom_data_len)) {
        LOG_WRN("Buffer full: action=%zu, custom=%u", ring_buf_space_get(action_buf),
                ring_buf_space_get(custom_buf));
        log_ctx.stats.actions_dropped++;
        return -ENOMEM;
    }

    /* Add action to buffer */
    ret = ring_buf_put(action_buf, serialized_action, action_len);
    if (ret < action_len) {
        LOG_ERR("Failed to add action to buffer");
        log_ctx.stats.actions_dropped++;
        return -EIO;
    }

    /* Add custom data if present */
    if (custom_data && custom_data_len > 0) {
        ret = ring_buf_put(custom_buf, custom_data, custom_data_len);
        if (ret < custom_data_len) {
            LOG_ERR("Failed to add custom data to buffer");
            log_ctx.stats.custom_fields_dropped++;
            return -EIO;
        }
        log_ctx.stats.custom_fields_logged++;
    }

    log_ctx.stats.actions_logged++;
    return 0;
}

/* Make room in buffer by removing oldest entries */
static void make_room_in_buffer(struct ring_buf *action_buf, struct ring_buf *custom_buf,
                                size_t action_size, size_t custom_size) {
    uint8_t first_byte;

    while (ring_buf_space_get(action_buf) < action_size ||
           ring_buf_space_get(custom_buf) < custom_size) {
        /* Read first byte to determine action type */
        if (ring_buf_get(action_buf, &first_byte, 1) < 1) {
            break;
        }

        /* Get m_hdr and status from first byte */
        uint8_t m_hdr = (first_byte & SAM_LOG_MASK_M_HDR) >> SAM_LOG_SHIFT_M_HDR;
        uint8_t status = (first_byte & SAM_LOG_MASK_STATUS) >> SAM_LOG_SHIFT_STATUS;

        /* Handle custom status if present */
        if (status == SAM_LOG_UNKNOWN) {
            ring_buf_get(action_buf, NULL, 1); /* Skip custom status low byte */
        }

        /* Handle extended header if present */
        if (m_hdr) {
            uint8_t hdr;

            if (ring_buf_get(action_buf, &hdr, 1) < 1) {
                break;
            }

            bool starting_slot_idx_updated = false;

            /* Skip all header-dependent fields */
            if (hdr & SAM_LOG_HDR_SLOT_IDX) {
                uint8_t slot_idx[SAM_LOG_BYTE_SIZE_SLOT_IDX];

                ring_buf_get(action_buf, slot_idx, SAM_LOG_BYTE_SIZE_SLOT_IDX);

                /* Update slot index of the oldest action in the end buffer */
                log_ctx.last_deleted_slot_idx =
                    ((slot_idx[0] << 16) | (slot_idx[1] << 8) | slot_idx[2]);
                starting_slot_idx_updated = true;
            }
            if (hdr & SAM_LOG_HDR_SLOT_IDX_DIFF) {
                ring_buf_get(action_buf, NULL, SAM_LOG_BYTE_SIZE_SLOT_IDX_DIFF);
            }
            if (hdr & SAM_LOG_HDR_SLOTS_TO_USE) {
                uint8_t slots_to_use;

                ring_buf_get(action_buf, &slots_to_use, SAM_LOG_BYTE_SIZE_SLOTS_TO_USE);
                if (hdr & SAM_LOG_HDR_DEFAULT_SLOTS_TO_USE) {
                    log_ctx.last_deleted_default_slots_to_use = slots_to_use;
                }

                /* Update slot index of the oldest action in the end buffer */
                if (!starting_slot_idx_updated) {
                    log_ctx.last_deleted_slot_idx += slots_to_use;
                    starting_slot_idx_updated = true;
                }
            }
            /* Update slot index of the oldest action in the end buffer */
            if (!starting_slot_idx_updated) {
                log_ctx.last_deleted_slot_idx += log_ctx.last_deleted_default_slots_to_use;
            }
            if (hdr & SAM_LOG_HDR_CUSTOM_FIELDS) {
                uint8_t len_bytes[SAM_LOG_BYTE_SIZE_TOTAL_CUSTOM_LEN];
                uint16_t custom_len;

                if (ring_buf_get(action_buf, len_bytes, SAM_LOG_BYTE_SIZE_TOTAL_CUSTOM_LEN) <
                    SAM_LOG_BYTE_SIZE_TOTAL_CUSTOM_LEN) {
                    break;
                }

                custom_len = (len_bytes[0] << 8) | len_bytes[1];
                ring_buf_get(custom_buf, NULL, custom_len);
                log_ctx.stats.custom_fields_dropped++;
            }
        } else {
            log_ctx.last_deleted_slot_idx += log_ctx.last_deleted_default_slots_to_use;
        }

        log_ctx.stats.actions_dropped++;
    }
}

/* Log an action with all possible fields */
int sam_log_action(enum sam_log_status status, uint16_t custom_status, uint32_t slot_idx,
                   int16_t slot_idx_diff, uint8_t slots_to_use, bool set_default_slots,
                   const void *custom_data, uint16_t custom_data_len) {
    struct sam_log_packed_action action = {0};
    uint8_t hdr = 0;
    int ret;

    if (!log_ctx.logging_enabled) {
        return -ENOTSUP;
    }

    /* Set status field */
    action.status = status;

    /* Handle custom status */
    if (status == SAM_LOG_UNKNOWN) {
        action.custom_status = custom_status & SAM_LOG_CUSTOM_STATUS_MASK;
    }

    /* Check if we need extended header */
    if (slot_idx != log_ctx.current_slot_idx || slot_idx_diff != 0 ||
        slots_to_use != log_ctx.default_slots_to_use || set_default_slots || custom_data_len > 0 ||
        status == SAM_LOG_SYNCH_DONE) {
        action.m_hdr = 1;

        /* Add fields to header */
        if (status == SAM_LOG_SYNCH_DONE || slot_idx != log_ctx.current_slot_idx) {
            hdr |= SAM_LOG_HDR_SLOT_IDX;
            action.slot_idx = slot_idx;
        }

        if (slot_idx_diff != 0) {
            hdr |= SAM_LOG_HDR_SLOT_IDX_DIFF;
            action.slot_idx_diff = slot_idx_diff;
        }

        if (slots_to_use != log_ctx.default_slots_to_use || set_default_slots) {
            hdr |= SAM_LOG_HDR_SLOTS_TO_USE;
            action.slots_to_use = slots_to_use;
        }

        if (set_default_slots) {
            hdr |= SAM_LOG_HDR_DEFAULT_SLOTS_TO_USE;
            log_ctx.default_slots_to_use = slots_to_use;
        }

        if (custom_data_len > 0) {
            hdr |= SAM_LOG_HDR_CUSTOM_FIELDS;
            action.total_custom_len = custom_data_len;
        }

        action.hdr = hdr;
    }

    /* Calculate required space */
    uint8_t serialized_action[SAM_LOG_MAX_ACTION_HEADER_SIZE];
    size_t action_size = serialize_action(&action, serialized_action, sizeof(serialized_action));

    if (action_size == 0) {
        LOG_ERR("Failed to calculate action size");
        log_ctx.stats.actions_dropped++;
        return -EINVAL;
    }

    /* Try to add to start buffer first if not full */
    if (!log_ctx.start_buffer_full) {
        /* Check if action fits in start buffer */
        if (ring_buf_space_get(&log_ctx.start_actions) >= action_size &&
            (custom_data_len == 0 ||
             ring_buf_space_get(&log_ctx.start_custom) >= custom_data_len)) {
            /* Save state of the last action that fit in the start buffer */
            log_ctx.last_deleted_slot_idx = log_ctx.current_slot_idx;
            log_ctx.last_deleted_default_slots_to_use = log_ctx.default_slots_to_use;

            /* Add to start buffer */
            ret = add_to_buffer(&log_ctx.start_actions, &log_ctx.start_custom, serialized_action,
                                action_size, custom_data, custom_data_len);

            if (ret == 0) {
                /* Successfully added to start buffer */
                /* Update current slot index */
                if (slot_idx != log_ctx.current_slot_idx) {
                    /* If a specific slot was provided, use it as the new base position */
                    log_ctx.current_slot_idx = slot_idx + slots_to_use;
                } else {
                    /* Otherwise, increment from current position */
                    log_ctx.current_slot_idx += slots_to_use;
                }
                return 0;
            }
        }

        /* Start buffer is full, switch to end buffer permanently */
        LOG_INF("Start buffer full, switching to end buffer");
        log_ctx.start_buffer_full = true;
    }

    /* If we're here, we need to use the end buffer */

    /* Make room in end buffer if needed */
    make_room_in_buffer(&log_ctx.end_actions, &log_ctx.end_custom, action_size, custom_data_len);

    /* Add to end buffer */
    ret = add_to_buffer(&log_ctx.end_actions, &log_ctx.end_custom, serialized_action, action_size,
                        custom_data, custom_data_len);

    if (ret < 0) {
        LOG_WRN("Failed to add to end buffer: %d", ret);
        log_ctx.stats.actions_dropped++;
        return ret;
    }

    /* Update current slot index */
    if (slot_idx != log_ctx.current_slot_idx) {
        /* If a specific slot was provided, use it as the new base position */
        log_ctx.current_slot_idx = slot_idx + slots_to_use;
    } else {
        /* Otherwise, increment from current position */
        log_ctx.current_slot_idx += slots_to_use;
    }

    return 0;
}

/* Get logging statistics */
int sam_log_get_stats(struct sam_log_stats *stats) {
    if (!stats) {
        return -EINVAL;
    }

    *stats = log_ctx.stats;
    return 0;
}

/**
 * State for bit-level buffer writing.
 * Tracks current write position within a byte (not byte-aligned).
 */
struct bitbuf_state_t {
    uint8_t *dest_buf;          // Pointer to current byte in destination buffer
    uint8_t offset;             // Bit offset within current byte (0-7)
    size_t total_bits_written;  // Total bits written to the buffer
};

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
    dest_buf.total_bits_written += bits;

    return dest_buf;
}

static void add_action_packed(const struct sam_log_packed_action *action,
                              struct bitbuf_state_t *bitbuf_state) {
    *bitbuf_state = add_on_offset(action->m_hdr, SAM_LOG_BIT_SIZE_M_HDR, *bitbuf_state);
    *bitbuf_state = add_on_offset(action->status, SAM_LOG_BIT_SIZE_STATUS, *bitbuf_state);

    if (action->status == SAM_LOG_UNKNOWN) {
        // Write high 2 bits first (bits 8-9 of the 10-bit value)
        *bitbuf_state = add_on_offset((action->custom_status >> 8) & 0x03, 2, *bitbuf_state);
        // Write low 8 bits (bits 0-7 of the 10-bit value)
        *bitbuf_state = add_on_offset(action->custom_status & 0xFF, 8, *bitbuf_state);
    }

    if (action->m_hdr) {
        *bitbuf_state = add_on_offset(action->hdr, SAM_LOG_BIT_SIZE_HDR, *bitbuf_state);

        if (action->hdr & SAM_LOG_HDR_SLOT_IDX) {
            *bitbuf_state = add_on_offset((action->slot_idx >> 16) & 0xFF, 8, *bitbuf_state);
            *bitbuf_state = add_on_offset((action->slot_idx >> 8) & 0xFF, 8, *bitbuf_state);
            *bitbuf_state = add_on_offset(action->slot_idx & 0xFF, 8, *bitbuf_state);
        }

        if (action->hdr & SAM_LOG_HDR_SLOT_IDX_DIFF) {
            *bitbuf_state = add_on_offset((action->slot_idx_diff >> 8) & 0xFF, 8, *bitbuf_state);
            *bitbuf_state = add_on_offset(action->slot_idx_diff & 0xFF, 8, *bitbuf_state);
        }

        if (action->hdr & SAM_LOG_HDR_SLOTS_TO_USE) {
            *bitbuf_state =
                add_on_offset(action->slots_to_use, SAM_LOG_BIT_SIZE_SLOTS_TO_USE, *bitbuf_state);
        }

        if (action->hdr & SAM_LOG_HDR_CUSTOM_FIELDS) {
            *bitbuf_state = add_on_offset((action->total_custom_len >> 8) & 0xFF, 8, *bitbuf_state);
            *bitbuf_state = add_on_offset(action->total_custom_len & 0xFF, 8, *bitbuf_state);
        }
    }
}

/* Process actions from a buffer and bit pack them */
static size_t process_buffer(struct ring_buf *action_buf, struct ring_buf *custom_buf,
                             uint8_t *out_buf, size_t out_size, bool put_first_slot_idx) {
    /* Output buffer position (start from 3rd elements since first and second are for starting
     * default slots to use and number of actions logged) */
    uint8_t starting_default_slots_to_use = SAM_LOG_DEFAULT_SLOTS_TO_USE;
    out_buf[0] = starting_default_slots_to_use;

    struct bitbuf_state_t bitbuf_state = {
        .dest_buf = &out_buf[2], .offset = 0, .total_bits_written = 0};

    /* Number of actions logged */
    uint8_t actions_logged = 0;

    /* If the first action in the buffer does not contain slot idx add it*/
    if (put_first_slot_idx) {
        struct sam_log_packed_action first_action_with_slot_idx;
        first_action_with_slot_idx.total_custom_len = 0;
        uint8_t tmp_buf[SAM_LOG_MAX_ACTION_HEADER_SIZE]; /* Temp buffer for serialized action */

        /* Read first byte of first action from the buffer */
        uint8_t first_byte;
        size_t bytes_read = ring_buf_get(action_buf, &first_byte, 1);

        if (bytes_read == 0) {
            /* No data in the buffer */
            return 2;
        }

        uint8_t m_hdr = (first_byte & SAM_LOG_MASK_M_HDR) >> SAM_LOG_SHIFT_M_HDR;
        uint8_t status = (first_byte & SAM_LOG_MASK_STATUS) >> SAM_LOG_SHIFT_STATUS;

        first_action_with_slot_idx.m_hdr = 1;
        first_action_with_slot_idx.status = status;

        if (status == SAM_LOG_UNKNOWN) {
            uint8_t custom_status;
            /* High bits already contained in previous byte */
            ring_buf_get(action_buf, &custom_status, SAM_LOG_BYTE_SIZE_CUSTOM_STATUS - 1);
            first_action_with_slot_idx.custom_status = (first_byte & 0x3) | custom_status;
        }

        first_action_with_slot_idx.hdr = 0;

        if (m_hdr) {
            uint8_t hdr;
            ring_buf_get(action_buf, &hdr, SAM_LOG_BYTE_SIZE_HDR);
            first_action_with_slot_idx.hdr = hdr;

            if (hdr & SAM_LOG_HDR_SLOT_IDX) {
                uint8_t slot_idx[SAM_LOG_BYTE_SIZE_SLOT_IDX];
                ring_buf_get(action_buf, slot_idx, SAM_LOG_BYTE_SIZE_SLOT_IDX);
                first_action_with_slot_idx.slot_idx =
                    (slot_idx[0] << 16) | (slot_idx[1] << 8) | slot_idx[2];
            }

            if (hdr & SAM_LOG_HDR_SLOT_IDX_DIFF) {
                uint8_t slot_idx_diff[SAM_LOG_BYTE_SIZE_SLOT_IDX_DIFF];
                ring_buf_get(action_buf, slot_idx_diff, SAM_LOG_BYTE_SIZE_SLOT_IDX_DIFF);
                first_action_with_slot_idx.slot_idx_diff =
                    (slot_idx_diff[0] << 8) | slot_idx_diff[1];
            }

            if (hdr & SAM_LOG_HDR_SLOTS_TO_USE) {
                uint8_t slots_to_use;
                ring_buf_get(action_buf, &slots_to_use, SAM_LOG_BYTE_SIZE_SLOTS_TO_USE);
                first_action_with_slot_idx.slots_to_use = slots_to_use;
            }

            if (hdr & SAM_LOG_HDR_CUSTOM_FIELDS) {
                uint8_t custom_len[SAM_LOG_BYTE_SIZE_TOTAL_CUSTOM_LEN];
                ring_buf_get(action_buf, custom_len, SAM_LOG_BYTE_SIZE_TOTAL_CUSTOM_LEN);
                first_action_with_slot_idx.total_custom_len = (custom_len[0] << 8) | custom_len[1];
            }
        }

        /* Add slot index if it was not in the action */
        if (!(first_action_with_slot_idx.hdr & SAM_LOG_HDR_SLOT_IDX)) {
            first_action_with_slot_idx.hdr |= SAM_LOG_HDR_SLOT_IDX;
            first_action_with_slot_idx.slot_idx =
                log_ctx.last_deleted_slot_idx + log_ctx.last_deleted_default_slots_to_use;
        }

        serialize_action(&first_action_with_slot_idx, tmp_buf, sizeof(tmp_buf));
        add_action_packed(&first_action_with_slot_idx, &bitbuf_state);

        actions_logged++;

        if (first_action_with_slot_idx.total_custom_len > 0) {
            uint8_t custom_data[first_action_with_slot_idx.total_custom_len];
            ring_buf_get(custom_buf, custom_data, first_action_with_slot_idx.total_custom_len);

            for (int i = 0; i < first_action_with_slot_idx.total_custom_len; i++) {
                bitbuf_state = add_on_offset(custom_data[i], 8, bitbuf_state);
            }
        }
    }

    struct sam_log_packed_action single_action_buffer;
    int single_action_bit_size;

    /* Process actions until buffer is empty or output is full */
    while (bitbuf_state.total_bits_written < out_size * 8 - 6) {
        if (ring_buf_size_get(action_buf) == 0) {
            /* No more data */
            break;
        }

        /* Reset single action buffer */
        single_action_buffer = (const struct sam_log_packed_action){0};
        single_action_bit_size = 0;

        /* Parse first byte to get action type */
        uint8_t first_byte;
        ring_buf_get(action_buf, &first_byte, 1);

        uint8_t m_hdr = (first_byte & SAM_LOG_MASK_M_HDR) >> SAM_LOG_SHIFT_M_HDR;
        uint8_t status = (first_byte & SAM_LOG_MASK_STATUS) >> SAM_LOG_SHIFT_STATUS;

        single_action_buffer.m_hdr = m_hdr;
        single_action_buffer.status = status;
        single_action_bit_size += SAM_LOG_BIT_SIZE_M_HDR + SAM_LOG_BIT_SIZE_STATUS;

        if (status == SAM_LOG_UNKNOWN) {
            uint8_t custom_status;
            /* High bits already contained in previous byte */
            ring_buf_get(action_buf, &custom_status, SAM_LOG_BYTE_SIZE_CUSTOM_STATUS - 1);
            single_action_buffer.custom_status = (first_byte & 0x3) | custom_status;
            single_action_bit_size += SAM_LOG_BIT_SIZE_CUSTOM_STATUS;
        }

        if (m_hdr) {
            uint8_t hdr;
            ring_buf_get(action_buf, &hdr, SAM_LOG_BYTE_SIZE_HDR);
            single_action_buffer.hdr = hdr;
            single_action_bit_size += SAM_LOG_BIT_SIZE_HDR;

            if (hdr & SAM_LOG_HDR_SLOT_IDX) {
                uint8_t slot_idx[SAM_LOG_BYTE_SIZE_SLOT_IDX];
                ring_buf_get(action_buf, slot_idx, SAM_LOG_BYTE_SIZE_SLOT_IDX);
                single_action_buffer.slot_idx =
                    (slot_idx[0] << 16) | (slot_idx[1] << 8) | slot_idx[2];
                single_action_bit_size += SAM_LOG_BIT_SIZE_SLOT_IDX;
            }

            if (hdr & SAM_LOG_HDR_SLOT_IDX_DIFF) {
                uint8_t slot_idx_diff[SAM_LOG_BYTE_SIZE_SLOT_IDX_DIFF];
                ring_buf_get(action_buf, slot_idx_diff, SAM_LOG_BYTE_SIZE_SLOT_IDX_DIFF);
                single_action_buffer.slot_idx_diff = (slot_idx_diff[0] << 8) | slot_idx_diff[1];
                single_action_bit_size += SAM_LOG_BIT_SIZE_SLOT_IDX_DIFF;
            }

            if (hdr & SAM_LOG_HDR_SLOTS_TO_USE) {
                uint8_t slots_to_use;
                ring_buf_get(action_buf, &slots_to_use, SAM_LOG_BYTE_SIZE_SLOTS_TO_USE);
                single_action_buffer.slots_to_use = slots_to_use;
                single_action_bit_size += SAM_LOG_BIT_SIZE_SLOTS_TO_USE;
            }

            if (hdr & SAM_LOG_HDR_CUSTOM_FIELDS) {
                uint8_t custom_len[SAM_LOG_BYTE_SIZE_TOTAL_CUSTOM_LEN];
                ring_buf_get(action_buf, custom_len, SAM_LOG_BYTE_SIZE_TOTAL_CUSTOM_LEN);
                single_action_buffer.total_custom_len = (custom_len[0] << 8) | custom_len[1];
                single_action_bit_size += SAM_LOG_BIT_SIZE_TOTAL_CUSTOM_LEN;
            }
        }

        /* Check output buffer space */
        if (bitbuf_state.total_bits_written + single_action_bit_size > out_size * 8) {
            break;
        }

        /* Copy action to output */
        add_action_packed(&single_action_buffer, &bitbuf_state);
        actions_logged++;

        /* Handle custom data if present */
        if (single_action_buffer.total_custom_len > 0) {
            /* Check output buffer space */
            if (bitbuf_state.total_bits_written + single_action_buffer.total_custom_len * 8 >
                out_size * 8) {
                continue;
            }

            uint8_t custom_data[single_action_buffer.total_custom_len];
            ring_buf_get(custom_buf, custom_data, single_action_buffer.total_custom_len);

            for (int i = 0; i < single_action_buffer.total_custom_len; i++) {
                bitbuf_state = add_on_offset(custom_data[i], 8, bitbuf_state);
            }
        }
    }

    /* Put number of actions logged at the start of the output buffer */
    out_buf[1] = actions_logged;

    // Calculate actual bytes written based on bits written
    size_t bits_written = bitbuf_state.total_bits_written;
    size_t bytes_written_for_actions = (bits_written + 7) / 8;  // Round up to nearest byte

    LOG_INF("out_buf[0] (default_slots) = %u, out_buf[1] (num_actions) = %u", out_buf[0],
            out_buf[1]);
    return 2 + bytes_written_for_actions;  // 2 header bytes + action data
}

/* Flush logs and encode them */
int sam_log_flush(char *log_name, uint32_t epoch_id, size_t *bytes_written) {
    /* Z85 encoding requires 5 bytes for every 4 bytes, plus padding */
    static char encoded[SAM_LOG_SERIALIZE_BUF_SIZE * 5 / 4 + 10];
    size_t encoded_len;
    size_t serialize_len;

    if (!log_name) {
        return -EINVAL;
    }

    /* Reset output */
    if (bytes_written) {
        *bytes_written = 0;
    }

    /* Process START buffer */
    memset(serialize_buf, 0, sizeof(serialize_buf));
    serialize_len = process_buffer(&log_ctx.start_actions, &log_ctx.start_custom, serialize_buf,
                                   sizeof(serialize_buf), false);
    LOG_INF("Serialized START buffer contains %u bytes", serialize_len);

    if (serialize_len > 0) {
        /* Encode to Z85 */
        memset(encoded, 0, sizeof(encoded));
        encoded_len = Z85_encode_with_padding((char *)serialize_buf, encoded, serialize_len);

        if (encoded_len > 0 && encoded_len < sizeof(encoded)) {
            encoded[encoded_len] = '\0';
            LOG_PRINTK("LOG[%s] START %u %s\n", log_name, epoch_id, encoded);

            if (bytes_written) {
                *bytes_written += encoded_len;
            }
        }
    }

    /* Process END buffer */
    if (log_ctx.start_buffer_full) {
        memset(serialize_buf, 0, sizeof(serialize_buf));
        serialize_len = process_buffer(&log_ctx.end_actions, &log_ctx.end_custom, serialize_buf,
                                       sizeof(serialize_buf), true);
        LOG_INF("Serialized END buffer contains %u bytes", serialize_len);

        if (serialize_len > 0) {
            /* Encode to Z85 */
            memset(encoded, 0, sizeof(encoded));
            encoded_len = Z85_encode_with_padding((char *)serialize_buf, encoded, serialize_len);

            if (encoded_len > 0 && encoded_len < sizeof(encoded)) {
                encoded[encoded_len] = '\0';
                LOG_PRINTK("LOG[%s] END %u %s\n", log_name, epoch_id, encoded);

                if (bytes_written) {
                    *bytes_written += encoded_len;
                }
            }
        }
    }

    /* Log statistics and reset */
    LOG_DBG("Stats: %u actions logged, %u dropped; %u custom fields logged, %u dropped",
            log_ctx.stats.actions_logged, log_ctx.stats.actions_dropped,
            log_ctx.stats.custom_fields_logged, log_ctx.stats.custom_fields_dropped);

    reset_log_context();

    return 0;
}