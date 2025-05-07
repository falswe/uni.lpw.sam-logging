#include "sam_log.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/ring_buffer.h>

#include "z85.h"

LOG_MODULE_REGISTER(sam_log, CONFIG_LOG_DEFAULT_LEVEL);

/* Configuration */
#define SAM_LOG_ACTIONS_BUF_SIZE 512
#define SAM_LOG_CUSTOM_BUF_SIZE 512
#define SAM_LOG_SERIALIZE_BUF_SIZE 1024

/* Bit masks for first byte */
#define EXTENDED_HDR_BITMASK 0x80
#define STATUS_BITMASK 0x1F
#define CUSTOM_STATUS_VALUE (SAM_LOG_UNKNOWN)

/* Define bit field sizes according to the specification */
#define SAM_LOG_BIT_SIZE_M_HDR 1
#define SAM_LOG_BIT_SIZE_STATUS 5
#define SAM_LOG_BIT_SIZE_CUSTOM_STATUS 10
#define SAM_LOG_BIT_SIZE_HDR 8
#define SAM_LOG_BIT_SIZE_SLOT_IDX 24
#define SAM_LOG_BIT_SIZE_SLOT_IDX_DIFF 16
#define SAM_LOG_BIT_SIZE_SLOTS_TO_USE 8
#define SAM_LOG_BIT_SIZE_TOTAL_CUSTOM_LEN 16

#define SAM_LOG_BYTE_SIZE_CUSTOM_STATUS \
    (((SAM_LOG_BIT_SIZE_CUSTOM_STATUS + (SAM_LOG_BIT_SIZE_CUSTOM_STATUS % 8)) / 8))
#define SAM_LOG_BYTE_SIZE_HDR ((SAM_LOG_BIT_SIZE_HDR + (SAM_LOG_BIT_SIZE_HDR % 8)) / 8)
#define SAM_LOG_BYTE_SIZE_SLOT_IDX \
    ((SAM_LOG_BIT_SIZE_SLOT_IDX + (SAM_LOG_BIT_SIZE_SLOT_IDX % 8)) / 8)
#define SAM_LOG_BYTE_SIZE_SLOT_IDX_DIFF \
    ((SAM_LOG_BIT_SIZE_SLOT_IDX_DIFF + (SAM_LOG_BIT_SIZE_SLOT_IDX_DIFF % 8)) / 8)
#define SAM_LOG_BYTE_SIZE_SLOTS_TO_USE \
    ((SAM_LOG_BIT_SIZE_SLOTS_TO_USE + (SAM_LOG_BIT_SIZE_SLOTS_TO_USE % 8)) / 8)
#define SAM_LOG_BYTE_SIZE_TOTAL_CUSTOM_LEN \
    ((SAM_LOG_BIT_SIZE_TOTAL_CUSTOM_LEN + (SAM_LOG_BIT_SIZE_TOTAL_CUSTOM_LEN % 8)) / 8)

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
    uint8_t default_slots_to_use;
    uint32_t current_slot_idx;
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

uint32_t le_to_be_24(uint32_t val) {
    return ((val & 0x000000FF) << 16) | ((val & 0x0000FF00)) | ((val & 0x00FF0000) >> 16) |
           (val & 0x00000000);
}

/* Serialize an action to a byte array */
static size_t serialize_action(const struct sam_log_packed_action *action, uint8_t *buf,
                               size_t bufsize) {
    size_t pos = 0;

    if (bufsize < 1) {
        return 0;
    }

    /* First byte: m_hdr and status */
    // TODO: 2 reserved bits placed between status and m_hdr - let's have more aggressive packing.
    // status should be placed after m_hdr directly, so custom_status can possibly fit.
    buf[pos++] = ((action->m_hdr & 0x01) << 7) | (action->status & STATUS_BITMASK);

    /* Custom status if needed */
    // TODO: let's place custom status in the remaining two bits of m_hdr and status and a new byte
    if (action->status == CUSTOM_STATUS_VALUE) {
        if (pos + 2 > bufsize) {
            return 0;
        }

        uint16_t custom_status = action->custom_status & 0x3FF; /* 10-bit mask */
        buf[pos++] = (custom_status >> 2) & 0xFF;               /* Upper 8 bits */
        buf[pos++] = ((custom_status & 0x03) << 6) & 0xC0;      /* Lower 2 bits */
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
            if (pos + 3 > bufsize) {
                return 0;
            }
            buf[pos++] = (action->slot_idx >> 16) & 0xFF;
            buf[pos++] = (action->slot_idx >> 8) & 0xFF;
            buf[pos++] = action->slot_idx & 0xFF;
        }

        /* Slot diff if needed */
        if (action->hdr & SAM_LOG_HDR_SLOT_IDX_DIFF) {
            if (pos + 2 > bufsize) {
                return 0;
            }
            buf[pos++] = (action->slot_idx_diff >> 8) & 0xFF;
            buf[pos++] = action->slot_idx_diff & 0xFF;
        }

        /* Slots to use if needed */
        if (action->hdr & SAM_LOG_HDR_SLOTS_TO_USE) {
            if (pos + 1 > bufsize) {
                return 0;
            }
            buf[pos++] = action->slots_to_use;
        }

        /* Custom data length if needed */
        if (action->hdr & SAM_LOG_HDR_CUSTOM_FIELDS) {
            if (pos + 2 > bufsize) {
                return 0;
            }
            buf[pos++] = (action->total_custom_len >> 8) & 0xFF;
            buf[pos++] = action->total_custom_len & 0xFF;
        }
    }

    return pos;
}

/* Initialize the logging subsystem */
int sam_log_init(void) {
    /* Initialize ring buffers */
    ring_buf_init(&log_ctx.start_actions, sizeof(start_actions_buf), start_actions_buf);
    ring_buf_init(&log_ctx.start_custom, sizeof(start_custom_buf), start_custom_buf);
    ring_buf_init(&log_ctx.end_actions, sizeof(end_actions_buf), end_actions_buf);
    ring_buf_init(&log_ctx.end_custom, sizeof(end_custom_buf), end_custom_buf);

    /* Initialize context */
    log_ctx.logging_enabled = true;
    log_ctx.default_slots_to_use = 1;
    log_ctx.current_slot_idx = 0;
    memset(&log_ctx.stats, 0, sizeof(struct sam_log_stats));

    return 0;
}

/* Add an action to a buffer */
static int add_to_buffer(struct ring_buf *action_buf, struct ring_buf *custom_buf,
                         const struct sam_log_packed_action *action, const void *custom_data,
                         uint16_t custom_data_len) {
    uint8_t buf[32]; /* Temp buffer for serialized action */
    size_t len;
    uint32_t ret;

    /* Serialize the action */
    len = serialize_action(action, buf, sizeof(buf));
    if (len == 0) {
        LOG_ERR("Failed to serialize action");
        log_ctx.stats.actions_dropped++;
        return -EINVAL;
    }

    /* Check space availability */
    if (ring_buf_space_get(action_buf) < len ||
        (custom_data_len > 0 && ring_buf_space_get(custom_buf) < custom_data_len)) {
        LOG_WRN("Buffer full: action=%zu, custom=%u", ring_buf_space_get(action_buf),
                ring_buf_space_get(custom_buf));
        log_ctx.stats.actions_dropped++;
        return -ENOMEM;
    }

    /* Add action to buffer */
    ret = ring_buf_put(action_buf, buf, len);
    if (ret < len) {
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

        /* Handle custom status if present */
        if ((first_byte & STATUS_BITMASK) == CUSTOM_STATUS_VALUE) {
            ring_buf_get(action_buf, NULL,
                         SAM_LOG_BYTE_SIZE_CUSTOM_STATUS); /* Skip custom status bytes */
        }

        /* Handle extended header if present */
        if (first_byte & EXTENDED_HDR_BITMASK) {
            uint8_t hdr;

            if (ring_buf_get(action_buf, &hdr, 1) < 1) {
                break;
            }

            /* Remove all header-dependent fields */
            if (hdr & SAM_LOG_HDR_SLOT_IDX) {
                uint32_t slot_idx = 0;
                ring_buf_get(&log_ctx.end_actions, (uint8_t *)&slot_idx,
                             SAM_LOG_BYTE_SIZE_SLOT_IDX);
                // LOG_INF("Removing slot_idx: %u", le_to_be_24(slot_idx));
            }
            if (hdr & SAM_LOG_HDR_SLOT_IDX_DIFF) {
                ring_buf_get(action_buf, NULL, SAM_LOG_BYTE_SIZE_SLOT_IDX_DIFF);
            }
            if (hdr & SAM_LOG_HDR_SLOTS_TO_USE) {
                ring_buf_get(action_buf, NULL, SAM_LOG_BYTE_SIZE_SLOTS_TO_USE);
            }
            if (hdr & SAM_LOG_HDR_CUSTOM_FIELDS) {
                uint8_t len_bytes[2];
                uint16_t custom_len;

                ring_buf_get(action_buf, len_bytes, SAM_LOG_BYTE_SIZE_TOTAL_CUSTOM_LEN);
                // if (ring_buf_get(action_buf, len_bytes,
                //  (int)ceil(SAM_LOG_BIT_SIZE_TOTAL_CUSTOM_LEN / 8.0)) < 2) {
                // break;
                // }

                custom_len = (len_bytes[0] << 8) | len_bytes[1];
                ring_buf_get(custom_buf, NULL, custom_len);
                log_ctx.stats.custom_fields_dropped++;
            }
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
    if (status == CUSTOM_STATUS_VALUE) {
        action.custom_status = custom_status & 0x3FF; /* 10-bit limit */
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

        if (slots_to_use != log_ctx.default_slots_to_use) {
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
    uint8_t temp_buf[32];
    size_t action_size = serialize_action(&action, temp_buf, sizeof(temp_buf));

    if (action_size == 0) {
        LOG_ERR("Failed to calculate action size");
        log_ctx.stats.actions_dropped++;
        return -EINVAL;
    }

    /* Try to add to start buffer */
    // TODO: looks like this could mess up the order of the actions - start buffer full should be
    // calculated only once (once it's "full", switch to end buffer)
    bool start_buffer_full =
        (ring_buf_space_get(&log_ctx.start_actions) < action_size ||
         (custom_data_len > 0 && ring_buf_space_get(&log_ctx.start_custom) < custom_data_len));

    if (!start_buffer_full) {
        ret = add_to_buffer(&log_ctx.start_actions, &log_ctx.start_custom, &action, custom_data,
                            custom_data_len);
        if (ret < 0) {
            start_buffer_full = true;
        } else {
            // LOG_INF("...Added to start buffer slot_idx %d", slot_idx);
        }
    }

    /* Add to end buffer if start buffer is full */
    if (start_buffer_full) {
        /* Make room in end buffer if needed */
        make_room_in_buffer(&log_ctx.end_actions, &log_ctx.end_custom, action_size,
                            custom_data_len);

        ret = add_to_buffer(&log_ctx.end_actions, &log_ctx.end_custom, &action, custom_data,
                            custom_data_len);

        if (ret < 0) {
            LOG_WRN("Failed to add to end buffer: %d", ret);
            log_ctx.stats.actions_dropped++;
            return ret;
        } else {
            // LOG_INF("+++Now end buffer size is: %d", ring_buf_size_get(&log_ctx.end_actions));
            // LOG_INF("...Added to end buffer slot_idx %d", slot_idx);
        }
    }

    /* Update current slot index */
    if (status == SAM_LOG_SYNCH_DONE) {
        log_ctx.current_slot_idx = slot_idx;
    } else {
        log_ctx.current_slot_idx += slots_to_use;
    }

    return 0;
}

/* Log an action with only status */
// TODO: might need to always have slot_idx and slot_idx_diff as a parameter - otherwise they will
// be logged with the anticipated (but maybe wrong) value
int sam_log_action_status(enum sam_log_status status) {
    return sam_log_action(status, 0, log_ctx.current_slot_idx, 0, log_ctx.default_slots_to_use,
                          false, NULL, 0);
}

/* Get logging statistics */
int sam_log_get_stats(struct sam_log_stats *stats) {
    if (!stats) {
        return -EINVAL;
    }

    *stats = log_ctx.stats;
    return 0;
}

/* Process actions from a buffer and serialize them */
static size_t process_buffer(struct ring_buf *action_buf, struct ring_buf *custom_buf,
                             uint8_t *out_buf, size_t out_size) {
    uint8_t *start_action_data, *end_action_data, *start_custom_data, *end_custom_data;
    uint32_t start_action_length, end_action_length, start_custom_length, end_custom_length;
    size_t serialize_pos = 0;

    uint32_t total_action_size = ring_buf_size_get(action_buf);
    uint32_t total_custom_size = ring_buf_size_get(custom_buf);

    LOG_INF("...Action buffer occupied size: %d", total_action_size);
    LOG_INF("...Custom buffer occupied size: %d", total_custom_size);

    /* Get all data from the buffers */
    start_action_length =
        ring_buf_get_claim(action_buf, &start_action_data, SAM_LOG_ACTIONS_BUF_SIZE);
    start_custom_length =
        ring_buf_get_claim(custom_buf, &start_custom_data, SAM_LOG_CUSTOM_BUF_SIZE);

    if (start_action_length < total_action_size) {
        ring_buf_get_claim(action_buf, &end_action_data, SAM_LOG_ACTIONS_BUF_SIZE);
    }
    if (start_custom_length < total_custom_size) {
        ring_buf_get_claim(custom_buf, &end_custom_data, SAM_LOG_ACTIONS_BUF_SIZE);
    }

    if (start_action_length == 0) {
        return 0;
    }

    uint8_t *current_action_data = start_action_data;
    uint8_t *current_custom_data = start_custom_data;
    uint32_t *current_action_buf_length = &start_action_length;
    uint32_t *current_custom_buf_length = &start_custom_length;

    uint32_t processed_action_size = 0;
    uint32_t processed_custom_size = 0;
    uint32_t action_pos = 0;
    uint32_t custom_pos = 0;

    /* Process each action */
    while (processed_action_size < total_action_size) {
        if (processed_action_size >= start_action_length) {
            current_action_data = end_action_data;
            current_action_buf_length = &end_action_length;
            action_pos = 0;
            LOG_INF("...Switching to end action buffer");
        }
        if (processed_custom_size >= start_custom_length) {
            current_custom_data = end_custom_data;
            current_custom_buf_length = &end_custom_length;
            custom_pos = 0;
            LOG_INF("...Switching to end custom buffer");
        }

        /* Get first byte to determine action type */
        uint8_t first_byte = current_action_data[action_pos];
        uint8_t m_hdr = (first_byte & EXTENDED_HDR_BITMASK) >> 7;
        uint8_t status = first_byte & STATUS_BITMASK;

        /* Determine action size */
        size_t action_size = 1; /* Start with first byte */
        uint16_t custom_data_size = 0;
        bool has_custom_data = false;

        /* Handle custom status */
        if (status == CUSTOM_STATUS_VALUE) {
            action_size += SAM_LOG_BYTE_SIZE_CUSTOM_STATUS;
        }

        /* Process extended header */
        if (m_hdr) {
            if (action_pos + action_size >= *current_action_buf_length) {
                break;
            }

            uint8_t hdr = current_action_data[action_pos + action_size];
            action_size += 1;

            /* Calculate size based on header fields */
            if (hdr & SAM_LOG_HDR_SLOT_IDX) {
                LOG_INF("...Processing slot_idx %d",
                        current_action_data[action_pos + action_size] << 16 |
                            current_action_data[action_pos + action_size + 1] << 8 |
                            current_action_data[action_pos + action_size + 2]);
                action_size += SAM_LOG_BYTE_SIZE_SLOT_IDX;
            }

            if (hdr & SAM_LOG_HDR_SLOT_IDX_DIFF) {
                action_size += SAM_LOG_BYTE_SIZE_SLOT_IDX_DIFF;
            }

            if (hdr & SAM_LOG_HDR_SLOTS_TO_USE) {
                action_size += SAM_LOG_BYTE_SIZE_SLOTS_TO_USE;
            }

            if (hdr & SAM_LOG_HDR_CUSTOM_FIELDS) {
                has_custom_data = true;

                if (action_pos + action_size + 1 >= *current_action_buf_length) {
                    break;
                }

                custom_data_size = (current_action_data[action_pos + action_size] << 8) |
                                   current_action_data[action_pos + action_size + 1];
                action_size += SAM_LOG_BYTE_SIZE_TOTAL_CUSTOM_LEN;
            }
        }

        /* Check buffer space */
        if (serialize_pos + action_size + custom_data_size > out_size) {
            break;
        }

        /* Check for complete action */
        if (action_pos + action_size > *current_action_buf_length) {
            break;
        }

        /* Copy action to output buffer */
        memcpy(out_buf + serialize_pos, current_action_data + action_pos, action_size);
        serialize_pos += action_size;

        /* Copy custom data if present */
        if (has_custom_data && custom_data_size > 0) {
            if (custom_pos + custom_data_size > *current_custom_buf_length) {
                break;
            }

            memcpy(out_buf + serialize_pos, current_custom_data + custom_pos, custom_data_size);
            serialize_pos += custom_data_size;
            custom_pos += custom_data_size;
        }

        action_pos += action_size;
        processed_action_size += action_size;
    }

    // TODO: checking if action_ and custom_pos match action_ and custom_length could be interesting

    /* Free the claimed data */
    ring_buf_get_finish(action_buf, total_action_size);
    ring_buf_get_finish(custom_buf, total_custom_size);

    return serialize_pos;
}

/* Flush logs and encode them */
int sam_log_flush(char *log_name, uint32_t epoch_id, size_t *bytes_written) {
    char encoded[SAM_LOG_SERIALIZE_BUF_SIZE * 5 / 4 + 10]; /* Z85 encoding overhead + padding */
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
                                   sizeof(serialize_buf));

    if (serialize_len > 0) {
        /* Encode to Z85 */
        memset(encoded, 0, sizeof(encoded));
        encoded_len = Z85_encode_with_padding((char *)serialize_buf, encoded, serialize_len);

        if (encoded_len > 0 && encoded_len < sizeof(encoded)) {
            encoded[encoded_len] = '\0';
            LOG_INF("LOG[%s] START %u %s", log_name, epoch_id, encoded);

            if (bytes_written) {
                *bytes_written += encoded_len;
            }
        }
    }

    /* Process END buffer */
    memset(serialize_buf, 0, sizeof(serialize_buf));
    serialize_len = process_buffer(&log_ctx.end_actions, &log_ctx.end_custom, serialize_buf,
                                   sizeof(serialize_buf));

    if (serialize_len > 0) {
        /* Encode to Z85 */
        memset(encoded, 0, sizeof(encoded));
        encoded_len = Z85_encode_with_padding((char *)serialize_buf, encoded, serialize_len);

        if (encoded_len > 0 && encoded_len < sizeof(encoded)) {
            encoded[encoded_len] = '\0';
            LOG_INF("LOG[%s] END %u %s", log_name, epoch_id, encoded);

            if (bytes_written) {
                *bytes_written += encoded_len;
            }
        }
    }

    /* Log statistics and reset */
    LOG_DBG("Stats: %u actions logged, %u dropped; %u custom fields logged, %u dropped",
            log_ctx.stats.actions_logged, log_ctx.stats.actions_dropped,
            log_ctx.stats.custom_fields_logged, log_ctx.stats.custom_fields_dropped);

    memset(&log_ctx.stats, 0, sizeof(struct sam_log_stats));

    return 0;
}