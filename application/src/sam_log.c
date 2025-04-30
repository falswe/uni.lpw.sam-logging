#include "sam_log.h"

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/ring_buffer.h>

#include "z85.h"

LOG_MODULE_REGISTER(sam_log, CONFIG_LOG_DEFAULT_LEVEL);

/* Configuration for the logging subsystem */
#define SAM_LOG_ACTIONS_BUF_SIZE 512 /* Should accommodate ~100 actions */
#define SAM_LOG_CUSTOM_BUF_SIZE 512
#define SAM_LOG_SERIALIZE_BUF_SIZE 8192

/* Define bit field sizes according to the specification */
#define SAM_LOG_BIT_SIZE_M_HDR 1             /* 1 bit for m_hdr */
#define SAM_LOG_BIT_SIZE_STATUS 5            /* 5 bits for status */
#define SAM_LOG_BIT_SIZE_CUSTOM_STATUS 10    /* 10 bits for custom_status */
#define SAM_LOG_BIT_SIZE_HDR 8               /* 8 bits for header */
#define SAM_LOG_BIT_SIZE_SLOT_IDX 24         /* 24 bits for slot_idx */
#define SAM_LOG_BIT_SIZE_SLOT_IDX_DIFF 16    /* 16 bits for slot_idx_diff */
#define SAM_LOG_BIT_SIZE_SLOTS_TO_USE 8      /* 8 bits for slots_to_use */
#define SAM_LOG_BIT_SIZE_TOTAL_CUSTOM_LEN 16 /* 16 bits for total_custom_len */

/* Structure representing a serialized action */
struct sam_log_packed_action {
    uint8_t m_hdr : SAM_LOG_BIT_SIZE_M_HDR;                  /* 1 if extended header is present */
    uint8_t status : SAM_LOG_BIT_SIZE_STATUS;                /* Action result status */
    uint16_t custom_status : SAM_LOG_BIT_SIZE_CUSTOM_STATUS; /* Custom status as per spec */
    uint8_t hdr : SAM_LOG_BIT_SIZE_HDR;                      /* Standard header bitmask */
    uint32_t slot_idx : SAM_LOG_BIT_SIZE_SLOT_IDX;           /* Slot index for the action */
    int16_t slot_idx_diff : SAM_LOG_BIT_SIZE_SLOT_IDX_DIFF;  /* Difference from expected slot */
    uint8_t slots_to_use : SAM_LOG_BIT_SIZE_SLOTS_TO_USE; /* Number of slots used by the action */
    uint16_t total_custom_len
        : SAM_LOG_BIT_SIZE_TOTAL_CUSTOM_LEN; /* Total length of custom fields */
} __attribute__((packed));

/* Structure for the logging subsystem */
struct sam_log_ctx {
    struct ring_buf start_actions; /* Buffer for first N actions */
    struct ring_buf end_actions;   /* Buffer for last N actions */
    struct ring_buf start_custom;  /* Buffer for first N custom fields */
    struct ring_buf end_custom;    /* Buffer for last N custom fields */
    bool logging_enabled;          /* Whether logging is enabled */
    uint8_t default_slots_to_use;  /* Default slots to use */
    uint32_t current_slot_idx;     /* Current slot index for sequential logging */
    struct sam_log_stats stats;    /* Logging statistics */
};

/* Buffers for the ringbuffers */
static uint8_t start_actions_buf[SAM_LOG_ACTIONS_BUF_SIZE];
static uint8_t end_actions_buf[SAM_LOG_ACTIONS_BUF_SIZE];
static uint8_t start_custom_buf[SAM_LOG_CUSTOM_BUF_SIZE];
static uint8_t end_custom_buf[SAM_LOG_CUSTOM_BUF_SIZE];

/* The logging context */
static struct sam_log_ctx log_ctx;

/* Buffer for serialized logs */
static uint8_t serialize_buf[SAM_LOG_SERIALIZE_BUF_SIZE];

/* Helper function to serialize an action into a byte array */
static size_t serialize_action(const struct sam_log_packed_action *action, uint8_t *buf,
                               size_t bufsize) {
    size_t pos = 0;

    if (bufsize < 1) {
        return 0;
    }

    /* Write m_hdr and status (first byte) */
    buf[pos++] = ((action->m_hdr & 0x01) << 7) | (action->status & 0x1F);

    /* If status is SAM_LOG_UNKNOWN, write custom_status (10 bits) */
    if (action->status == SAM_LOG_UNKNOWN) {
        if (pos + 2 > bufsize) {
            return 0;
        }

        /* We need to access custom_status through the structure */
        uint16_t custom_status_value =
            action->custom_status & ((1 << SAM_LOG_BIT_SIZE_CUSTOM_STATUS) - 1);

        /* Write the 10-bit custom_status value across two bytes */
        buf[pos++] = (custom_status_value >> 2) & 0xFF;          /* Upper 8 bits */
        buf[pos++] = ((custom_status_value & 0x03) << 6) & 0xC0; /* Lower 2 bits in top position */
    }

    /* If m_hdr is set, write additional fields */
    if (action->m_hdr) {
        if (pos + 1 > bufsize) {
            return 0;
        }

        /* Write header byte */
        buf[pos++] = action->hdr;

        /* Write slot_idx if needed */
        if (action->hdr & SAM_LOG_HDR_SLOT_IDX) {
            if (pos + 3 > bufsize) {
                return 0;
            }
            buf[pos++] = (action->slot_idx >> 16) & 0xFF;
            buf[pos++] = (action->slot_idx >> 8) & 0xFF;
            buf[pos++] = action->slot_idx & 0xFF;
        }

        /* Write slot_idx_diff if needed */
        if (action->hdr & SAM_LOG_HDR_SLOT_IDX_DIFF) {
            if (pos + 2 > bufsize) {
                return 0;
            }
            buf[pos++] = (action->slot_idx_diff >> 8) & 0xFF;
            buf[pos++] = action->slot_idx_diff & 0xFF;
        }

        /* Write slots_to_use if needed */
        if (action->hdr & SAM_LOG_HDR_SLOTS_TO_USE) {
            if (pos + 1 > bufsize) {
                return 0;
            }
            buf[pos++] = action->slots_to_use;
        }

        /* Write total_custom_len if needed */
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
    /* Initialize ringbuffers */
    ring_buf_init(&log_ctx.start_actions, sizeof(start_actions_buf), start_actions_buf);
    ring_buf_init(&log_ctx.end_actions, sizeof(end_actions_buf), end_actions_buf);
    ring_buf_init(&log_ctx.start_custom, sizeof(start_custom_buf), start_custom_buf);
    ring_buf_init(&log_ctx.end_custom, sizeof(end_custom_buf), end_custom_buf);

    /* Initialize the context */
    log_ctx.logging_enabled = true;
    log_ctx.default_slots_to_use = 1; /* Default is 1 slot per action */
    log_ctx.current_slot_idx = 0;

    /* Clear statistics */
    memset(&log_ctx.stats, 0, sizeof(struct sam_log_stats));

    return 0;
}

/* Helper function to add an action to a buffer */
static int add_to_buffer(struct ring_buf *action_buf, struct ring_buf *custom_buf,
                         const struct sam_log_packed_action *action, const void *custom_data,
                         uint16_t custom_data_len) {
    uint8_t buf[32]; /* Temporary buffer for serialized action */
    size_t len;
    int ret;

    /* Serialize the action */
    len = serialize_action(action, buf, sizeof(buf));
    if (len == 0) {
        LOG_ERR("Failed to serialize action");
        log_ctx.stats.actions_dropped++;
        return -EINVAL;
    }

    /* Check if we have enough space */
    if (ring_buf_space_get(action_buf) < len ||
        (custom_data_len > 0 && ring_buf_space_get(custom_buf) < custom_data_len)) {
        LOG_WRN("Buffer full: action=%zu, custom=%u", ring_buf_space_get(action_buf),
                ring_buf_space_get(custom_buf));
        log_ctx.stats.actions_dropped++;
        return -ENOMEM;
    }

    /* Add the action to the buffer */
    ret = ring_buf_put(action_buf, buf, len);
    if (ret < len) {
        LOG_ERR("Failed to add action to buffer");
        log_ctx.stats.actions_dropped++;
        return -EIO;
    }

    /* If we have custom data, add it to the custom buffer */
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

    /* Set mandatory fields */
    action.status = status;

    /* If status is the maximum value, we need to set custom_status */
    if (status == SAM_LOG_UNKNOWN) {
        /* Ensure custom_status fits in the 10-bit field */
        action.custom_status = custom_status & ((1 << SAM_LOG_BIT_SIZE_CUSTOM_STATUS) - 1);
        if (custom_status != action.custom_status) {
            LOG_WRN("Custom status 0x%04x truncated to 10 bits: 0x%03x", custom_status,
                    action.custom_status);
        }
    }

    /* If we have any additional fields, we need the extended header */
    if (slot_idx != log_ctx.current_slot_idx || slot_idx_diff != 0 ||
        slots_to_use != log_ctx.default_slots_to_use || set_default_slots || custom_data_len > 0 ||
        status == SAM_LOG_SYNCH_DONE) {
        action.m_hdr = 1;

        /* Build the header based on which fields we include */
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

    /* Try to add to start buffer first */
    uint8_t buf[32]; /* Temporary buffer for serialized action */
    size_t len = serialize_action(&action, buf, sizeof(buf));
    if (len == 0) {
        LOG_ERR("Failed to serialize action");
        log_ctx.stats.actions_dropped++;
        return -EINVAL;
    }

    bool start_buffer_full =
        (ring_buf_space_get(&log_ctx.start_actions) < len ||
         (custom_data_len > 0 && ring_buf_space_get(&log_ctx.start_custom) < custom_data_len));

    /* Add to start buffer if there's space */
    if (!start_buffer_full) {
        ret = add_to_buffer(&log_ctx.start_actions, &log_ctx.start_custom, &action, custom_data,
                            custom_data_len);
        if (ret < 0) {
            LOG_WRN("Failed to add to start buffer: %d", ret);
            start_buffer_full = true;
        }
    }

    /* Add to end buffer only if start buffer is full */
    if (start_buffer_full) {
        ret = add_to_buffer(&log_ctx.end_actions, &log_ctx.end_custom, &action, custom_data,
                            custom_data_len);
        if (ret < 0) {
            LOG_WRN("Failed to add to end buffer: %d", ret);
            log_ctx.stats.actions_dropped++;
            return ret;
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

/* Helper function to extract the size of an action from its serialized form */
static size_t get_action_size(uint8_t *action_data, uint32_t action_pos, uint32_t action_length) {
    size_t action_size = 1; /* Start with the first byte */

    if (action_pos >= action_length) {
        return 0;
    }

    /* First byte contains m_hdr and status */
    uint8_t first_byte = action_data[action_pos];
    uint8_t m_hdr = (first_byte & 0x80) >> 7;
    uint8_t status = first_byte & 0x1F;

    /* If status is SAM_LOG_UNKNOWN, add custom_status size */
    if (status == SAM_LOG_UNKNOWN) {
        action_size += 2; /* 10-bit custom status spans 2 bytes */
    }

    /* If m_hdr is set, we have extended header */
    if (m_hdr) {
        /* Add header byte size */
        action_size += 1;

        /* Check bounds */
        if (action_pos + 1 >= action_length) {
            return action_size; /* Return what we have so far */
        }

        /* Read header byte */
        uint8_t hdr = action_data[action_pos + 1];

        /* Add field sizes based on header */
        if (hdr & SAM_LOG_HDR_SLOT_IDX) {
            action_size += 3;
        }

        if (hdr & SAM_LOG_HDR_SLOT_IDX_DIFF) {
            action_size += 2;
        }

        if (hdr & SAM_LOG_HDR_SLOTS_TO_USE) {
            action_size += 1;
        }

        if (hdr & SAM_LOG_HDR_CUSTOM_FIELDS) {
            /* Custom data length field */
            action_size += 2;

            /* Check bounds */
            if (action_pos + action_size <= action_length) {
                /* Add custom data size */
                uint16_t custom_len = (action_data[action_pos + action_size - 2] << 8) |
                                      action_data[action_pos + action_size - 1];
                action_size += custom_len;
            }
        }
    }

    return action_size;
}

/* Function to process a buffer of actions and encode them */
static int process_and_encode_buffer(struct ring_buf *action_buf, struct ring_buf *custom_buf,
                                     char *log_name, uint32_t epoch_id, char *buffer_name) {
    uint8_t *action_data, *custom_data;
    uint32_t action_length, custom_length;
    char encoded[SAM_LOG_SERIALIZE_BUF_SIZE * 5 / 4 + 10]; /* Z85 encoding overhead + padding */
    size_t encoded_len;

    /* Get data from the buffers */
    action_length = ring_buf_get_claim(action_buf, &action_data, UINT32_MAX);
    custom_length = ring_buf_get_claim(custom_buf, &custom_data, UINT32_MAX);

    if (action_length == 0) {
        return 0; /* No data to process */
    }

    /* Completely zero out the buffer */
    memset(serialize_buf, 0, sizeof(serialize_buf));
    size_t serialize_pos = 0;

    /* Copy and validate each action */
    uint32_t action_pos = 0;
    uint32_t custom_pos = 0;
    size_t total_size = 0;

    while (action_pos < action_length) {
        /* Check if this could be a valid action */
        if (action_pos + 1 > action_length) {
            break; /* Not enough data left */
        }

        /* Validate first byte */
        uint8_t first_byte = action_data[action_pos];
        uint8_t m_hdr = (first_byte & 0x80) >> 7;
        uint8_t status = first_byte & 0x1F;
        uint8_t reserved = (first_byte & 0x60) >> 5;

        /* Invalid action - stop processing */
        if (status > 19 || reserved != 0) {
            LOG_ERR("Invalid action at pos %u", action_pos);
            break;
        }

        /* Get the size of this action */
        size_t action_size = get_action_size(action_data, action_pos, action_length);
        if (action_size == 0 || action_pos + action_size > action_length) {
            LOG_ERR("Invalid action size %zu at pos %u", action_size, action_pos);
            break;
        }

        /* Ensure we have enough space in the buffer */
        if (serialize_pos + action_size >= SAM_LOG_SERIALIZE_BUF_SIZE) {
            LOG_WRN("Buffer full, truncating");
            break;
        }

        /* Check if this action has custom data */
        size_t header_size = action_size;
        uint16_t custom_data_size = 0;
        bool has_custom_data = false;

        if (m_hdr && (action_pos + 2 <= action_length)) {
            uint8_t hdr = action_data[action_pos + 1];
            if (hdr & SAM_LOG_HDR_CUSTOM_FIELDS) {
                has_custom_data = true;

                /* Find position of custom data length */
                size_t custom_len_pos = 2; /* Start after first byte and header */

                if (hdr & SAM_LOG_HDR_SLOT_IDX) {
                    custom_len_pos += 3;
                }

                if (hdr & SAM_LOG_HDR_SLOT_IDX_DIFF) {
                    custom_len_pos += 2;
                }

                if (hdr & SAM_LOG_HDR_SLOTS_TO_USE) {
                    custom_len_pos += 1;
                }

                /* Check bounds */
                if (action_pos + custom_len_pos + 1 < action_length) {
                    custom_data_size = (action_data[action_pos + custom_len_pos] << 8) |
                                       action_data[action_pos + custom_len_pos + 1];

                    /* Adjust action_size to not include custom data */
                    header_size = custom_len_pos + 2; /* +2 for custom data length field */
                }
            }
        }

        /* Copy the action header */
        memcpy(serialize_buf + serialize_pos, action_data + action_pos, header_size);
        serialize_pos += header_size;

        /* Copy custom data if needed */
        if (has_custom_data && custom_data_size > 0) {
            if (custom_pos + custom_data_size <= custom_length) {
                memcpy(serialize_buf + serialize_pos, custom_data + custom_pos, custom_data_size);
                serialize_pos += custom_data_size;
                custom_pos += custom_data_size;
            } else {
                LOG_ERR("Not enough custom data: need %u, have %u", custom_data_size,
                        custom_length - custom_pos);
                break;
            }
        }

        /* Move to next action */
        action_pos += header_size;
        total_size += header_size + custom_data_size;
    }

    /* Add terminator byte */
    if (serialize_pos < SAM_LOG_SERIALIZE_BUF_SIZE) {
        serialize_buf[serialize_pos++] = 0xFF;
        total_size++;
    }

    /* Calculate minimum encoding size (which must be multiple of 4) */
    size_t pad_bytes = (4 - (total_size % 4)) % 4; /* Calculate padding needed */
    size_t encoding_size = total_size + pad_bytes;

    /* Ensure we don't exceed buffer size */
    if (encoding_size > SAM_LOG_SERIALIZE_BUF_SIZE) {
        encoding_size = SAM_LOG_SERIALIZE_BUF_SIZE;
    }

    /* Encode exact number of bytes needed */
    encoded_len = Z85_encode_with_padding((char *)serialize_buf, encoded, encoding_size);
    if (encoded_len > 0) {
        LOG_INF("LOG[%s] %s %u %s", log_name, buffer_name, epoch_id, encoded);
    }

    /* Free the claimed data */
    ring_buf_get_finish(action_buf, action_length);
    ring_buf_get_finish(custom_buf, custom_length);

    return encoded_len;
}

/* Function to flush logs and encode them */
int sam_log_flush(char *log_name, uint32_t epoch_id, size_t *bytes_written) {
    size_t encoded_len = 0;
    struct sam_log_stats current_stats = log_ctx.stats;

    if (!log_name) {
        return -EINVAL;
    }

    /* Reset output if bytes_written is provided */
    if (bytes_written) {
        *bytes_written = 0;
    }

    /* Process START buffer */
    encoded_len = process_and_encode_buffer(&log_ctx.start_actions, &log_ctx.start_custom, log_name,
                                            epoch_id, "START");
    if (bytes_written && encoded_len > 0) {
        *bytes_written += encoded_len;
    }

    /* Process END buffer */
    encoded_len = process_and_encode_buffer(&log_ctx.end_actions, &log_ctx.end_custom, log_name,
                                            epoch_id, "END");
    if (bytes_written && encoded_len > 0) {
        *bytes_written += encoded_len;
    }

    /* Log statistics before resetting */
    LOG_DBG("Logging stats: %u actions logged, %u dropped; %u custom fields logged, %u dropped",
            current_stats.actions_logged, current_stats.actions_dropped,
            current_stats.custom_fields_logged, current_stats.custom_fields_dropped);

    /* Reset statistics */
    memset(&log_ctx.stats, 0, sizeof(struct sam_log_stats));

    return 0;
}