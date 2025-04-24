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

/* Structure representing a serialized action */
struct sam_log_packed_action {
    uint8_t m_hdr : 1;         /* 1 if extended header is present */
    uint8_t status : 5;        /* Action result status */
    uint8_t reserved : 2;      /* Unused, for alignment */
    uint16_t custom_status;    /* Custom status for custom actions */
    uint8_t hdr;               /* Standard header bitmask */
    uint32_t slot_idx : 24;    /* Slot index for the action */
    int16_t slot_idx_diff;     /* Difference from expected slot */
    uint8_t slots_to_use;      /* Number of slots used by the action */
    uint16_t total_custom_len; /* Total length of custom fields */
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

    /* If status is SAM_LOG_UNKNOWN, write custom_status */
    if (action->status == SAM_LOG_UNKNOWN) {
        if (pos + 2 > bufsize) {
            return 0;
        }
        buf[pos++] = (action->custom_status >> 8) & 0xFF;
        buf[pos++] = action->custom_status & 0xFF;
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
        action.custom_status = custom_status;
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

/* Function to flush logs and encode them */
int sam_log_flush(char *log_name, uint32_t epoch_id, size_t *bytes_written) {
    uint8_t *action_data, *custom_data;
    uint32_t action_length, custom_length;
    char encoded[SAM_LOG_SERIALIZE_BUF_SIZE * 5 / 4 + 10]; /* Z85 encoding overhead + padding */
    size_t encoded_len;
    size_t serialize_pos = 0;

    if (!log_name) {
        return -EINVAL;
    }

    /* Reset output if bytes_written is provided */
    if (bytes_written) {
        *bytes_written = 0;
    }

    /* Process START buffer */
    action_length = ring_buf_get_claim(&log_ctx.start_actions, &action_data, UINT32_MAX);
    if (action_length > 0) {
        /* Copy actions to serialize buffer */
        memset(serialize_buf, 0, sizeof(serialize_buf));
        if (action_length > sizeof(serialize_buf)) {
            action_length = sizeof(serialize_buf);
        }
        memcpy(serialize_buf, action_data, action_length);
        serialize_pos = action_length;

        /* Get and append custom data */
        custom_length = ring_buf_get_claim(&log_ctx.start_custom, &custom_data, UINT32_MAX);
        if (custom_length > 0) {
            if (serialize_pos + custom_length <= sizeof(serialize_buf)) {
                memcpy(serialize_buf + serialize_pos, custom_data, custom_length);
                serialize_pos += custom_length;
                ring_buf_get_finish(&log_ctx.start_custom, custom_length);
            } else {
                LOG_WRN("Custom data buffer too large for serialize buffer");
                ring_buf_get_finish(&log_ctx.start_custom, custom_length);
            }
        }

        /* Encode using Z85 */
        encoded_len = Z85_encode_with_padding((char *)serialize_buf, encoded, serialize_pos);
        if (encoded_len > 0) {
            /* Print the log */
            LOG_INF("LOG[%s] START %u %s", log_name, epoch_id, encoded);
            if (bytes_written) {
                *bytes_written += encoded_len;
            }
        }

        /* Free the claimed action data */
        ring_buf_get_finish(&log_ctx.start_actions, action_length);
    }

    /* Process END buffer */
    serialize_pos = 0;

    action_length = ring_buf_get_claim(&log_ctx.end_actions, &action_data, UINT32_MAX);
    if (action_length > 0) {
        /* Copy actions to serialize buffer */
        memset(serialize_buf, 0, sizeof(serialize_buf));
        if (action_length > sizeof(serialize_buf)) {
            action_length = sizeof(serialize_buf);
        }
        memcpy(serialize_buf, action_data, action_length);
        serialize_pos = action_length;

        /* Get and append custom data */
        custom_length = ring_buf_get_claim(&log_ctx.end_custom, &custom_data, UINT32_MAX);
        if (custom_length > 0) {
            if (serialize_pos + custom_length <= sizeof(serialize_buf)) {
                memcpy(serialize_buf + serialize_pos, custom_data, custom_length);
                serialize_pos += custom_length;
                ring_buf_get_finish(&log_ctx.end_custom, custom_length);
            } else {
                LOG_WRN("Custom data buffer too large for serialize buffer");
                ring_buf_get_finish(&log_ctx.end_custom, custom_length);
            }
        }

        /* Encode using Z85 */
        encoded_len = Z85_encode_with_padding((char *)serialize_buf, encoded, serialize_pos);
        if (encoded_len > 0) {
            /* Print the log */
            LOG_INF("LOG[%s] END %u %s", log_name, epoch_id, encoded);
            if (bytes_written) {
                *bytes_written += encoded_len;
            }
        }

        /* Free the claimed action data */
        ring_buf_get_finish(&log_ctx.end_actions, action_length);
    }

    /* Reset statistics */
    memset(&log_ctx.stats, 0, sizeof(struct sam_log_stats));

    return 0;
}