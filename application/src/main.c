
#include <stdlib.h>
#include <zephyr/kernel.h>
#include "zephyr/toolchain/gcc.h"
#include <zephyr/sys/printk.h>

#include "sam.h"

/*--------------------------------------------------------------------------*/
/* LOGGING */
/*--------------------------------------------------------------------------*/

#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>
LOG_MODULE_REGISTER(main, CONFIG_LOG_DEFAULT_LEVEL);

/*--------------------------------------------------------------------------*/
/* THREADS */
/*--------------------------------------------------------------------------*/

struct k_thread initiator_thread_data;
#define INITIATOR_STACK_SIZE 2048
#define INITIATOR_PRIORITY 5
K_THREAD_STACK_DEFINE(initiator_stack_area, INITIATOR_STACK_SIZE);
struct k_thread initiator_thread_data;
/*--------------------------------------------------------------------------*/
void initiator_thread()
{
	LOG_DBG("Initiator thread start.");
	
	/* Data to send */
	char msg[] = "sample_msg\0";

	/* Set TX parameters */
	tx_sched_args_t tx_sched_args;
	tx_sched_args.tx_buf = msg;
	tx_sched_args.tx_len = sizeof(msg);
	tx_wait_args_t tx_wait_args;

	/* Slot skipping */
	int slots_to_skip = 50000;
	bool flag_slots_to_skip = true;

	/* Set the restart parameters */
	restart_args_t restart_args;
	restart_args.epoch_duration_ms = 3000;
	restart_args.min_synch_epochs = 0;
	restart_args.tref_guard_time_us = 2000;
	restart_args.wakeup_guard_time_us = 10000; // 10ms
	bool flag_restart = true;

	/* TX loop */
	while (1)
	{
		LOG_DBG("Schedule TX.");
		sam.tx_sched(tx_sched_args, NULL);
		LOG_DBG("Wait TX done...");
		sam.tx_wait(tx_wait_args, NULL);
		LOG_DBG("TX done.");
		if(flag_slots_to_skip) sam.skip_slots(slots_to_skip);
		if(flag_restart) {
			sam_result_t res = sam.restart(restart_args);
			if(res != RESTART_SUCCESS) {
				LOG_DBG("No restart.");
			}
		}
	}
}
/*--------------------------------------------------------------------------*/
uint8_t rx_buf[SAM_FRAME_LEN]; // Buffer to store the received frame
struct k_thread receiver_thread_data;
#define RECEIVER_STACK_SIZE 2048
#define RECEIVER_PRIORITY 5
K_THREAD_STACK_DEFINE(receiver_stack_area, RECEIVER_STACK_SIZE);
struct k_thread receiver_thread_data;
/*--------------------------------------------------------------------------*/
void receiver_thread()
{
	/* Set the RX listen parameters */
	rx_listen_args_t rx_listen_args;
	rx_listen_args.rx_timeout_us = 0; // SCAN
	rx_listen_args.rx_guard_us = 500;

	/* Set the RX wait parameters */
	rx_wait_args_t rx_wait_args;
	rx_wait_args.rx_buf = rx_buf;
	rx_wait_args.rx_len = sizeof(rx_buf);

	/* Slot skipping */
	int slots_to_skip = 50000;
	bool flag_slots_to_skip = true;

	/* Set the restart parameters */
	restart_args_t restart_args;
	restart_args.epoch_duration_ms = 3000;
	restart_args.min_synch_epochs = 3;
	restart_args.tref_guard_time_us = 2000;
	restart_args.wakeup_guard_time_us = 10000; // 10ms
	bool flag_restart = true;

	/* Operation outcome */
	sam_result_t res;

	/* RX loop */
	while (1)
	{
		/* Start RX*/
		LOG_DBG("Schedule RX.");
		res = sam.rx_listen(rx_listen_args, NULL);
		if(res == RX_LISTEN_SUCCESS) {

			/* If we could schedule, wait for RX done */
			LOG_DBG("Wait RX done...");
			res = sam.rx_wait(rx_wait_args, NULL);
		}
		else {

			/* If we couldn't schedule, skip 1 slot
			 * (should give us enough time if we were late)
			 * and try again */
			LOG_DBG("RX sched fail. Skipping...");
			sam.skip_slots(slots_to_skip);
			continue;
		}
		LOG_DBG("RX done.");

		/* Synchronize to the received frame;
		 * from now on, use the RX timeout */
		if(res == RX_SUCCESS) {
			sam.synch(NULL);
			rx_listen_args.rx_timeout_us = 1500;
		}
		else {

			/* If RX failed, we may be desynchronized;
			 * set scan-like endless listening for the next attempt */
			LOG_DBG("Will use SCAN-like RX.");
			rx_listen_args.rx_timeout_us = 0;
			continue;
		}

		/* Jump to the next RX action (optional skip and restart) */
		if(flag_slots_to_skip) sam.skip_slots(slots_to_skip);
		if(flag_restart) {
			res = sam.restart(restart_args);
			if(res != RESTART_SUCCESS) {
				LOG_DBG("No restart.");
			}
		}
	}
}

/*--------------------------------------------------------------------------*/
/* MAIN */
/*--------------------------------------------------------------------------*/

static union {
	uint64_t raw;
	uint8_t bytes[8];
} ieee_addr;
/*--------------------------------------------------------------------------*/
void main()
{
    LOG_INIT();

    /* Initialize the radio */
	if(sam_init() != INIT_OK) {
		LOG_ERR("Failed sam initialization");
		while (1) k_sleep(K_MSEC(1000));
	}
    LOG_INF("Initializing...");
	struct k_timer init_wait;
	k_timer_init(&init_wait, NULL, NULL);
	k_timer_start(&init_wait, K_SECONDS(5), K_NO_WAIT);
	LOG_INF("Initialization done.");

	/* Extract the Link Layer addresses depending on the PART and LOT IDs */
	uint32_t lot_id = dwt_getlotid();
	uint32_t part_id = dwt_getpartid();
	LOG_INF("LotId %u", lot_id);
	LOG_INF("PartId %u", part_id);
	ieee_addr.bytes[0] = (lot_id  & 0xFF000000) >> 24;
	ieee_addr.bytes[1] = (lot_id  & 0x00FF0000) >> 16;
	ieee_addr.bytes[2] = (lot_id  & 0x0000FF00) >> 8;
	ieee_addr.bytes[3] = (lot_id  & 0x000000FF);
	ieee_addr.bytes[4] = (part_id & 0xFF000000) >> 24;
	ieee_addr.bytes[5] = (part_id & 0x00FF0000) >> 16;
	ieee_addr.bytes[6] = (part_id & 0x0000FF00) >> 8;
	ieee_addr.bytes[7] = (part_id & 0x000000FF);
	uint16_t short_addr = (ieee_addr.bytes[6] << 8) | ieee_addr.bytes[7];

	/* Identify the device */
	LOG_INF("Address is %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		ieee_addr.bytes[0], ieee_addr.bytes[1], ieee_addr.bytes[2], ieee_addr.bytes[3],
		ieee_addr.bytes[4], ieee_addr.bytes[5], ieee_addr.bytes[6], ieee_addr.bytes[7]);
	LOG_INF("Short is %02x:%02x (%d)",
		short_addr >> 8, short_addr & 0xff, short_addr);

	/* Start the appropriate thread */
	if (0X8DA7 == short_addr || 0X4636 == short_addr) { // c2:21 is node 74, 46:36 is node 52, 8da7 is a tabletop node
		LOG_INF("Creating initiator_thread...");
		k_tid_t initiator_tid = k_thread_create(&initiator_thread_data, initiator_stack_area,
                                    K_THREAD_STACK_SIZEOF(initiator_stack_area),
                                    initiator_thread,
                                    NULL, NULL, NULL,
                                    INITIATOR_PRIORITY, 0, K_NO_WAIT);
		
		k_thread_join(initiator_tid, K_FOREVER);
	}
	else {
		LOG_INF("Creating receiver_thread...\n");
		k_tid_t receiver_tid = k_thread_create(&receiver_thread_data, receiver_stack_area,
                                    K_THREAD_STACK_SIZEOF(receiver_stack_area),
                                    receiver_thread,
                                    NULL, NULL, NULL,
                                    RECEIVER_PRIORITY, 0, K_NO_WAIT);
		k_thread_join(receiver_tid, K_FOREVER);
	}
    
	while(1) k_sleep(K_MSEC(1000));
}

/*--------------------------------------------------------------------------*/
