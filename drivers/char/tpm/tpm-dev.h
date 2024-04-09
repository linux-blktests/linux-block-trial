/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TPM_DEV_H
#define _TPM_DEV_H

#include <linux/poll.h>
#include "tpm.h"

struct file_priv {
	struct tpm_chip *chip;
	struct tpm_space *space;

	struct mutex buffer_mutex;
	struct timer_list user_read_timer;      /* user needs to claim result */
	struct work_struct timeout_work;
	struct work_struct async_work;
	wait_queue_head_t async_wait;
	ssize_t response_length;
	bool response_read;
	bool command_enqueued;

	u8 data_buffer[TPM_BUFSIZE];
};

void tpm_common_open(struct file *file, struct tpm_chip *chip,
		     struct file_priv *priv, struct tpm_space *space);
ssize_t tpm_common_read_iter(struct kiocb *iocb, struct iov_iter *to);
ssize_t tpm_common_write(struct kiocb *iocb, struct iov_iter *from);
__poll_t tpm_common_poll(struct file *file, poll_table *wait);

void tpm_common_release(struct file *file, struct file_priv *priv);
#endif
