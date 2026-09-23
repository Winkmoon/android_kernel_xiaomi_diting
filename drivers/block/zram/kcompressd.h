/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024 MediaTek Inc.
 */

#ifndef _KCOMPRESSD_H_
#define _KCOMPRESSD_H_

#include <linux/rwsem.h>
#include <linux/kfifo.h>
#include <linux/atomic.h>
#include <linux/cpu.h>

typedef void (*compress_callback)(void *func, struct bio *bio);
int schedule_bio_write(void *zram, struct bio *bio, compress_callback cb);

struct kcompress {
	struct task_struct *kcompressd;
	wait_queue_head_t kcompressd_wait;
	struct kfifo write_fifo;
	spinlock_t write_fifo_lock;
	atomic_t running;
};

int kcompressd_enabled(void);
int kcompressd_init(void);
void kcompressd_exit(void);
#endif
