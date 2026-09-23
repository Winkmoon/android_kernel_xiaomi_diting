// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024 MediaTek Inc.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/bitops.h>
#include <linux/freezer.h>
#include <linux/kernel.h>
#include <linux/psi.h>
#include <linux/kfifo.h>
#include <linux/swap.h>
#include <linux/delay.h>
#include "kcompressd.h"

#define INIT_QUEUE_SIZE		4096
#define DEFAULT_NR_KCOMPRESSD	1

static atomic_t enable_kcompressd;
static unsigned int nr_kcompressd;
static unsigned int queue_size_per_kcompressd;
static struct kcompress *kcompress;

struct write_work {
	void *zram;
	struct bio *bio;
	compress_callback cb;
};

enum run_state {
	KCOMPRESSD_NOT_STARTED = 0,
	KCOMPRESSD_RUNNING,
	KCOMPRESSD_SLEEPING,
};

struct kcompressd_para {
	wait_queue_head_t *kcompressd_wait;
	struct kfifo *write_fifo;
	atomic_t *running;
};

static struct kcompressd_para *kcompressd_para;

int kcompressd_enabled(void)
{
	return likely(atomic_read(&enable_kcompressd));
}
EXPORT_SYMBOL(kcompressd_enabled);

static void kcompressd_try_to_sleep(struct kcompressd_para *p)
{
	DEFINE_WAIT(wait);

	if (!kfifo_is_empty(p->write_fifo))
		return;

	if (freezing(current) || kthread_should_stop())
		return;

	atomic_set(p->running, KCOMPRESSD_SLEEPING);
	prepare_to_wait(p->kcompressd_wait, &wait, TASK_INTERRUPTIBLE);

	/**
	 * After a short sleep, check if it was a premature sleep.
	 * If not, then go fully to sleep until explicitly woken up.
	 */
	if (!kthread_should_stop() && kfifo_is_empty(p->write_fifo))
		schedule();

	finish_wait(p->kcompressd_wait, &wait);
	atomic_set(p->running, KCOMPRESSD_RUNNING);
}

static int kcompressd(void *para)
{
	struct task_struct *tsk = current;
	struct kcompressd_para *p = (struct kcompressd_para *)para;

	tsk->flags |= PF_MEMALLOC | PF_KSWAPD;
	set_freezable();

	while (!kthread_should_stop()) {
		bool ret;

		kcompressd_try_to_sleep(p);
		ret = try_to_freeze();
		if (kthread_should_stop())
			break;

		if (ret)
			continue;

		while (!kfifo_is_empty(p->write_fifo)) {
			struct write_work entry;

			if (sizeof(struct write_work) == kfifo_out(p->write_fifo,
						&entry, sizeof(struct write_work))) {
				entry.cb(entry.zram, entry.bio);
				bio_put(entry.bio);
			}
		}
		usleep_range(1000, 2000);
	}

	tsk->flags &= ~(PF_MEMALLOC | PF_KSWAPD);
	atomic_set(p->running, KCOMPRESSD_NOT_STARTED);
	return 0;
}

static int init_write_queue(void)
{
	int i;
	unsigned int queue_len = queue_size_per_kcompressd * sizeof(struct write_work);

	for (i = 0; i < nr_kcompressd; i++) {
		if (kfifo_alloc(&kcompress[i].write_fifo,
					queue_len, GFP_KERNEL)) {
			pr_err("Failed to alloc Kcompressed kfifo %d\n", i);
			return -ENOMEM;
		}
	}
	return 0;
}

static void clean_bio_queue(int idx)
{
	struct write_work entry;

	while (sizeof(struct write_work) == kfifo_out(&kcompress[idx].write_fifo,
				&entry, sizeof(struct write_work))) {
		bio_put(entry.bio);
		entry.cb(entry.zram, entry.bio);
	}
	kfifo_free(&kcompress[idx].write_fifo);
}

static int kcompress_update(void)
{
	int i, ret;

	kcompress = kvcalloc(nr_kcompressd, sizeof(struct kcompress), GFP_KERNEL);
	if (!kcompress)
		return -ENOMEM;

	kcompressd_para = kvcalloc(nr_kcompressd, sizeof(struct kcompressd_para), GFP_KERNEL);
	if (!kcompressd_para) {
		kvfree(kcompress);
		return -ENOMEM;
	}

	ret = init_write_queue();
	if (ret) {
		kvfree(kcompressd_para);
		kvfree(kcompress);
		return ret;
	}

	for (i = 0; i < nr_kcompressd; i++) {
		init_waitqueue_head(&kcompress[i].kcompressd_wait);
		spin_lock_init(&kcompress[i].write_fifo_lock);
		kcompressd_para[i].kcompressd_wait = &kcompress[i].kcompressd_wait;
		kcompressd_para[i].write_fifo = &kcompress[i].write_fifo;
		kcompressd_para[i].running = &kcompress[i].running;
	}

	return 0;
}

static void stop_all_kcompressd_thread(void)
{
	int i;

	for (i = 0; i < nr_kcompressd; i++) {
		kthread_stop(kcompress[i].kcompressd);
		kcompress[i].kcompressd = NULL;
		clean_bio_queue(i);
	}
}

int schedule_bio_write(void *zram, struct bio *bio, compress_callback cb)
{
	int i;
	bool submit_success = false;
	size_t sz_work = sizeof(struct write_work);

	struct write_work entry = {
		.bio = bio,
		.zram = zram,
		.cb = cb
	};

	if (unlikely(!atomic_read(&enable_kcompressd)))
		return -EBUSY;

	if (!nr_kcompressd || !current_is_kswapd())
		return -EBUSY;

	bio_get(bio);
	if (op_is_sync(bio->bi_opf)) {
		bio_put(bio);
		pr_warn("kcompressd: request should not be sync, bio->bi_opf: %d\n", bio->bi_opf);
		return -EBUSY;
	}

	for (i = 0; i < nr_kcompressd; i++) {
		submit_success =
			(kfifo_avail(&kcompress[i].write_fifo) >= sz_work) &&
			(sz_work == kfifo_in_spinlocked_noirqsave(&kcompress[i].write_fifo, &entry, sz_work, &kcompress[i].write_fifo_lock));

		if (submit_success) {
			switch (atomic_read(&kcompress[i].running)) {
			case KCOMPRESSD_NOT_STARTED:
				atomic_set(&kcompress[i].running, KCOMPRESSD_RUNNING);
				kcompress[i].kcompressd = kthread_run(kcompressd,
						&kcompressd_para[i], "kcompressd:%d", i);
				if (IS_ERR(kcompress[i].kcompressd)) {
					atomic_set(&kcompress[i].running, KCOMPRESSD_NOT_STARTED);
					pr_warn("Failed to start kcompressd:%d\n", i);
					clean_bio_queue(i);
				}
				break;
			case KCOMPRESSD_RUNNING:
				break;
			case KCOMPRESSD_SLEEPING:
				wake_up_interruptible(&kcompress[i].kcompressd_wait);
				break;
			default:
				break;
			}
			return 0;
		}
	}

	bio_put(bio);
	return -EBUSY;
}
EXPORT_SYMBOL(schedule_bio_write);

int kcompressd_init(void)
{
	int i, ret = 0;

	nr_kcompressd = DEFAULT_NR_KCOMPRESSD;
	queue_size_per_kcompressd = INIT_QUEUE_SIZE;

	ret = kcompress_update();
	if (ret) {
		pr_err("kcompressd: create kernel thread failed!\n");
		return ret;
	}

	for (i = 0; i < nr_kcompressd; i++) {
		atomic_set(&kcompress[i].running, KCOMPRESSD_RUNNING);
		kcompress[i].kcompressd = kthread_run(kcompressd,
				&kcompressd_para[i], "kcompressd:%d", i);
		if (IS_ERR(kcompress[i].kcompressd)) {
			atomic_set(&kcompress[i].running, KCOMPRESSD_NOT_STARTED);
			pr_err("Failed to start kcompressd:%d\n", i);
			goto out;
		}
	}

	pr_info("create kcompressd thread succee\n");
	atomic_set(&enable_kcompressd, true);
out:
	return ret;
}

void kcompressd_exit(void)
{
	if (!kcompressd_enabled())
		return;

	atomic_set(&enable_kcompressd, false);
	stop_all_kcompressd_thread();

	kvfree(kcompress);
	kvfree(kcompressd_para);
}
