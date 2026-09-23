/*
 * Compressed RAM block device
 *
 * Copyright (C) 2008, 2009, 2010  Nitin Gupta
 *               2012, 2013 Minchan Kim
 *
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the licence that better fits your requirements.
 *
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 *
 */

#define KMSG_COMPONENT "ExtM"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#if defined(CONFIG_ZRAM_WRITEBACK)
enum anon_writeback_flags {
	ANON_WRITEBACK_NORMAL= 0,
	ANON_WRITEBACK_PROTECTED,
#if defined(CONFIG_MI_MEMORY_FREEZE)
	ANON_WRITEBACK_UNLIMITED,
#endif
	__NR_ANON_WRITEBACK_FLAGS,
};
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/device.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/err.h>
#include <linux/idr.h>
#include <linux/sysfs.h>
#include <linux/debugfs.h>
#include <linux/cpuhotplug.h>
#include <linux/part_stat.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/memcontrol.h>
#include <linux/vmstat.h>

#include "zram_drv.h"
#ifdef CONFIG_ZRAM_KCOMPRESSD_OPT
#include "kcompressd.h"
#endif
#include "internal.h"

static DEFINE_IDR(zram_index_idr);
/* idr index must be protected */
static DEFINE_MUTEX(zram_index_mutex);

static int zram_major;
static const char *default_compressor = CONFIG_ZRAM_DEF_COMP;

/* Module params (documentation at end) */
static unsigned int num_devices = 1;
/*
 * Pages that compress to sizes equals or greater than this are stored
 * uncompressed in memory.
 */
static size_t huge_class_size;

static const struct block_device_operations zram_devops;
#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
#define TIME_DIFF_MS   200U
/* default_time_list for page life statics and the unit is seconds */
static  int default_time_list[] = {60, 120, 180, 300, 600};
#endif
static unsigned int glow_compress_ratio = 75;
#ifdef CONFIG_ZRAM_KSHRINK_SLABD
extern void zram_kshrink_slabd_init(void);
extern void zram_kshrink_slabd_exit(void);
#endif
static void zram_free_page(struct zram *zram, size_t index);
static int zram_read_page(struct zram *zram, struct page *page, u32 index,
			  struct bio *parent);
#ifdef CONFIG_ZRAM_KCOMPRESSD_OPT
static void zram_bio_write(struct zram *zram, struct bio *bio);
static void zram_bio_write_engine(void *func, struct bio *bio)
{
	struct zram *zram = (struct zram *)func;
	zram_bio_write(zram, bio);
}
#endif

#ifdef CONFIG_ZRAM_WRITEBACK
#define list_length(head) ({ \
    struct list_head *_head = (head); \
    int _count = 0; \
    struct list_head *_node; \
    list_for_each(_node, _head) \
        _count++; \
    _count; \
})
#endif

static int zram_slot_trylock(struct zram *zram, u32 index)
{
	return bit_spin_trylock(ZRAM_LOCK, &zram->table[index].flags);
}

static void zram_slot_lock(struct zram *zram, u32 index)
{
	bit_spin_lock(ZRAM_LOCK, &zram->table[index].flags);
}

static void zram_slot_unlock(struct zram *zram, u32 index)
{
	bit_spin_unlock(ZRAM_LOCK, &zram->table[index].flags);
}

static inline bool init_done(struct zram *zram)
{
	return zram->disksize;
}

static inline struct zram *dev_to_zram(struct device *dev)
{
	return (struct zram *)dev_to_disk(dev)->private_data;
}

static unsigned long zram_get_handle(struct zram *zram, u32 index)
{
	return zram->table[index].handle;
}

static void zram_set_handle(struct zram *zram, u32 index, unsigned long handle)
{
	zram->table[index].handle = handle;
}

static inline unsigned long zram_get_idle_count(struct zram *zram, u32 index)
{
	return zram->table[index].flags >> ZRAM_WB_IDLE_SHIFT;
}

static inline void zram_clear_idle_count(struct zram *zram, u32 index)
{

#ifdef CONFIG_ZRAM_WRITEBACK
	unsigned long count_index;
	// zram_clear_idle_count，对应的idle_count的页面数量-1.
	count_index = zram_get_idle_count(zram, index);
	if (count_index > 0) {
		WARN_ON(atomic64_read(&zram->stats.total_idle_count[count_index-1]) <= 0);
		atomic64_dec(&zram->stats.total_idle_count[count_index-1]);
	}
#endif

	zram->table[index].flags &= (BIT(ZRAM_WB_IDLE_SHIFT) - 1);
}

static inline void zram_set_idle_count(struct zram *zram, u32 index,
				       unsigned long idle_count)
{
	zram_clear_idle_count(zram, index);

	zram->table[index].flags |= (idle_count << ZRAM_WB_IDLE_SHIFT);
}

static inline void zram_inc_idle_count(struct zram *zram, u32 index)
{
	unsigned long idle_count = zram_get_idle_count(zram, index);

	// 标记idle_count次数小于10次的页面
	if (idle_count < ZRAM_WB_IDLE_MAX) {
		zram_set_idle_count(zram, index, idle_count + 1);
#ifdef CONFIG_ZRAM_WRITEBACK
		atomic64_inc(&zram->stats.total_idle_count[idle_count]);
#endif
        }
}

/* flag operations require table entry bit_spin_lock() being held */
static bool zram_test_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
	return zram->table[index].flags & BIT(flag);
}

static void zram_set_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
	zram->table[index].flags |= BIT(flag);
}

static void zram_clear_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
	zram->table[index].flags &= ~BIT(flag);
}

static inline void zram_set_element(struct zram *zram, u32 index,
			unsigned long element)
{
	zram->table[index].element = element;
}

static unsigned long zram_get_element(struct zram *zram, u32 index)
{
	return zram->table[index].element;
}

static size_t zram_get_obj_size(struct zram *zram, u32 index)
{
	return zram->table[index].flags & (BIT(ZRAM_FLAG_SHIFT) - 1);
}

static void zram_set_obj_size(struct zram *zram,
					u32 index, size_t size)
{
	unsigned long flags = zram->table[index].flags >> ZRAM_FLAG_SHIFT;

	zram->table[index].flags = (flags << ZRAM_FLAG_SHIFT) | size;
}

static inline bool zram_allocated(struct zram *zram, u32 index)
{
	return zram_get_obj_size(zram, index) ||
			zram_test_flag(zram, index, ZRAM_SAME) ||
			zram_test_flag(zram, index, ZRAM_WB);
}

#if PAGE_SIZE != 4096
static inline bool is_partial_io(struct bio_vec *bvec)
{
	return bvec->bv_len != PAGE_SIZE;
}
#define ZRAM_PARTIAL_IO		1
#else
static inline bool is_partial_io(struct bio_vec *bvec)
{
	return false;
}
#endif

static inline void zram_set_priority(struct zram *zram, u32 index, u32 prio)
{
	prio &= ZRAM_COMP_PRIORITY_MASK;
	/*
	 * Clear previous priority value first, in case if we recompress
	 * further an already recompressed page
	 */
	zram->table[index].flags &= ~(ZRAM_COMP_PRIORITY_MASK <<
				      ZRAM_COMP_PRIORITY_BIT1);
	zram->table[index].flags |= (prio << ZRAM_COMP_PRIORITY_BIT1);
}

static inline u32 zram_get_priority(struct zram *zram, u32 index)
{
	u32 prio = zram->table[index].flags >> ZRAM_COMP_PRIORITY_BIT1;

	return prio & ZRAM_COMP_PRIORITY_MASK;
}
#ifdef CONFIG_ZRAM_WRITEBACK
struct zram_pp_slot {
	unsigned long		index;
	struct list_head	entry;
};

#define NUM_PP_BUCKETS		17

struct zram_pp_ctl {
	struct list_head	pp_buckets[NUM_PP_BUCKETS];
};

static struct zram_pp_ctl *init_pp_ctl(void)
{
	struct zram_pp_ctl *ctl;
	u32 idx;

	ctl = kmalloc(sizeof(*ctl), GFP_KERNEL);
	if (!ctl)
		return NULL;

	for (idx = 0; idx < NUM_PP_BUCKETS; idx++)
		INIT_LIST_HEAD(&ctl->pp_buckets[idx]);

	return ctl;
}

static void release_pp_slot(struct zram *zram, struct zram_pp_slot *pps)
{
	zram_slot_lock(zram, pps->index);
	if (zram_test_flag(zram, pps->index, ZRAM_PP_SLOT))
		zram_clear_flag(zram, pps->index, ZRAM_PP_SLOT);
	zram_slot_unlock(zram, pps->index);
	kfree(pps);
}

static void release_pp_ctl(struct zram *zram, struct zram_pp_ctl *ctl)
{
	u32 idx;

	if (!ctl)
		return;

	for (idx = 0; idx < NUM_PP_BUCKETS; idx++) {
		while (!list_empty(&ctl->pp_buckets[idx])) {
			struct zram_pp_slot *pps;

			pps = list_first_entry(&ctl->pp_buckets[idx],
					       struct zram_pp_slot,
					       entry);
			list_del_init(&pps->entry);
			release_pp_slot(zram, pps);
		}
	}

	kfree(ctl);
}

static void place_pp_slot(struct zram *zram, struct zram_pp_ctl *ctl,
			  struct zram_pp_slot *pps)
{
	s32 diff, idx;

	/*
	 * On 4K system this keeps PP slot groups 256 bytes apart. The
	 * higher the group IDX the larger the slot size.
	 */
	diff = PAGE_SIZE / (NUM_PP_BUCKETS - 1);
	idx = zram_get_obj_size(zram, pps->index) / diff;
	list_add(&pps->entry, &ctl->pp_buckets[idx]);

	zram_set_flag(zram, pps->index, ZRAM_PP_SLOT);
}

static struct zram_pp_slot *select_pp_slot(struct zram_pp_ctl *ctl)
{
	struct zram_pp_slot *pps = NULL;
	s32 idx = NUM_PP_BUCKETS - 1;

	/*
	 * Select PP-slots starting from the highest group, which should
	 * give us the best candidate for writeback.
	 */
	while (idx > 0) {
		pps = list_first_entry_or_null(&ctl->pp_buckets[idx],
					       struct zram_pp_slot,
					       entry);
		if (pps) {
			list_del_init(&pps->entry);
			break;
		}

		idx--;
	}
	return pps;
}
#endif

static inline void update_used_max(struct zram *zram,
					const unsigned long pages)
{
	unsigned long cur_max = atomic_long_read(&zram->stats.max_used_pages);

	do {
		if (cur_max >= pages)
			return;
	} while (!atomic_long_try_cmpxchg(&zram->stats.max_used_pages,
					  &cur_max, pages));
}

static inline void zram_fill_page(void *ptr, unsigned long len,
					unsigned long value)
{
	WARN_ON_ONCE(!IS_ALIGNED(len, sizeof(unsigned long)));
	memset_l(ptr, value, len / sizeof(unsigned long));
}

static bool page_same_filled(void *ptr, unsigned long *element)
{
	unsigned long *page;
	unsigned long val;
	unsigned int pos, last_pos = PAGE_SIZE / sizeof(*page) - 1;

	page = (unsigned long *)ptr;
	val = page[0];

	if (val != page[last_pos])
		return false;

	for (pos = 1; pos < last_pos; pos++) {
		if (val != page[pos])
			return false;
	}

	*element = val;

	return true;
}

static ssize_t initstate_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u32 val;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	val = init_done(zram);
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t disksize_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", zram->disksize);
}

static ssize_t mem_limit_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	u64 limit;
	char *tmp;
	struct zram *zram = dev_to_zram(dev);

	limit = memparse(buf, &tmp);
	if (buf == tmp) /* no chars parsed, invalid input */
		return -EINVAL;

	down_write(&zram->init_lock);
	zram->limit_pages = PAGE_ALIGN(limit) >> PAGE_SHIFT;
	up_write(&zram->init_lock);

	return len;
}

static ssize_t mem_used_max_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	int err;
	unsigned long val;
	struct zram *zram = dev_to_zram(dev);

	err = kstrtoul(buf, 10, &val);
	if (err || val != 0)
		return -EINVAL;

	down_read(&zram->init_lock);
	if (init_done(zram)) {
		atomic_long_set(&zram->stats.max_used_pages,
				zs_get_total_pages(zram->mem_pool));
	}
	up_read(&zram->init_lock);

	return len;
}

/*
 * Mark all pages which are older than or equal to cutoff as IDLE.
 * Callers should hold the zram init lock in read mode
 */
static void mark_idle(struct zram *zram)
{
	unsigned long nr_pages = zram->disksize >> PAGE_SHIFT;
	int index, mark_nr = 0;

	for (index = 0; index < nr_pages; index++) {
		/*
		 * Do not mark ZRAM_UNDER_WB slot as ZRAM_IDLE to close race.
		 * See the comment in writeback_store.
		 */
		zram_slot_lock(zram, index);
		if (zram_get_obj_size(zram, index) &&
					zram_test_flag(zram, index, ZRAM_COMPRESS_LOW) &&
					!zram_test_flag(zram, index, ZRAM_UNDER_WB) &&
#if defined(CONFIG_ZRAM_WRITEBACK)
					!zram_test_flag(zram, index, ZRAM_WRITEBACK_PROTECTED) &&
#endif
					!zram_test_flag(zram, index, ZRAM_WB)) {
				zram_inc_idle_count(zram, index);
				if (!zram_test_flag(zram, index, ZRAM_IDLE)) {
					zram_set_flag(zram, index, ZRAM_IDLE);
					mark_nr++;
				}
		}
		zram_slot_unlock(zram, index);
	}
	pr_info("Mark IDLE finished. Mark %d pages\n", mark_nr);
}

static ssize_t idle_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);

	ssize_t rv = -EINVAL;

	if (!sysfs_streq(buf, "all")) {
		/*
		 * If it did not parse as 'all' try to treat it as an integer
		 * when we have memory tracking enabled.
		 */
		goto out;
	}

	down_read(&zram->init_lock);
	if (!init_done(zram))
		goto out_unlock;

	/*
	 * A cutoff_time of 0 marks everything as idle, this is the
	 * "all" behavior.
	 */
	mark_idle(zram);
	rv = len;

out_unlock:
	up_read(&zram->init_lock);
out:
	return rv;
}

static ssize_t new_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	unsigned long nr_pages = zram->disksize >> PAGE_SHIFT;
	unsigned int index;

	if (!sysfs_streq(buf, "all"))
		return -EINVAL;

	down_read(&zram->init_lock);

	if (!init_done(zram)) {
		up_read(&zram->init_lock);
		return -EINVAL;
	}

	for (index = 0; index < nr_pages; index++) {
		zram_slot_lock(zram, index);
		zram_clear_flag(zram, index, ZRAM_IDLE);
		zram_clear_idle_count(zram, index);
		zram_slot_unlock(zram, index);
	}

	up_read(&zram->init_lock);

	return len;
}

#if defined(CONFIG_ZRAM_WRITEBACK) && defined(CONFIG_MI_MEMORY_FREEZE)
static ssize_t mfz_enable_store(struct device *dev,
				struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	unsigned int val;
	ssize_t ret = -EINVAL;

	if (kstrtouint(buf, 10, &val))
		return ret;

	down_read(&zram->init_lock);
	spin_lock(&zram->wb_limit_lock);
	zram->mfz_enable = !!val;
	spin_unlock(&zram->wb_limit_lock);
	up_read(&zram->init_lock);
	ret = len;

	return ret;
}

static ssize_t mfz_enable_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	return scnprintf(buf, PAGE_SIZE, "%u\n", zram->mfz_enable);
}

static ssize_t mfz_disk_quota_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	char *argbuf, *args, *arg;
	unsigned int val = 0;
	ssize_t ret = -EINVAL;

	args = argbuf = kstrndup(buf, 32, GFP_KERNEL);
	if (!args)
		return ret;

	arg = strsep(&args, " ");

	if (arg) {
		if (kstrtouint(arg, 10, &val))
			goto err;
		if (strsep(&args, " "))
			goto err;
	}

	if (val < 0 || val > zram->nr_pages)
		return ret;

	down_read(&zram->init_lock);
	spin_lock(&zram->wb_limit_lock);
	zram->mfz_disk_quota = val;
	pr_info("mfz_quota: %lu", zram->mfz_disk_quota);
	spin_unlock(&zram->wb_limit_lock);
	up_read(&zram->init_lock);
	ret = len;

err:
	kfree(argbuf);
	return ret;
}

static ssize_t mfz_disk_quota_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	return scnprintf(buf, PAGE_SIZE, "%lu\n", zram->mfz_disk_quota);
}
#endif

#ifdef CONFIG_ZRAM_WRITEBACK
static ssize_t low_compress_ratio_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	unsigned int val;
	ssize_t ret = -EINVAL;

	if (kstrtouint(buf, 10, &val))
		return ret;

	down_read(&zram->init_lock);
	spin_lock(&zram->wb_limit_lock);
	glow_compress_ratio = val;
	spin_unlock(&zram->wb_limit_lock);
	up_read(&zram->init_lock);
	ret = len;

	return ret;
}

static ssize_t low_compress_ratio_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", glow_compress_ratio);
}

static ssize_t writeback_limit_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	u64 val;
	ssize_t ret = -EINVAL;

	if (kstrtoull(buf, 10, &val))
		return ret;

	down_read(&zram->init_lock);
	spin_lock(&zram->wb_limit_lock);
	zram->wb_limit_enable = val;
	spin_unlock(&zram->wb_limit_lock);
	up_read(&zram->init_lock);
	ret = len;

	return ret;
}

static ssize_t writeback_limit_enable_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	bool val;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	spin_lock(&zram->wb_limit_lock);
	val = zram->wb_limit_enable;
	spin_unlock(&zram->wb_limit_lock);
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%d\n", val);
}

static ssize_t writeback_limit_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	u64 val;
	ssize_t ret = -EINVAL;

	if (kstrtoull(buf, 10, &val))
		return ret;

	down_read(&zram->init_lock);
	spin_lock(&zram->wb_limit_lock);
	zram->bd_wb_limit = val;
	spin_unlock(&zram->wb_limit_lock);
	up_read(&zram->init_lock);
	ret = len;

	return ret;
}

static ssize_t writeback_limit_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u64 val;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	spin_lock(&zram->wb_limit_lock);
	val = zram->bd_wb_limit;
	spin_unlock(&zram->wb_limit_lock);
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", val);
}

static void reset_bdev(struct zram *zram)
{
	struct block_device *bdev;

	if (!zram->backing_dev)
		return;

	bdev = zram->bdev;

	/**
	 * Conflict Fix Kernel API with blkdev_put
	 */
	/* blkdev_put(bdev, zram); */
	blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);

	/* hope filp_close flush all of IO */
	filp_close(zram->backing_dev, NULL);
	zram->backing_dev = NULL;
	zram->bdev = NULL;
	zram->disk->fops = &zram_devops;
	kvfree(zram->bitmap);
	zram->bitmap = NULL;
}

static ssize_t backing_dev_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct file *file;
	struct zram *zram = dev_to_zram(dev);
	char *p;
	ssize_t ret;

	down_read(&zram->init_lock);
	file = zram->backing_dev;
	if (!file) {
		memcpy(buf, "none\n", 5);
		up_read(&zram->init_lock);
		return 5;
	}

	p = file_path(file, buf, PAGE_SIZE - 1);
	if (IS_ERR(p)) {
		ret = PTR_ERR(p);
		goto out;
	}

	ret = strlen(p);
	memmove(buf, p, ret);
	buf[ret++] = '\n';
out:
	up_read(&zram->init_lock);
	return ret;
}

static ssize_t backing_dev_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	char *file_name;
	size_t sz;
	struct file *backing_dev = NULL;
	struct inode *inode;
	struct address_space *mapping;
	unsigned int bitmap_sz;
	unsigned long nr_pages, *bitmap = NULL;
	struct block_device *bdev = NULL;
	int err;
	struct zram *zram = dev_to_zram(dev);

	file_name = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!file_name)
		return -ENOMEM;

	down_write(&zram->init_lock);
	if (init_done(zram)) {
		pr_info("Can't setup backing device for initialized device\n");
		err = -EBUSY;
		goto out;
	}

	strscpy(file_name, buf, PATH_MAX);
	/* ignore trailing newline */
	sz = strlen(file_name);
	if (sz > 0 && file_name[sz - 1] == '\n')
		file_name[sz - 1] = 0x00;

	/**
	 * common kernel use filp_open_block replace filp_open
	 * reference: cf8f7947f ("ANDROID: Add filp_open_block() for zram")
	 */
	/* backing_dev = filp_open(file_name, O_RDWR|O_LARGEFILE, 0); */
	backing_dev = filp_open_block(file_name, O_RDWR|O_LARGEFILE, 0);

	if (IS_ERR(backing_dev)) {
		err = PTR_ERR(backing_dev);
		backing_dev = NULL;
		goto out;
	}

	mapping = backing_dev->f_mapping;
	inode = mapping->host;

	/* Support only block device in this moment */
	if (!S_ISBLK(inode->i_mode)) {
		err = -ENOTBLK;
		goto out;
	}

	/**
	 * Conflict Fix Kernel API with blkdev_get_by_dev
	 */
	/* bdev = blkdev_get_by_dev(inode->i_rdev, BLK_OPEN_READ | BLK_OPEN_WRITE,
				 zram, NULL); */
	bdev = blkdev_get_by_dev(inode->i_rdev,
			FMODE_READ | FMODE_WRITE | FMODE_EXCL, zram);

	if (IS_ERR(bdev)) {
		err = PTR_ERR(bdev);
		bdev = NULL;
		goto out;
	}

	nr_pages = i_size_read(inode) >> PAGE_SHIFT;
	bitmap_sz = BITS_TO_LONGS(nr_pages) * sizeof(long);
	bitmap = kvzalloc(bitmap_sz, GFP_KERNEL);
	if (!bitmap) {
		err = -ENOMEM;
		goto out;
	}

	reset_bdev(zram);

	zram->bdev = bdev;
	zram->backing_dev = backing_dev;
	zram->bitmap = bitmap;
	zram->nr_pages = nr_pages;
	up_write(&zram->init_lock);

	pr_info("setup backing device %s\n", file_name);
	kfree(file_name);

	return len;
out:
	kvfree(bitmap);

	if (bdev)
		/**
		 * Conflict Fix Kernel API with blkdev_put
		 */
		/* blkdev_put(bdev, zram); */
		blkdev_put(bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);

	if (backing_dev)
		filp_close(backing_dev, NULL);

	up_write(&zram->init_lock);

	kfree(file_name);

	return err;
}

#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
static inline void update_wb_pages_max(struct zram *zram,
					const s64 wb_pages)
{
	unsigned long old_max, cur_max;

	old_max = atomic_long_read(&zram->stats.wb_pages_max);

	do {
		cur_max = old_max;
		if (wb_pages > cur_max)
			old_max = atomic_long_cmpxchg(
				&zram->stats.wb_pages_max, cur_max, wb_pages);
	} while (old_max != cur_max);
}
#endif

static unsigned long alloc_block_bdev(struct zram *zram)
{
	unsigned long blk_idx = 1;
retry:
	/* skip 0 bit to confuse zram.handle = 0 */
	blk_idx = find_next_zero_bit(zram->bitmap, zram->nr_pages, blk_idx);
	if (blk_idx == zram->nr_pages)
		return 0;

	if (test_and_set_bit(blk_idx, zram->bitmap))
		goto retry;

	atomic64_inc(&zram->stats.bd_count);
#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
	update_wb_pages_max(zram,
		atomic64_read(&zram->stats.bd_count));
#endif
	return blk_idx;
}

static void free_block_bdev(struct zram *zram, unsigned long blk_idx)
{
	int was_set;

	was_set = test_and_clear_bit(blk_idx, zram->bitmap);
	WARN_ON_ONCE(!was_set);
	atomic64_dec(&zram->stats.bd_count);
}

static void read_from_bdev_async(struct zram *zram, struct page *page,
			unsigned long entry, struct bio *parent)
{
	struct bio *bio;

	/**
	 * Restore the 5.10.237 the read_from_bdev_async
	 * reference: 4aabdc14c ("zram_drv: allow reclaim on bio_alloc")
	 * reference: 07888c665 ("block: pass a block_device and opf to bio_alloc")
	 * reference: 49add4966 ("block: pass a block_device and opf to bio_init")
	 * reference: 4e3c87b94 ("zram: fix synchronous reads [android15-6.6]")
	 * reference: fd45af53e ("zram: pass a page to read_from_bdev [android15-6.6]")
	 * reference: 0cd97a037 ("zram: don't return errors from read_from_bdev_async")
	 */
	bio = bio_alloc(GFP_NOIO, 1);

	bio_set_dev(bio, zram->bdev);
	bio->bi_iter.bi_sector = entry * (PAGE_SIZE >> 9);
	bio->bi_opf = parent->bi_opf;

	/* __bio_add_page(bio, page, PAGE_SIZE, 0); */
	zram_bio_add_page(bio, page, PAGE_SIZE, 0);

	bio_chain(bio, parent);
	submit_bio(bio);
}

#define PAGE_WB_SIG "page_index="

#define PAGE_WRITEBACK			0
#define HUGE_WRITEBACK			(1<<0)
#define IDLE_WRITEBACK			(1<<1)
#define INCOMPRESSIBLE_WRITEBACK	(1<<2)

/* Returns true on success, false on parsing error. */
static bool writeback_parse_input(const char *buf,
			unsigned long *wb_max, unsigned int *wb_idle_min, unsigned int *mf_cgroup)
{
	char *argbuf, *args, *arg;
	bool ret = false;

	args = argbuf = kstrndup(buf, 32, GFP_KERNEL);
	if (!args)
		return false;

	arg = strsep(&args, " ");
	if (!sysfs_streq(arg, "idle"))
		goto err;

	/* get @wb_max */
	arg = strsep(&args, " ");
	if (arg) {
		if (kstrtoul(arg, 10, wb_max))
			goto err;

		/* get @wb_idle_min */
		arg = strsep(&args, " ");
		if (arg) {
			if (kstrtouint(arg, 10, wb_idle_min))
				goto err;

			if (*wb_idle_min > ZRAM_WB_IDLE_MAX)
				*wb_idle_min = ZRAM_WB_IDLE_MAX;

			arg = strsep(&args, " ");
			if (arg) {
				if (kstrtouint(arg, 10, mf_cgroup))
					goto err;

				if (strsep(&args, " "))
					goto err;
			}
		}
	}

	ret = true;
	pr_info("Parse succeed. wb_max: %lu, wb_idle_min: %u\n", *wb_max,
		*wb_idle_min);
err:
	kfree(argbuf);
	return ret;
}

static int wait_for_writeback_batch(struct zram *zram, int start_blkidx, int nr_write,
					struct writeback_batch_pages *batch_pages)
{
	struct bio bio;
	struct bio_vec bio_vecs[MAX_WRITEBACK_SIZE];
	int i, err, index;
	int wb_pages_nr = 0;

#ifdef CONFIG_MI_MEMORY_FREEZE
	bool mfz_flag = false;
#endif

	/**
	 * Restore the 5.10.237 the wait_for_writeback_batch
	 * reference: 49add4966 ("block: pass a block_device and opf to bio_init")
	 */
	bio_init(&bio, bio_vecs, nr_write);
	bio_set_dev(&bio, zram->bdev);
	bio.bi_iter.bi_sector = start_blkidx * (PAGE_SIZE >> 9);
	bio.bi_opf = REQ_OP_WRITE | REQ_SYNC;

	/* bio_init(&bio, zram->bdev, bio_vecs, nr_write,
		REQ_OP_WRITE | REQ_SYNC);
	bio.bi_iter.bi_sector = start_blkidx * (PAGE_SIZE >> 9); */

	for (i = 0; i < nr_write; i++)
		/* __bio_add_page(&bio, batch_pages[i].page, PAGE_SIZE, 0); */
		zram_bio_add_page(&bio, batch_pages[i].page, PAGE_SIZE, 0);

	err = submit_bio_wait(&bio);
	if (err) {
		for (i = 0; i < nr_write; i++) {
			index = batch_pages[i].index;
			zram_slot_lock(zram, index);
			zram_clear_flag(zram, index, ZRAM_UNDER_WB);
			zram_clear_flag(zram, index, ZRAM_IDLE);
			zram_clear_idle_count(zram, index);
#ifdef CONFIG_MI_MEMORY_FREEZE
			if (zram_test_flag(zram, index, ZRAM_WRITEBACK_UNLIMITED)) {
				if (atomic64_read(&zram->stats.mf_bd_count) > 0)
					atomic64_dec(&zram->stats.mf_bd_count);
			}
#endif
			zram_slot_unlock(zram, index);
			free_block_bdev(zram, start_blkidx + i);
		}
		/*
		* Return last IO error unless every IO were
		* not suceeded.
		*/
		return 0;
	}

	for (i = 0; i < nr_write; i++) {
		index = batch_pages[i].index;
		atomic64_inc(&zram->stats.bd_writes);
		/*
		 * We released zram_slot_lock so need to check if the slot was
		 * changed. If there is freeing for the slot, we can catch it
		 * easily by zram_allocated.
		 * A subtle case is the slot is freed/reallocated/marked as
		 * ZRAM_IDLE again. To close the race, idle_store doesn't
		 * mark ZRAM_IDLE once it found the slot was ZRAM_UNDER_WB.
		 * Thus, we could close the race by checking ZRAM_IDLE bit.
		 */
		zram_slot_lock(zram, index);
#ifdef CONFIG_MI_MEMORY_FREEZE
		if (zram_test_flag(zram, index, ZRAM_WRITEBACK_UNLIMITED)) {
			mfz_flag = true;
		}
#endif
		if (!zram_allocated(zram, index) ||
		    !zram_test_flag(zram, index, ZRAM_IDLE)) {
			zram_clear_flag(zram, index, ZRAM_UNDER_WB);
			zram_clear_flag(zram, index, ZRAM_IDLE);
			zram_clear_idle_count(zram, index);
#ifdef CONFIG_MI_MEMORY_FREEZE
			if (mfz_flag) {
				if (atomic64_read(&zram->stats.mf_bd_count) > 0)
					atomic64_dec(&zram->stats.mf_bd_count);
			}
#endif
			zram_slot_unlock(zram, index);
			free_block_bdev(zram, start_blkidx + i);
			continue;
		}

		zram_free_page(zram, index);
		zram_clear_flag(zram, index, ZRAM_UNDER_WB);
		zram_set_flag(zram, index, ZRAM_WB);
#ifdef CONFIG_MI_MEMORY_FREEZE
		if (mfz_flag) {
			zram_set_flag(zram, index, ZRAM_WRITEBACK_UNLIMITED);
			atomic64_inc(&zram->stats.mf_bd_writes);
			mfz_flag = false;
		}
#endif
		zram_set_element(zram, index, start_blkidx + i);
		wb_pages_nr++;
		// blk_idx = 0;
		atomic64_inc(&zram->stats.pages_stored);
		spin_lock(&zram->wb_limit_lock);
		if (zram->wb_limit_enable && zram->bd_wb_limit > 0)
			zram->bd_wb_limit -=  1UL << (PAGE_SHIFT - 12);
		spin_unlock(&zram->wb_limit_lock);
		zram_slot_unlock(zram, index);
	}

	return wb_pages_nr;
}

#if defined(CONFIG_ZRAM_WRITEBACK) && defined(CONFIG_MI_MEMORY_FREEZE)
static bool extm_has_disk_quota(struct zram *zram)
{
	unsigned long bd_count_result, mf_bd_count_result, mf_bd_count_max,
		bd_count_diff;

	if (zram->mfz_disk_quota == 0) {
		return true;
	}

	//get mfz writeback count and calculate the conut_max
	bd_count_result = atomic64_read(&zram->stats.bd_count);
	mf_bd_count_result = atomic64_read(&zram->stats.mf_bd_count);
	bd_count_diff = bd_count_result - mf_bd_count_result;
	mf_bd_count_max = zram->nr_pages - zram->mfz_disk_quota;

	if (bd_count_diff >= mf_bd_count_max) {
		return false;
	}
	return true;
}
#endif

#ifdef CONFIG_ZRAM_WRITEBACK
static int scan_slots_for_writeback(struct zram *zram, u32 mode,
                                    unsigned int wb_idle_min,
				    unsigned long nr_pages,
				    unsigned long index,
				    struct zram_pp_ctl *ctl)
{
	struct zram_pp_slot *pps = NULL;

	for (; nr_pages != 0; index++, nr_pages--) {
		if (!pps)
			pps = kmalloc(sizeof(*pps), GFP_KERNEL);
		if (!pps)
			return -ENOMEM;

		INIT_LIST_HEAD(&pps->entry);

		zram_slot_lock(zram, index);
		if (!zram_allocated(zram, index))
			goto next;

		if (zram_test_flag(zram, index, ZRAM_WB) ||
		    zram_test_flag(zram, index, ZRAM_SAME) ||
		    zram_test_flag(zram, index, ZRAM_UNDER_WB) ||
			!zram_test_flag(zram, index, ZRAM_COMPRESS_LOW))
			goto next;

		if (mode & IDLE_WRITEBACK &&
			  (!zram_test_flag(zram, index, ZRAM_IDLE) ||
			   zram_get_idle_count(zram, index) < wb_idle_min))
			goto next;
		if (mode & HUGE_WRITEBACK &&
		    !zram_test_flag(zram, index, ZRAM_HUGE))
			goto next;

		pps->index = index;
		place_pp_slot(zram, ctl, pps);
		pps = NULL;
next:
		zram_slot_unlock(zram, index);
	}

	kfree(pps);
	return 0;
}

static ssize_t pp_buckets_show(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    struct zram *zram = dev_to_zram(dev);
    struct zram_pp_ctl *ctl = NULL;
    int count = 0;
    int i, length, length_total = 0, ret, ret_scan, mode = 2;
    unsigned int wb_idle_min_def = 1;
    unsigned long index = 0;
    unsigned long nr_pages = zram->disksize >> PAGE_SHIFT;

    ctl = init_pp_ctl();
    if (!ctl) {
        ret = -ENOMEM;
        pr_info("init_pp_ctl-ENOMEM");
        return ret;
    }
    ret_scan = scan_slots_for_writeback(zram, mode, wb_idle_min_def, nr_pages, index, ctl);
    if (ret_scan != 0) {
        release_pp_ctl(zram, ctl);
        ret = -ENOMEM;
        return ret;
    }
    for (i = 0; i < NUM_PP_BUCKETS; i++) {
        length = list_length(&ctl->pp_buckets[i]);
        length_total += length;
        count += snprintf(buf + count, PAGE_SIZE - count, "%d ", length);
        if (count >= PAGE_SIZE) {
            break;
        }
    }
    count += snprintf(buf + count, PAGE_SIZE - count, " %d\n", length_total);
    release_pp_ctl(zram, ctl);
    return count;
}
#endif

static ssize_t writeback_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	unsigned long nr_pages = zram->disksize >> PAGE_SHIFT;
	struct zram_pp_ctl *ctl = NULL;
	struct zram_pp_slot *pps;
	unsigned long index = 0, wb_max = ULONG_MAX;
	unsigned int mf_cgroup = 0, wb_idle_min = ZRAM_WB_IDLE_DEFAULT;
	struct writeback_batch_pages batch_pages[MAX_WRITEBACK_SIZE];
	int nr_write = 0, flush_count = 0, mode;
	ssize_t ret = len;
	unsigned long blk_idx = 0, start_blkidx = 0, wb_pages_nr = 0;

	if (writeback_parse_input(buf, &wb_max, &wb_idle_min, &mf_cgroup))
		mode = IDLE_WRITEBACK;
	else if (sysfs_streq(buf, "idle"))
		mode = IDLE_WRITEBACK;
	else if (sysfs_streq(buf, "huge"))
		mode = HUGE_WRITEBACK;
	else if (sysfs_streq(buf, "huge_idle"))
		mode = IDLE_WRITEBACK | HUGE_WRITEBACK;
	else if (sysfs_streq(buf, "incompressible"))
		mode = INCOMPRESSIBLE_WRITEBACK;
	else {
		if (strncmp(buf, PAGE_WB_SIG, sizeof(PAGE_WB_SIG) - 1))
			return -EINVAL;

		if (kstrtol(buf + sizeof(PAGE_WB_SIG) - 1, 10, &index) ||
				index >= nr_pages)
			return -EINVAL;

		nr_pages = 1;
		mode = PAGE_WRITEBACK;
	}

	down_read(&zram->init_lock);
	if (!init_done(zram)) {
		ret = -EINVAL;
		goto release_init_lock;
	}

	if (!zram->backing_dev) {
		ret = -ENODEV;
		goto release_init_lock;
	}

	if (!zram->writeback_pages) {
		ret = -ENOMEM;
		goto release_init_lock;
	}

	ctl = init_pp_ctl();
	if (!ctl) {
		ret = -ENOMEM;
		goto release_init_lock;
	}

	scan_slots_for_writeback(zram, mode, wb_idle_min, nr_pages, index, ctl);
	while ((pps = select_pp_slot(ctl))) {
		struct page *page;
		/*
		 * If the writeback thread is running and we receive the
		 * SCREEN_ON event, we will send SIGUSR1 singnal to teriminate
		 * the writeback thread. So if there is a SIGUSR1 signal in
		 * current thread, stop writeback.
		 */
		if (signal_pending(current) &&
		    (sigismember(&current->signal->shared_pending.signal, SIGUSR1) ||
		     sigismember(&current->pending.signal, SIGUSR1))) {
			pr_info("Stop writeback, because SIGUSR1 is received\n");
			ret = -EINTR;
			release_pp_slot(zram, pps);
			break;
		}

		spin_lock(&zram->wb_limit_lock);
		if (zram->wb_limit_enable && !zram->bd_wb_limit) {
			spin_unlock(&zram->wb_limit_lock);
			release_pp_slot(zram, pps);
			ret = -EIO;
			break;
		}
		spin_unlock(&zram->wb_limit_lock);

		if (!blk_idx) {
			blk_idx = alloc_block_bdev(zram);
			if (!blk_idx) {
				ret = -ENOSPC;
				release_pp_slot(zram, pps);
				break;
			}
			if (nr_write == 0)
				start_blkidx = blk_idx;
		}

		if (nr_write >= MAX_WRITEBACK_SIZE ||
				(start_blkidx + nr_write != blk_idx)) {
			wb_pages_nr += wait_for_writeback_batch(zram, start_blkidx,
								nr_write, batch_pages);
			start_blkidx = blk_idx;
			nr_write = 0;
			flush_count++;
		}

		if (wb_pages_nr >= wb_max) {
			release_pp_slot(zram, pps);
			break;
		}

		page = zram->writeback_pages + nr_write;
		index = pps->index;
		zram_slot_lock(zram, index);

#ifdef CONFIG_MI_MEMORY_FREEZE
		/* if mf_cgroup is true, then only the page in mfz cgroup will be written back */
		if (mf_cgroup &&
			  !zram_test_flag(zram, index, ZRAM_WRITEBACK_UNLIMITED))
			goto next;
#endif

		if (!zram_test_flag(zram, index, ZRAM_PP_SLOT))
 			goto next;

#ifdef CONFIG_MI_MEMORY_FREEZE
		if (zram->mfz_enable &&
		    !zram_test_flag(zram, index, ZRAM_WRITEBACK_UNLIMITED) &&
		    !extm_has_disk_quota(zram))
			goto next;
#endif
		if (zram_test_flag(zram, index, ZRAM_WRITEBACK_PROTECTED))
			goto next;
		if (mode & INCOMPRESSIBLE_WRITEBACK &&
		    !zram_test_flag(zram, index, ZRAM_INCOMPRESSIBLE))
			goto next;

		/*
		 * Clearing ZRAM_UNDER_WB is duty of caller.
		 * IOW, zram_free_page never clear it.
		 */
#ifdef CONFIG_MI_MEMORY_FREEZE
		if (zram_test_flag(zram, index, ZRAM_WRITEBACK_UNLIMITED)) {
			atomic64_inc(&zram->stats.mf_bd_count);
		}
#endif
		zram_set_flag(zram, index, ZRAM_UNDER_WB);
		/* Need for hugepage writeback racing */
		zram_set_flag(zram, index, ZRAM_IDLE);
		zram_slot_unlock(zram, index);
		if (zram_read_page(zram, page, index, NULL)) {
			zram_slot_lock(zram, index);
			zram_clear_flag(zram, index, ZRAM_UNDER_WB);
			zram_clear_flag(zram, index, ZRAM_IDLE);
			zram_clear_idle_count(zram, index);
#ifdef CONFIG_MI_MEMORY_FREEZE
			if (zram_test_flag(zram, index, ZRAM_WRITEBACK_UNLIMITED)) {
				if (atomic64_read(&zram->stats.mf_bd_count) > 0)
					atomic64_dec(&zram->stats.mf_bd_count);
			}
#endif
			zram_slot_unlock(zram, index);
			release_pp_slot(zram, pps);
			continue;
		}

		batch_pages[nr_write].page = page;
		batch_pages[nr_write].index = index;
		nr_write++;
		blk_idx = 0;
		continue;
next:
		zram_slot_unlock(zram, index);
		release_pp_slot(zram, pps);
	}
	if (nr_write) {
		wb_pages_nr += wait_for_writeback_batch(zram, start_blkidx,
							nr_write, batch_pages);
		flush_count++;
	}
	if (blk_idx)
		free_block_bdev(zram, blk_idx);

release_init_lock:
	release_pp_ctl(zram, ctl);
	up_read(&zram->init_lock);

	pr_info("Flush finished. Mode %d, flush %lu pages, flush count %d\n", mode, wb_pages_nr, flush_count);
	return ret ? ret : len;
}

struct zram_work {
	struct work_struct work;
	struct zram *zram;
	unsigned long entry;
	struct page *page;
	int error;
};

static void zram_sync_read(struct work_struct *work)
{
	struct zram_work *zw = container_of(work, struct zram_work, work);
	struct bio_vec bv;
	struct bio bio;

	/**
	 * Restore the 5.10.237 the zram_sync_read
	 * reference: 49add4966 ("block: pass a block_device and opf to bio_init")
	 */
	bio_init(&bio, &bv, 1);
	bio_set_dev(&bio, zw->zram->bdev);
	bio.bi_iter.bi_sector = zw->entry * (PAGE_SIZE >> 9);
	bio.bi_opf = REQ_OP_READ;

	/* bio_init(&bio, zw->zram->bdev, &bv, 1, REQ_OP_READ);
	bio.bi_iter.bi_sector = zw->entry * (PAGE_SIZE >> 9); */
	/* __bio_add_page(&bio, zw->page, PAGE_SIZE, 0); */
	zram_bio_add_page(&bio, zw->page, PAGE_SIZE, 0);

	zw->error = submit_bio_wait(&bio);
}

/*
 * Block layer want one ->submit_bio to be active at a time, so if we use
 * chained IO with parent IO in same context, it's a deadlock. To avoid that,
 * use a worker thread context.
 */
static int read_from_bdev_sync(struct zram *zram, struct page *page,
				unsigned long entry)
{
	struct zram_work work;

	work.page = page;
	work.zram = zram;
	work.entry = entry;

	INIT_WORK_ONSTACK(&work.work, zram_sync_read);
	queue_work(system_unbound_wq, &work.work);
	flush_work(&work.work);
	destroy_work_on_stack(&work.work);

	return work.error;
}

static int read_from_bdev(struct zram *zram, struct page *page,
			unsigned long entry, struct bio *parent)
{
	atomic64_inc(&zram->stats.bd_reads);
	if (!parent) {
		if (WARN_ON_ONCE(!IS_ENABLED(ZRAM_PARTIAL_IO)))
			return -EIO;
		return read_from_bdev_sync(zram, page, entry);
	}
	read_from_bdev_async(zram, page, entry, parent);
	return 0;
}
#else
static inline void reset_bdev(struct zram *zram) {};
static int read_from_bdev(struct zram *zram, struct page *page,
			unsigned long entry, struct bio *parent)
{
	return -EIO;
}

static void free_block_bdev(struct zram *zram, unsigned long blk_idx) {};
#endif

#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
static inline void update_origin_pages_max(struct zram *zram,
					const s64 pages)
{
	unsigned long old_max, cur_max;

	old_max = atomic_long_read(&zram->stats.origin_pages_max);

	do {
		cur_max = old_max;
		if (pages > cur_max)
			old_max = atomic_long_cmpxchg(
				&zram->stats.origin_pages_max, cur_max, pages);
	} while (old_max != cur_max);
}

static void average_size(struct zram *zram, const s64 pages_store)
{
	ktime_t cur_time = ktime_get_boottime();
	unsigned long new_avg;
	ktime_t  diff_time;

	if (!zram->first_time) {
		zram->last_time = zram->first_time = cur_time;
		atomic64_set(&zram->avg_size, pages_store);
	} else {
		diff_time = ktime_sub(cur_time, zram->last_time);
		if (ktime_to_ms(diff_time) > TIME_DIFF_MS) {
			new_avg = ((zram->last_time - zram->first_time) * atomic64_read(&zram->avg_size)
				+ diff_time * pages_store) / (cur_time - zram->first_time);
			atomic64_set(&zram->avg_size, new_avg);
			zram->last_time = cur_time;
		}
	}
	return;
}

static void free_pages_life(struct zram_pages_life *pl)
{
	if (!pl || !pl->time_nr)
		return;

	pl->time_nr = 0;
	if (pl->time_list) {
		kfree(pl->time_list);
		pl->time_list = NULL;
	}
	if (pl->time_list) {
		kfree(pl->lifes);
		pl->lifes = NULL;
	}
	if (pl) {
		kfree(pl);
		pl = NULL;
	}
}

static struct zram_pages_life *init_pages_life(void)
{
	size_t i = 0;
	struct zram_pages_life *pl = NULL;

	pl = kmalloc(sizeof(struct zram_pages_life), GFP_KERNEL);
	if (!pl) {
		return NULL;
	}

	pl->time_nr = ARRAY_SIZE(default_time_list);

	pl->time_list = kmalloc_array(pl->time_nr,
				sizeof(*pl->time_list), GFP_KERNEL);
	pl->lifes = kzalloc((pl->time_nr + 1) *
				sizeof(*pl->lifes), GFP_KERNEL);
	if (!pl->time_list || !pl->lifes) {
		free_pages_life(pl);
		return NULL;
	}

	for (i = 0; i < pl->time_nr; i++) {
		pl->time_list[i] = default_time_list[i];
	}
	return pl;
}

static void zram_record_page_life(struct zram *zram, u32 index)
{
	struct zram_pages_life *pl = NULL;
	ktime_t ac_time, diff;
	int time;
	unsigned int i;

	ac_time = zram->table[index].ac_time;
	if (!ac_time)
		return;

	diff = ktime_get_boottime() - ac_time;
	time = ktime_to_ms(diff) / 1000;

	rcu_read_lock();
	pl =  rcu_dereference(zram->pages_life);
	if (pl) {
		for (i = 0; i < pl->time_nr; i++) {
			if (time <= pl->time_list[i]) {
				pl->lifes[i]++;
				rcu_read_unlock();
				return;
			}
		}
		pl->lifes[i]++;
	}
	rcu_read_unlock();

	return;
}
#endif

#ifdef CONFIG_ZRAM_MEMORY_TRACKING

static struct dentry *zram_debugfs_root;

static void zram_debugfs_create(void)
{
	zram_debugfs_root = debugfs_create_dir("zram", NULL);
}

static void zram_debugfs_destroy(void)
{
	debugfs_remove_recursive(zram_debugfs_root);
}

static void zram_accessed(struct zram *zram, u32 index)
{
	zram_clear_flag(zram, index, ZRAM_IDLE);
	zram_clear_idle_count(zram, index);
#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
	zram_record_page_life(zram, index);
#endif
	zram->table[index].ac_time = ktime_get_boottime();
}

static ssize_t read_block_state(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	char *kbuf;
	ssize_t index, written = 0;
	struct zram *zram = file->private_data;
	unsigned long nr_pages = zram->disksize >> PAGE_SHIFT;
	struct timespec64 ts;

	kbuf = kvmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	down_read(&zram->init_lock);
	if (!init_done(zram)) {
		up_read(&zram->init_lock);
		kvfree(kbuf);
		return -EINVAL;
	}

	for (index = *ppos; index < nr_pages; index++) {
		int copied;

		zram_slot_lock(zram, index);
		if (!zram_allocated(zram, index))
			goto next;

		ts = ktime_to_timespec64(zram->table[index].ac_time);
		copied = snprintf(kbuf + written, count,
			"%12zd %12lld.%06lu %c%c%c%c%c%c\n",
			index, (s64)ts.tv_sec,
			ts.tv_nsec / NSEC_PER_USEC,
			zram_test_flag(zram, index, ZRAM_SAME) ? 's' : '.',
			zram_test_flag(zram, index, ZRAM_WB) ? 'w' : '.',
			zram_test_flag(zram, index, ZRAM_HUGE) ? 'h' : '.',
			zram_test_flag(zram, index, ZRAM_IDLE) ? 'i' : '.',
			zram_get_priority(zram, index) ? 'r' : '.',
			zram_test_flag(zram, index,
				       ZRAM_INCOMPRESSIBLE) ? 'n' : '.');

		if (count <= copied) {
			zram_slot_unlock(zram, index);
			break;
		}
		written += copied;
		count -= copied;
next:
		zram_slot_unlock(zram, index);
		*ppos += 1;
	}

	up_read(&zram->init_lock);
	if (copy_to_user(buf, kbuf, written))
		written = -EFAULT;
	kvfree(kbuf);

	return written;
}

static const struct file_operations proc_zram_block_state_op = {
	.open = simple_open,
	.read = read_block_state,
	.llseek = default_llseek,
};

static void zram_debugfs_register(struct zram *zram)
{
	if (!zram_debugfs_root)
		return;

	zram->debugfs_dir = debugfs_create_dir(zram->disk->disk_name,
						zram_debugfs_root);
	debugfs_create_file("block_state", 0400, zram->debugfs_dir,
				zram, &proc_zram_block_state_op);
}

static void zram_debugfs_unregister(struct zram *zram)
{
	debugfs_remove_recursive(zram->debugfs_dir);
}
#else
static void zram_debugfs_create(void) {};
static void zram_debugfs_destroy(void) {};
static void zram_accessed(struct zram *zram, u32 index)
{
	zram_clear_flag(zram, index, ZRAM_IDLE);
	zram_clear_idle_count(zram, index);
#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
	zram_record_page_life(zram, index);
	zram->table[index].ac_time = ktime_get_boottime();
#endif
};
static void zram_debugfs_register(struct zram *zram) {};
static void zram_debugfs_unregister(struct zram *zram) {};
#endif

/*
 * We switched to per-cpu streams and this attr is not needed anymore.
 * However, we will keep it around for some time, because:
 * a) we may revert per-cpu streams in the future
 * b) it's visible to user space and we need to follow our 2 years
 *    retirement rule; but we already have a number of 'soon to be
 *    altered' attrs, so max_comp_streams need to wait for the next
 *    layoff cycle.
 */
static ssize_t max_comp_streams_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", num_online_cpus());
}

static ssize_t max_comp_streams_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	return len;
}

static void comp_algorithm_set(struct zram *zram, u32 prio, const char *alg)
{
	/* Do not free statically defined compression algorithms */
	if (zram->comp_algs[prio] != default_compressor)
		kfree(zram->comp_algs[prio]);

	zram->comp_algs[prio] = alg;
}

static ssize_t __comp_algorithm_show(struct zram *zram, u32 prio, char *buf)
{
	ssize_t sz;

	down_read(&zram->init_lock);
	sz = zcomp_available_show(zram->comp_algs[prio], buf);
	up_read(&zram->init_lock);

	return sz;
}

static int __comp_algorithm_store(struct zram *zram, u32 prio, const char *buf)
{
	char *compressor;
	size_t sz;

	sz = strlen(buf);
	if (sz >= CRYPTO_MAX_ALG_NAME)
		return -E2BIG;

	compressor = kstrdup(buf, GFP_KERNEL);
	if (!compressor)
		return -ENOMEM;

	/* ignore trailing newline */
	if (sz > 0 && compressor[sz - 1] == '\n')
		compressor[sz - 1] = 0x00;

	if (!zcomp_available_algorithm(compressor)) {
		kfree(compressor);
		return -EINVAL;
	}

	down_write(&zram->init_lock);
	if (init_done(zram)) {
		up_write(&zram->init_lock);
		kfree(compressor);
		pr_info("Can't change algorithm for initialized device\n");
		return -EBUSY;
	}

	comp_algorithm_set(zram, prio, compressor);
	up_write(&zram->init_lock);
	return 0;
}

static ssize_t comp_algorithm_show(struct device *dev,
				   struct device_attribute *attr,
				   char *buf)
{
	struct zram *zram = dev_to_zram(dev);

	return __comp_algorithm_show(zram, ZRAM_PRIMARY_COMP, buf);
}

static ssize_t comp_algorithm_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf,
				    size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	int ret;

	ret = __comp_algorithm_store(zram, ZRAM_PRIMARY_COMP, buf);
	return ret ? ret : len;
}

#ifdef CONFIG_ZRAM_MULTI_COMP
static ssize_t recomp_algorithm_show(struct device *dev,
				     struct device_attribute *attr,
				     char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	ssize_t sz = 0;
	u32 prio;

	for (prio = ZRAM_SECONDARY_COMP; prio < ZRAM_MAX_COMPS; prio++) {
		if (!zram->comp_algs[prio])
			continue;

		sz += scnprintf(buf + sz, PAGE_SIZE - sz - 2, "#%d: ", prio);
		sz += __comp_algorithm_show(zram, prio, buf + sz);
	}

	return sz;
}

static ssize_t recomp_algorithm_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf,
				      size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	int prio = ZRAM_SECONDARY_COMP;
	char *args, *param, *val;
	char *alg = NULL;
	int ret;

	args = skip_spaces(buf);
	while (*args) {
		args = next_arg(args, &param, &val);

		if (!val || !*val)
			return -EINVAL;

		if (!strcmp(param, "algo")) {
			alg = val;
			continue;
		}

		if (!strcmp(param, "priority")) {
			ret = kstrtoint(val, 10, &prio);
			if (ret)
				return ret;
			continue;
		}
	}

	if (!alg)
		return -EINVAL;

	if (prio < ZRAM_SECONDARY_COMP || prio >= ZRAM_MAX_COMPS)
		return -EINVAL;

	ret = __comp_algorithm_store(zram, prio, alg);
	return ret ? ret : len;
}
#endif

static ssize_t compact_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	if (!init_done(zram)) {
		up_read(&zram->init_lock);
		return -EINVAL;
	}

	zs_compact(zram->mem_pool);
	up_read(&zram->init_lock);

	return len;
}

static ssize_t io_stat_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	ssize_t ret;

	down_read(&zram->init_lock);
	ret = scnprintf(buf, PAGE_SIZE,
			"%8llu %8llu 0 %8llu\n",
			(u64)atomic64_read(&zram->stats.failed_reads),
			(u64)atomic64_read(&zram->stats.failed_writes),
			(u64)atomic64_read(&zram->stats.notify_free));
	up_read(&zram->init_lock);

	return ret;
}

static ssize_t mm_stat_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	struct zs_pool_stats pool_stats;
	u64 orig_size, mem_used = 0;
	long max_used;
	ssize_t ret;

	memset(&pool_stats, 0x00, sizeof(struct zs_pool_stats));

	down_read(&zram->init_lock);
	if (init_done(zram)) {
		mem_used = zs_get_total_pages(zram->mem_pool);
		zs_pool_stats(zram->mem_pool, &pool_stats);
	}

	orig_size = atomic64_read(&zram->stats.pages_stored);
	max_used = atomic_long_read(&zram->stats.max_used_pages);

	ret = scnprintf(buf, PAGE_SIZE,
			"%8llu %8llu %8llu %8lu %8ld %8llu %8lu %8llu %8llu %8llu\n",
			orig_size << PAGE_SHIFT,
			(u64)atomic64_read(&zram->stats.compr_data_size),
			mem_used << PAGE_SHIFT,
			zram->limit_pages << PAGE_SHIFT,
			max_used << PAGE_SHIFT,
			(u64)atomic64_read(&zram->stats.same_pages),
			atomic_long_read(&pool_stats.pages_compacted),
			(u64)atomic64_read(&zram->stats.huge_pages),
			(u64)atomic64_read(&zram->stats.huge_pages_since),
			(u64)atomic64_read(&zram->stats.lowratio_pages));
	up_read(&zram->init_lock);

	return ret;
}

static ssize_t get_idle_or_new_pages(struct zram *zram,
					char *buf, const bool idle)
{
#ifdef	CONFIG_ZRAM_WRITEBACK
	unsigned int i = 0;
#endif
	ssize_t ret = -EINVAL;
#ifdef	CONFIG_ZRAM_WRITEBACK
	size_t off = 0;
#endif
	down_read(&zram->init_lock);

	if (!init_done(zram))
		goto out;
#ifdef	CONFIG_ZRAM_WRITEBACK
	for (i = 0; i < ZRAM_WB_IDLE_MAX; i++)
		off += scnprintf(buf + off, PAGE_SIZE - off, "%llu ", atomic64_read(&zram->stats.total_idle_count[i]));
	buf[off - 1] = '\n';
	ret = off;
#endif
out:
	up_read(&zram->init_lock);
	return ret;
}

#if defined(CONFIG_ZRAM_WRITEBACK) && defined(CONFIG_MI_MEMORY_FREEZE)
static ssize_t get_mfz_idle_pages(struct zram *zram, char *buf, const bool idle)
{
	unsigned long index, nr_pages = zram->disksize >> PAGE_SHIFT;
	unsigned long pages_nr[ZRAM_WB_IDLE_MAX + 1] = { 0 };
	unsigned int max_idle_count = idle ? ZRAM_WB_IDLE_MAX : 0;
	unsigned int min_idle_count = idle ? 1 : 0;
	unsigned int idle_count = 0;
	unsigned int i = 0;
	ssize_t ret = -EINVAL;
	size_t off = 0;

	down_read(&zram->init_lock);

	if (!init_done(zram))
		goto out;

	for (index = 0; index < nr_pages; index++) {
		zram_slot_lock(zram, index);

		if (zram_get_obj_size(zram, index) &&
		    zram_test_flag(zram, index, ZRAM_IDLE)) {
			if (zram_test_flag(zram, index,
					   ZRAM_WRITEBACK_UNLIMITED)) {
				idle_count = zram_get_idle_count(zram, index);
				if (idle_count <= max_idle_count)
					pages_nr[idle_count]++;
			}
		}
		zram_slot_unlock(zram, index);
	}

	for (i = min_idle_count; i <= max_idle_count; i++)
		off += scnprintf(buf + off, PAGE_SIZE - off, "%lu ",
				 pages_nr[i]);
	buf[off - 1] = '\n';
	ret = off;

out:
	up_read(&zram->init_lock);
	return ret;
}

static ssize_t mfz_compr_data_size_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	ssize_t ret;

	down_read(&zram->init_lock);
	ret = scnprintf(buf, PAGE_SIZE, "%8llu\n",
		(u64)atomic64_read(&zram->stats.mfz_compr_data_size));
	up_read(&zram->init_lock);

	return ret;
}
#endif

static ssize_t idle_stat_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return get_idle_or_new_pages(dev_to_zram(dev), buf, true);
}

static ssize_t new_stat_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return get_idle_or_new_pages(dev_to_zram(dev), buf, false);
}

#if defined(CONFIG_ZRAM_WRITEBACK) && defined(CONFIG_MI_MEMORY_FREEZE)
static ssize_t mfz_idle_stat_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	return get_mfz_idle_pages(dev_to_zram(dev), buf, true);
}
#endif

#ifdef CONFIG_ZRAM_WRITEBACK
#define FOUR_K(x) ((x) * (1 << (PAGE_SHIFT - 12)))
static ssize_t bd_stat_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	ssize_t ret;

	down_read(&zram->init_lock);
	ret = scnprintf(buf, PAGE_SIZE, "%8llu %8llu %8llu %8llu %8llu %8llu\n",
			FOUR_K((u64)atomic64_read(&zram->stats.bd_count)),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_reads)),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_writes)),
			FOUR_K((u64)atomic64_read(&zram->stats.mf_bd_count)),
			FOUR_K((u64)atomic64_read(&zram->stats.mf_bd_reads)),
			FOUR_K((u64)atomic64_read(&zram->stats.mf_bd_writes)));
	up_read(&zram->init_lock);

	return ret;
}
#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
static ssize_t wb_pages_max_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	ssize_t ret;

	down_read(&zram->init_lock);
	ret = scnprintf(buf, PAGE_SIZE, "%8lld\n",
			atomic64_read(&zram->stats.wb_pages_max));
	up_read(&zram->init_lock);

	return ret;
}
#endif
#endif

static ssize_t debug_stat_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int version = 1;
	struct zram *zram = dev_to_zram(dev);
	ssize_t ret;

	down_read(&zram->init_lock);
	ret = scnprintf(buf, PAGE_SIZE,
			"version: %d\n%8llu %8llu\n",
			version,
			(u64)atomic64_read(&zram->stats.writestall),
			(u64)atomic64_read(&zram->stats.miss_free));
	up_read(&zram->init_lock);

	return ret;
}

#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
static ssize_t origin_pages_max_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	ssize_t ret;

	down_read(&zram->init_lock);
	ret = scnprintf(buf, PAGE_SIZE, "%8lld\n",
			atomic64_read(&zram->stats.origin_pages_max));
	up_read(&zram->init_lock);

	return ret;
}

static size_t print_time_list(struct zram_pages_life *pl, char *buf)
{
	size_t off = 0;
	unsigned int i;

	if (!pl->time_nr)
		goto out;

	for (i = 0; i < pl->time_nr; i++)
		off += scnprintf(buf + off, PAGE_SIZE - off,
				"%d\t", pl->time_list[i]);

	off += scnprintf(buf + off, PAGE_SIZE - off,
			">%d\n",  pl->time_list[i - 1]);

out:
	return off;
}

static size_t print_pages_life(struct zram_pages_life *pl, char *buf)
{
	size_t off = 0;
	unsigned int i;

	if (!pl->time_nr)
		goto out;

	off = print_time_list(pl, buf);

	for (i = 0; i < pl->time_nr + 1; i++)
		off += scnprintf(buf + off, PAGE_SIZE - off,
				"%lu\t", pl->lifes[i]);
	buf[off - 1] = '\n';

out:
	return off;
}

static ssize_t time_list_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	ssize_t ret = -EINVAL;
	struct zram_pages_life *pl = NULL;

	down_read(&zram->init_lock);

	if (!init_done(zram))
		goto out;

	pl = rcu_dereference(zram->pages_life);
	if (pl) {
		ret = print_time_list(pl, buf);
	}
out:
	up_read(&zram->init_lock);
	return ret;
}
static void clean_pages_life(struct rcu_head *rcu)
{
	struct zram_pages_life *pl = container_of(rcu, struct zram_pages_life, rcu);
	free_pages_life(pl);
}

static int renew_pages_life(struct zram *zram, unsigned int *time_list, unsigned int time_nr)
{
	struct zram_pages_life *pl_old = zram->pages_life;
	struct zram_pages_life *pl_new = NULL;

	if (!time_nr || !time_list) {
		return -ENOMEM;
	}

	pl_new =  kmalloc(sizeof(struct zram_pages_life), GFP_KERNEL);
	if (!pl_new) {
		return -ENOMEM;
	}
	pl_new->time_nr  = time_nr;
	pl_new->time_list = kmalloc_array(time_nr,
				sizeof(*pl_new->time_list), GFP_KERNEL);

	pl_new->lifes = kzalloc((time_nr + 1) *
				sizeof(*pl_new->lifes), GFP_KERNEL);

	if (!pl_new->time_list || !pl_new->lifes) {
		free_pages_life(pl_new);
		return -ENOMEM;
	}

	memcpy(pl_new->time_list, time_list, sizeof(*pl_new->time_list)*time_nr);
	rcu_assign_pointer(zram->pages_life, pl_new);
	if (pl_old) {
		call_rcu(&pl_old->rcu, clean_pages_life);
		pl_old = NULL;
	}

	return time_nr;
}

static ssize_t time_list_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	ssize_t ret = -EINVAL;
	int *time_list;
	int time;
	char *arg, *args, *arg_buf;
	unsigned int time_nr, i;

	args = arg_buf = kstrndup(buf, 32, GFP_KERNEL);
	arg = strsep(&args, " ");
	if (!arg || kstrtouint(arg, 10, &time_nr))
		goto free_arg_buf;

	if (!time_nr) {
		ret = 0;
		goto free_arg_buf;
	}

	time_list = kmalloc_array(time_nr,
				sizeof(*time_list), GFP_KERNEL);
	if (!time_list) {
		ret = -ENOMEM;
		goto free_arg_buf;
	}
	for (i = 0; i < time_nr; i++) {
		/* get time */
		arg = strsep(&args, " ");
		if (!arg || kstrtoint(arg, 10, &time))
			goto free_time;

		time_list[i] = time;
	}

	down_read(&zram->init_lock);
	if (!init_done(zram))
		goto out;
	ret = renew_pages_life(zram, time_list, time_nr);
out:
	up_read(&zram->init_lock);
free_time:
	kfree(time_list);
free_arg_buf:
	kfree(arg_buf);
	return ret ? ret : len;
}

static ssize_t pages_life_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	ssize_t ret = -EINVAL;
	struct zram_pages_life *pl = NULL;

	rcu_read_lock();
	pl = rcu_dereference(zram->pages_life);
	if (pl)
		ret = print_pages_life(pl, buf);
	rcu_read_unlock();

	return ret;
}

static ssize_t avg_size_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	return scnprintf(buf, PAGE_SIZE, "%8llu\n", (u64)atomic64_read(&zram->avg_size));
}
#endif

static DEVICE_ATTR_RO(io_stat);
static DEVICE_ATTR_RO(mm_stat);
static DEVICE_ATTR_RO(idle_stat);
static DEVICE_ATTR_RO(new_stat);
#ifdef CONFIG_ZRAM_WRITEBACK
static DEVICE_ATTR_RO(bd_stat);
static DEVICE_ATTR_RO(pp_buckets);
#ifdef CONFIG_MI_MEMORY_FREEZE
static DEVICE_ATTR_RO(mfz_idle_stat);
static DEVICE_ATTR_RW(mfz_enable);
static DEVICE_ATTR_RW(mfz_disk_quota);
static DEVICE_ATTR_RO(mfz_compr_data_size);
#endif
#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
static DEVICE_ATTR_RO(wb_pages_max);
#endif
#endif
static DEVICE_ATTR_RO(debug_stat);

#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
static DEVICE_ATTR_RW(time_list);
static DEVICE_ATTR_RO(pages_life);
static DEVICE_ATTR_RO(avg_size);
static DEVICE_ATTR_RO(origin_pages_max);
static DEVICE_ATTR_RW(low_compress_ratio);
#endif

static void zram_meta_free(struct zram *zram, u64 disksize)
{
	size_t num_pages = disksize >> PAGE_SHIFT;
	size_t index;

	/* Free all pages that are still in this zram device */
	for (index = 0; index < num_pages; index++)
		zram_free_page(zram, index);

	zs_destroy_pool(zram->mem_pool);
	vfree(zram->table);
}

static bool zram_meta_alloc(struct zram *zram, u64 disksize)
{
	size_t num_pages;

	num_pages = disksize >> PAGE_SHIFT;
	zram->table = vzalloc(array_size(num_pages, sizeof(*zram->table)));
	if (!zram->table)
		return false;

	zram->mem_pool = zs_create_pool(zram->disk->disk_name);
	if (!zram->mem_pool) {
		vfree(zram->table);
		return false;
	}

#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
	rcu_assign_pointer(zram->pages_life, init_pages_life());
#endif

	if (!huge_class_size)
		huge_class_size = zs_huge_class_size(zram->mem_pool);
	return true;
}

/*
 * To protect concurrent access to the same index entry,
 * caller should hold this table index entry's bit_spinlock to
 * indicate this index entry is accessing.
 */
static void zram_free_page(struct zram *zram, size_t index)
{
	unsigned long handle;

#ifdef CONFIG_ZRAM_MEMORY_TRACKING
	zram->table[index].ac_time = 0;
#endif
	if (zram_test_flag(zram, index, ZRAM_IDLE)) {
		zram_clear_flag(zram, index, ZRAM_IDLE);
		zram_clear_idle_count(zram, index);
	}

	if (zram_test_flag(zram, index, ZRAM_COMPRESS_LOW)) {
		zram_clear_flag(zram, index, ZRAM_COMPRESS_LOW);
		atomic64_dec(&zram->stats.lowratio_pages);
	}

	if (zram_test_flag(zram, index, ZRAM_HUGE)) {
		zram_clear_flag(zram, index, ZRAM_HUGE);
		atomic64_dec(&zram->stats.huge_pages);
	}

#if defined(CONFIG_ZRAM_WRITEBACK)
#if defined(CONFIG_MI_MEMORY_FREEZE)
	if (zram_test_flag(zram, index, ZRAM_WRITEBACK_UNLIMITED)) {
		zram_clear_flag(zram, index, ZRAM_WRITEBACK_UNLIMITED);
		if (zram_test_flag(zram, index, ZRAM_WB)) {
			if (atomic64_read(&zram->stats.mf_bd_count) > 0)
				atomic64_dec(&zram->stats.mf_bd_count);
		}
		atomic64_sub(zram_get_obj_size(zram, index),
				&zram->stats.mfz_compr_data_size);
	}
#endif
	if (zram_test_flag(zram, index, ZRAM_WRITEBACK_PROTECTED)) {
		zram_clear_flag(zram, index, ZRAM_WRITEBACK_PROTECTED);
	}
#endif
	if (zram_test_flag(zram, index, ZRAM_INCOMPRESSIBLE))
		zram_clear_flag(zram, index, ZRAM_INCOMPRESSIBLE);

	zram_set_priority(zram, index, 0);

	if (zram_test_flag(zram, index, ZRAM_WB)) {
		zram_clear_flag(zram, index, ZRAM_WB);
		free_block_bdev(zram, zram_get_element(zram, index));
		goto out;
	}

	/*
	 * No memory is allocated for same element filled pages.
	 * Simply clear same page flag.
	 */
	if (zram_test_flag(zram, index, ZRAM_SAME)) {
		zram_clear_flag(zram, index, ZRAM_SAME);
		atomic64_dec(&zram->stats.same_pages);
		goto out;
	}

#ifdef CONFIG_ZRAM_WRITEBACK
	if (zram_test_flag(zram, index, ZRAM_PP_SLOT))
		zram_clear_flag(zram, index, ZRAM_PP_SLOT);
#endif
	handle = zram_get_handle(zram, index);
	if (!handle)
		return;

	zs_free(zram->mem_pool, handle);

	atomic64_sub(zram_get_obj_size(zram, index),
			&zram->stats.compr_data_size);
out:
	atomic64_dec(&zram->stats.pages_stored);
#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
	average_size(zram, atomic64_read(&zram->stats.pages_stored));
#endif
	zram_set_handle(zram, index, 0);
	zram_set_obj_size(zram, index, 0);
	WARN_ON_ONCE(zram->table[index].flags &
		~(1UL << ZRAM_LOCK | 1UL << ZRAM_UNDER_WB));
}

/*
 * Reads (decompresses if needed) a page from zspool (zsmalloc).
 * Corresponding ZRAM slot should be locked.
 */
static int zram_read_from_zspool(struct zram *zram, struct page *page,
				 u32 index)
{
	struct zcomp_strm *zstrm;
	unsigned long handle;
	unsigned int size;
	void *src, *dst;
	u32 prio;
	int ret;

	handle = zram_get_handle(zram, index);
	if (!handle || zram_test_flag(zram, index, ZRAM_SAME)) {
		unsigned long value;
		void *mem;

		value = handle ? zram_get_element(zram, index) : 0;
		mem = kmap_atomic(page);
		zram_fill_page(mem, PAGE_SIZE, value);
		kunmap_atomic(mem);
		return 0;
	}

	size = zram_get_obj_size(zram, index);

	if (size != PAGE_SIZE) {
		prio = zram_get_priority(zram, index);
		zstrm = zcomp_stream_get(zram->comps[prio]);
	}

	src = zs_map_object(zram->mem_pool, handle, ZS_MM_RO);
	if (size == PAGE_SIZE) {
		dst = kmap_atomic(page);
		memcpy(dst, src, PAGE_SIZE);
		kunmap_atomic(dst);
		ret = 0;
	} else {
		dst = kmap_atomic(page);
		ret = zcomp_decompress(zstrm, src, size, dst);
		kunmap_atomic(dst);
		zcomp_stream_put(zram->comps[prio]);
	}
	zs_unmap_object(zram->mem_pool, handle);
	return ret;
}

static int zram_read_page(struct zram *zram, struct page *page, u32 index,
			  struct bio *parent)
{
	int ret;

	zram_slot_lock(zram, index);
	if (!zram_test_flag(zram, index, ZRAM_WB)) {
		/* Slot should be locked through out the function call */
		ret = zram_read_from_zspool(zram, page, index);
		zram_slot_unlock(zram, index);
	} else {
		#if defined(CONFIG_ZRAM_WRITEBACK) && defined(CONFIG_MI_MEMORY_FREEZE)
				if (zram_test_flag(zram, index, ZRAM_WRITEBACK_UNLIMITED)) {
					atomic64_inc(&zram->stats.mf_bd_reads);
				}
		#endif
		/*
		 * The slot should be unlocked before reading from the backing
		 * device.
		 */
		zram_slot_unlock(zram, index);

		ret = read_from_bdev(zram, page, zram_get_element(zram, index),
				     parent);
	}

	/* Should NEVER happen. Return bio error if it does. */
	if (WARN_ON(ret < 0))
		pr_err("Decompression failed! err=%d, page=%u\n", ret, index);

	return ret;
}

/*
 * Use a temporary buffer to decompress the page, as the decompressor
 * always expects a full page for the output.
 */
static int zram_bvec_read_partial(struct zram *zram, struct bio_vec *bvec,
				  u32 index, int offset)
{
	struct page *page = alloc_page(GFP_NOIO);
	int ret;

	if (!page)
		return -ENOMEM;
	ret = zram_read_page(zram, page, index, NULL);
	if (likely(!ret))
		memcpy_to_bvec(bvec, page_address(page) + offset);
	__free_page(page);
	return ret;
}

static int zram_bvec_read(struct zram *zram, struct bio_vec *bvec,
			  u32 index, int offset, struct bio *bio)
{
	if (is_partial_io(bvec))
		return zram_bvec_read_partial(zram, bvec, index, offset);
	return zram_read_page(zram, bvec->bv_page, index, bio);
}

static int zram_write_page(struct zram *zram, struct page *page, u32 index)
{
	int ret = 0;
	unsigned long alloced_pages;
	unsigned long handle = -ENOMEM;
	unsigned int comp_len = 0;
	void *src, *dst, *mem;
	struct zcomp_strm *zstrm;
	unsigned long element = 0;
	enum zram_pageflags flags = 0;
#if defined(CONFIG_ZRAM_WRITEBACK)
	struct mem_cgroup *memcg = page_memcg(page);
	unsigned long long android_oem_data1;
#endif
	mem = kmap_atomic(page);
	if (page_same_filled(mem, &element)) {
		kunmap_atomic(mem);
		/* Free memory associated with this sector now. */
		flags = ZRAM_SAME;
		atomic64_inc(&zram->stats.same_pages);
		goto out;
	}
	kunmap_atomic(mem);

compress_again:
	zstrm = zcomp_stream_get(zram->comps[ZRAM_PRIMARY_COMP]);
	src = kmap_atomic(page);
	ret = zcomp_compress(zstrm, src, &comp_len);
	kunmap_atomic(src);

	if (unlikely(ret)) {
		zcomp_stream_put(zram->comps[ZRAM_PRIMARY_COMP]);
		pr_err("Compression failed! err=%d\n", ret);
		zs_free(zram->mem_pool, handle);
		return ret;
	}

	if (comp_len >= huge_class_size)
		comp_len = PAGE_SIZE;
	/*
	 * handle allocation has 2 paths:
	 * a) fast path is executed with preemption disabled (for
	 *  per-cpu streams) and has __GFP_DIRECT_RECLAIM bit clear,
	 *  since we can't sleep;
	 * b) slow path enables preemption and attempts to allocate
	 *  the page with __GFP_DIRECT_RECLAIM bit set. we have to
	 *  put per-cpu compression stream and, thus, to re-do
	 *  the compression once handle is allocated.
	 *
	 * if we have a 'non-null' handle here then we are coming
	 * from the slow path and handle has already been allocated.
	 */
	if (IS_ERR_VALUE(handle))
		handle = zs_malloc(zram->mem_pool, comp_len,
				__GFP_KSWAPD_RECLAIM |
				__GFP_NOWARN |
				__GFP_HIGHMEM |
				__GFP_MOVABLE);
	if (IS_ERR_VALUE(handle)) {
		zcomp_stream_put(zram->comps[ZRAM_PRIMARY_COMP]);
		atomic64_inc(&zram->stats.writestall);
		handle = zs_malloc(zram->mem_pool, comp_len,
				GFP_NOIO | __GFP_HIGHMEM |
				__GFP_MOVABLE);
		if (IS_ERR_VALUE(handle))
			return PTR_ERR((void *)handle);

		if (comp_len != PAGE_SIZE)
			goto compress_again;
		/*
		 * If the page is not compressible, you need to acquire the
		 * lock and execute the code below. The zcomp_stream_get()
		 * call is needed to disable the cpu hotplug and grab the
		 * zstrm buffer back. It is necessary that the dereferencing
		 * of the zstrm variable below occurs correctly.
		 */
		zstrm = zcomp_stream_get(zram->comps[ZRAM_PRIMARY_COMP]);
	}

	alloced_pages = zs_get_total_pages(zram->mem_pool);
	update_used_max(zram, alloced_pages);

	if (zram->limit_pages && alloced_pages > zram->limit_pages) {
		zcomp_stream_put(zram->comps[ZRAM_PRIMARY_COMP]);
		zs_free(zram->mem_pool, handle);
		return -ENOMEM;
	}

	dst = zs_map_object(zram->mem_pool, handle, ZS_MM_WO);

	src = zstrm->buffer;
	if (comp_len == PAGE_SIZE)
		src = kmap_atomic(page);
	memcpy(dst, src, comp_len);
	if (comp_len == PAGE_SIZE)
		kunmap_atomic(src);

	zcomp_stream_put(zram->comps[ZRAM_PRIMARY_COMP]);
	zs_unmap_object(zram->mem_pool, handle);
	atomic64_add(comp_len, &zram->stats.compr_data_size);
out:
	/*
	 * Free memory associated with this sector
	 * before overwriting unused sectors.
	 */
	zram_slot_lock(zram, index);
	zram_free_page(zram, index);

	if (comp_len == PAGE_SIZE) {
		zram_set_flag(zram, index, ZRAM_HUGE);
		atomic64_inc(&zram->stats.huge_pages);
		atomic64_inc(&zram->stats.huge_pages_since);
	}

	if (flags) {
		zram_set_flag(zram, index, flags);
		zram_set_element(zram, index, element);
	}  else {
		zram_set_handle(zram, index, handle);
		zram_set_obj_size(zram, index, comp_len);

		if((100 * (PAGE_SIZE - comp_len)/PAGE_SIZE) < glow_compress_ratio) {
			zram_set_flag(zram, index, ZRAM_COMPRESS_LOW);
			atomic64_inc(&zram->stats.lowratio_pages);
		}
	}

#if defined(CONFIG_ZRAM_WRITEBACK)
	if (memcg != NULL) {
		/**
		 * In Kernel 5.10 include/linux/memcontrol.h
		 * struct mem_cgroup on android_oem_data1 does
		 * not use an Array to store from memcg value
		 */
		/* android_oem_data1 = READ_ONCE(memcg->android_oem_data1[0]); */
		android_oem_data1 = READ_ONCE(memcg->android_oem_data1);

		if (android_oem_data1 == ANON_WRITEBACK_PROTECTED)
			zram_set_flag(zram, index, ZRAM_WRITEBACK_PROTECTED);

#if defined(CONFIG_MI_MEMORY_FREEZE)
		if (android_oem_data1 == ANON_WRITEBACK_UNLIMITED) {
			zram_set_flag(zram, index, ZRAM_WRITEBACK_UNLIMITED);
			atomic64_add(comp_len, &zram->stats.mfz_compr_data_size);
		}
#endif
	}
#endif

	zram_slot_unlock(zram, index);

	/* Update stats */
	atomic64_inc(&zram->stats.pages_stored);
#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
	average_size(zram, atomic64_read(&zram->stats.pages_stored));
	update_origin_pages_max(zram,
		atomic64_read(&zram->stats.pages_stored));
#endif
	return ret;
}

/*
 * This is a partial IO. Read the full page before writing the changes.
 */
static int zram_bvec_write_partial(struct zram *zram, struct bio_vec *bvec,
				   u32 index, int offset, struct bio *bio)
{
	struct page *page = alloc_page(GFP_NOIO);
	int ret;

	if (!page)
		return -ENOMEM;

	ret = zram_read_page(zram, page, index, bio);
	if (!ret) {
		memcpy_from_bvec(page_address(page) + offset, bvec);
		ret = zram_write_page(zram, page, index);
	}
	__free_page(page);
	return ret;
}

static int zram_bvec_write(struct zram *zram, struct bio_vec *bvec,
			   u32 index, int offset, struct bio *bio)
{
	if (is_partial_io(bvec))
		return zram_bvec_write_partial(zram, bvec, index, offset, bio);
	return zram_write_page(zram, bvec->bv_page, index);
}

#ifdef CONFIG_ZRAM_MULTI_COMP
/*
 * This function will decompress (unless it's ZRAM_HUGE) the page and then
 * attempt to compress it using provided compression algorithm priority
 * (which is potentially more effective).
 *
 * Corresponding ZRAM slot should be locked.
 */
static int zram_recompress(struct zram *zram, u32 index, struct page *page,
			   u32 threshold, u32 prio, u32 prio_max)
{
	struct zcomp_strm *zstrm = NULL;
	unsigned long handle_old;
	unsigned long handle_new;
	unsigned int comp_len_old;
	unsigned int comp_len_new;
	unsigned int class_index_old;
	unsigned int class_index_new;
	u32 num_recomps = 0;
	void *src, *dst;
	int ret;

	handle_old = zram_get_handle(zram, index);
	if (!handle_old)
		return -EINVAL;

	comp_len_old = zram_get_obj_size(zram, index);
	/*
	 * Do not recompress objects that are already "small enough".
	 */
	if (comp_len_old < threshold)
		return 0;

	ret = zram_read_from_zspool(zram, page, index);
	if (ret)
		return ret;

	class_index_old = zs_lookup_class_index(zram->mem_pool, comp_len_old);
	/*
	 * Iterate the secondary comp algorithms list (in order of priority)
	 * and try to recompress the page.
	 */
	for (; prio < prio_max; prio++) {
		if (!zram->comps[prio])
			continue;

		/*
		 * Skip if the object is already re-compressed with a higher
		 * priority algorithm (or same algorithm).
		 */
		if (prio <= zram_get_priority(zram, index))
			continue;

		num_recomps++;
		zstrm = zcomp_stream_get(zram->comps[prio]);
		src = kmap_atomic(page);
		ret = zcomp_compress(zstrm, src, &comp_len_new);
		kunmap_atomic(src);

		if (ret) {
			zcomp_stream_put(zram->comps[prio]);
			return ret;
		}

		class_index_new = zs_lookup_class_index(zram->mem_pool,
							comp_len_new);

		/* Continue until we make progress */
		if (class_index_new >= class_index_old ||
		    (threshold && comp_len_new >= threshold)) {
			zcomp_stream_put(zram->comps[prio]);
			continue;
		}

		/* Recompression was successful so break out */
		break;
	}

	/*
	 * We did not try to recompress, e.g. when we have only one
	 * secondary algorithm and the page is already recompressed
	 * using that algorithm
	 */
	if (!zstrm)
		return 0;

	if (class_index_new >= class_index_old) {
		/*
		 * Secondary algorithms failed to re-compress the page
		 * in a way that would save memory, mark the object as
		 * incompressible so that we will not try to compress
		 * it again.
		 *
		 * We need to make sure that all secondary algorithms have
		 * failed, so we test if the number of recompressions matches
		 * the number of active secondary algorithms.
		 */
		if (num_recomps == zram->num_active_comps - 1)
			zram_set_flag(zram, index, ZRAM_INCOMPRESSIBLE);
		return 0;
	}

	/* Successful recompression but above threshold */
	if (threshold && comp_len_new >= threshold)
		return 0;

	/*
	 * No direct reclaim (slow path) for handle allocation and no
	 * re-compression attempt (unlike in zram_write_bvec()) since
	 * we already have stored that object in zsmalloc. If we cannot
	 * alloc memory for recompressed object then we bail out and
	 * simply keep the old (existing) object in zsmalloc.
	 */
	handle_new = zs_malloc(zram->mem_pool, comp_len_new,
			       __GFP_KSWAPD_RECLAIM |
			       __GFP_NOWARN |
			       __GFP_HIGHMEM |
			       __GFP_MOVABLE);
	if (IS_ERR_VALUE(handle_new)) {
		zcomp_stream_put(zram->comps[prio]);
		return PTR_ERR((void *)handle_new);
	}

	dst = zs_map_object(zram->mem_pool, handle_new, ZS_MM_WO);
	memcpy(dst, zstrm->buffer, comp_len_new);
	zcomp_stream_put(zram->comps[prio]);

	zs_unmap_object(zram->mem_pool, handle_new);

	zram_free_page(zram, index);
	zram_set_handle(zram, index, handle_new);
	zram_set_obj_size(zram, index, comp_len_new);
	zram_set_priority(zram, index, prio);

	atomic64_add(comp_len_new, &zram->stats.compr_data_size);
	atomic64_inc(&zram->stats.pages_stored);

	return 0;
}

#define RECOMPRESS_IDLE		(1 << 0)
#define RECOMPRESS_HUGE		(1 << 1)

static ssize_t recompress_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t len)
{
	u32 prio = ZRAM_SECONDARY_COMP, prio_max = ZRAM_MAX_COMPS;
	struct zram *zram = dev_to_zram(dev);
	unsigned long nr_pages = zram->disksize >> PAGE_SHIFT;
	char *args, *param, *val, *algo = NULL;
	u32 mode = 0, threshold = 0;
	unsigned long index;
	struct page *page;
	ssize_t ret;

	args = skip_spaces(buf);
	while (*args) {
		args = next_arg(args, &param, &val);

		if (!val || !*val)
			return -EINVAL;

		if (!strcmp(param, "type")) {
			if (!strcmp(val, "idle"))
				mode = RECOMPRESS_IDLE;
			if (!strcmp(val, "huge"))
				mode = RECOMPRESS_HUGE;
			if (!strcmp(val, "huge_idle"))
				mode = RECOMPRESS_IDLE | RECOMPRESS_HUGE;
			continue;
		}

		if (!strcmp(param, "threshold")) {
			/*
			 * We will re-compress only idle objects equal or
			 * greater in size than watermark.
			 */
			ret = kstrtouint(val, 10, &threshold);
			if (ret)
				return ret;
			continue;
		}

		if (!strcmp(param, "algo")) {
			algo = val;
			continue;
		}
	}

	if (threshold >= huge_class_size)
		return -EINVAL;

	down_read(&zram->init_lock);
	if (!init_done(zram)) {
		ret = -EINVAL;
		goto release_init_lock;
	}

	if (algo) {
		bool found = false;

		for (; prio < ZRAM_MAX_COMPS; prio++) {
			if (!zram->comp_algs[prio])
				continue;

			if (!strcmp(zram->comp_algs[prio], algo)) {
				prio_max = min(prio + 1, ZRAM_MAX_COMPS);
				found = true;
				break;
			}
		}

		if (!found) {
			ret = -EINVAL;
			goto release_init_lock;
		}
	}

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto release_init_lock;
	}

	ret = len;
	for (index = 0; index < nr_pages; index++) {
		int err = 0;

		zram_slot_lock(zram, index);

		if (!zram_allocated(zram, index))
			goto next;

		if (mode & RECOMPRESS_IDLE &&
		    !zram_test_flag(zram, index, ZRAM_IDLE))
			goto next;

		if (mode & RECOMPRESS_HUGE &&
		    !zram_test_flag(zram, index, ZRAM_HUGE))
			goto next;

		if (zram_test_flag(zram, index, ZRAM_WB) ||
		    zram_test_flag(zram, index, ZRAM_UNDER_WB) ||
		    zram_test_flag(zram, index, ZRAM_SAME) ||
		    zram_test_flag(zram, index, ZRAM_INCOMPRESSIBLE))
			goto next;

		err = zram_recompress(zram, index, page, threshold,
				      prio, prio_max);
next:
		zram_slot_unlock(zram, index);
		if (err) {
			ret = err;
			break;
		}

		cond_resched();
	}

	__free_page(page);

release_init_lock:
	up_read(&zram->init_lock);
	return ret;
}
#endif

static void zram_bio_discard(struct zram *zram, struct bio *bio)
{
	size_t n = bio->bi_iter.bi_size;
	u32 index = bio->bi_iter.bi_sector >> SECTORS_PER_PAGE_SHIFT;
	u32 offset = (bio->bi_iter.bi_sector & (SECTORS_PER_PAGE - 1)) <<
			SECTOR_SHIFT;

	/*
	 * zram manages data in physical block size units. Because logical block
	 * size isn't identical with physical block size on some arch, we
	 * could get a discard request pointing to a specific offset within a
	 * certain physical block.  Although we can handle this request by
	 * reading that physiclal block and decompressing and partially zeroing
	 * and re-compressing and then re-storing it, this isn't reasonable
	 * because our intent with a discard request is to save memory.  So
	 * skipping this logical block is appropriate here.
	 */
	if (offset) {
		if (n <= (PAGE_SIZE - offset))
			return;

		n -= (PAGE_SIZE - offset);
		index++;
	}

	while (n >= PAGE_SIZE) {
		zram_slot_lock(zram, index);
		zram_free_page(zram, index);
		zram_slot_unlock(zram, index);
		atomic64_inc(&zram->stats.notify_free);
		index++;
		n -= PAGE_SIZE;
	}

	bio_endio(bio);
}

static void zram_bio_read(struct zram *zram, struct bio *bio)
{
	unsigned long start_time = bio_start_io_acct(bio);
	struct bvec_iter iter = bio->bi_iter;

	do {
		u32 index = iter.bi_sector >> SECTORS_PER_PAGE_SHIFT;
		u32 offset = (iter.bi_sector & (SECTORS_PER_PAGE - 1)) <<
				SECTOR_SHIFT;
		struct bio_vec bv = bio_iter_iovec(bio, iter);

		bv.bv_len = min_t(u32, bv.bv_len, PAGE_SIZE - offset);

		if (zram_bvec_read(zram, &bv, index, offset, bio) < 0) {
			atomic64_inc(&zram->stats.failed_reads);
			bio->bi_status = BLK_STS_IOERR;
			break;
		}
		flush_dcache_page(bv.bv_page);

		zram_slot_lock(zram, index);
		zram_accessed(zram, index);
		zram_slot_unlock(zram, index);

		bio_advance_iter_single(bio, &iter, bv.bv_len);
	} while (iter.bi_size);

	bio_end_io_acct(bio, start_time);
	bio_endio(bio);
}

static void zram_bio_write(struct zram *zram, struct bio *bio)
{
	unsigned long start_time = bio_start_io_acct(bio);
	struct bvec_iter iter = bio->bi_iter;

	do {
		u32 index = iter.bi_sector >> SECTORS_PER_PAGE_SHIFT;
		u32 offset = (iter.bi_sector & (SECTORS_PER_PAGE - 1)) <<
				SECTOR_SHIFT;
		struct bio_vec bv = bio_iter_iovec(bio, iter);

		bv.bv_len = min_t(u32, bv.bv_len, PAGE_SIZE - offset);

		if (zram_bvec_write(zram, &bv, index, offset, bio) < 0) {
			atomic64_inc(&zram->stats.failed_writes);
			bio->bi_status = BLK_STS_IOERR;
			break;
		}

		zram_slot_lock(zram, index);
		zram_accessed(zram, index);
		zram_slot_unlock(zram, index);

		bio_advance_iter_single(bio, &iter, bv.bv_len);
	} while (iter.bi_size);

	bio_end_io_acct(bio, start_time);
	bio_endio(bio);
}

/*
 * Handler function for all zram I/O requests.
 */
static blk_qc_t zram_submit_bio(struct bio *bio)
{
	struct zram *zram = bio->bi_disk->private_data;

	switch (bio_op(bio)) {
	case REQ_OP_READ:
		zram_bio_read(zram, bio);
		break;
	case REQ_OP_WRITE:
#ifdef CONFIG_ZRAM_KCOMPRESSD_OPT
		if (kcompressd_enabled() &&
		    !schedule_bio_write(zram, bio, zram_bio_write_engine))
			break;
#endif
		zram_bio_write(zram, bio);
		break;
	case REQ_OP_DISCARD:
	case REQ_OP_WRITE_ZEROES:
		zram_bio_discard(zram, bio);
		break;
	default:
		WARN_ON_ONCE(1);
		bio_endio(bio);
	}
	return BLK_QC_T_NONE;
}

static void zram_slot_free_notify(struct block_device *bdev,
				unsigned long index)
{
	struct zram *zram;

	zram = bdev->bd_disk->private_data;

	atomic64_inc(&zram->stats.notify_free);
	if (!zram_slot_trylock(zram, index)) {
		atomic64_inc(&zram->stats.miss_free);
		return;
	}

	zram_free_page(zram, index);
	zram_slot_unlock(zram, index);
}

static void zram_destroy_comps(struct zram *zram)
{
	u32 prio;

	for (prio = 0; prio < ZRAM_MAX_COMPS; prio++) {
		struct zcomp *comp = zram->comps[prio];

		zram->comps[prio] = NULL;
		if (!comp)
			continue;
		zcomp_destroy(comp);
		zram->num_active_comps--;
	}
}

static void zram_reset_device(struct zram *zram)
{
	down_write(&zram->init_lock);

	zram->limit_pages = 0;

	if (!init_done(zram)) {
		up_write(&zram->init_lock);
		return;
	}

	set_capacity(zram->disk, 0);
	part_stat_set_all(&zram->disk->part0, 0);

#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
	free_pages_life(zram->pages_life);
#endif

	/* I/O operation under all of CPU are done so let's free */
	zram_meta_free(zram, zram->disksize);
	zram->disksize = 0;
	zram_destroy_comps(zram);
	memset(&zram->stats, 0, sizeof(zram->stats));
	reset_bdev(zram);

	comp_algorithm_set(zram, ZRAM_PRIMARY_COMP, default_compressor);
	up_write(&zram->init_lock);
}

static ssize_t disksize_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	u64 disksize;
	struct zcomp *comp;
	struct zram *zram = dev_to_zram(dev);
	int err;
	u32 prio;

	disksize = memparse(buf, NULL);
	if (!disksize)
		return -EINVAL;

	down_write(&zram->init_lock);
	if (init_done(zram)) {
		pr_info("Cannot change disksize for initialized device\n");
		err = -EBUSY;
		goto out_unlock;
	}

	disksize = PAGE_ALIGN(disksize);
	if (!zram_meta_alloc(zram, disksize)) {
		err = -ENOMEM;
		goto out_unlock;
	}

	for (prio = 0; prio < ZRAM_MAX_COMPS; prio++) {
		if (!zram->comp_algs[prio])
			continue;

		comp = zcomp_create(zram->comp_algs[prio]);
		if (IS_ERR(comp)) {
			pr_err("Cannot initialise %s compressing backend\n",
			       zram->comp_algs[prio]);
			err = PTR_ERR(comp);
			goto out_free_comps;
		}

		zram->comps[prio] = comp;
		zram->num_active_comps++;
	}
#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
	zram->first_time = zram->last_time = 0;
#endif
	zram->disksize = disksize;
	set_capacity(zram->disk, zram->disksize >> SECTOR_SHIFT);

	revalidate_disk_size(zram->disk, true);
	up_write(&zram->init_lock);

	return len;

out_free_comps:
	zram_destroy_comps(zram);
	zram_meta_free(zram, disksize);
out_unlock:
	up_write(&zram->init_lock);
	return err;
}

static ssize_t reset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	int ret;
	unsigned short do_reset;
	struct zram *zram;
	struct block_device *bdev;

	ret = kstrtou16(buf, 10, &do_reset);
	if (ret)
		return ret;

	if (!do_reset)
		return -EINVAL;

	zram = dev_to_zram(dev);
	bdev = bdget_disk(zram->disk, 0);
	if (!bdev)
		return -ENOMEM;

	mutex_lock(&bdev->bd_mutex);
	/* Do not reset an active device or claimed device */
	if (bdev->bd_openers || zram->claim) {
		mutex_unlock(&bdev->bd_mutex);
		bdput(bdev);
		return -EBUSY;
	}

	/* From now on, anyone can't open /dev/zram[0-9] */
	zram->claim = true;
	mutex_unlock(&bdev->bd_mutex);

	/* Make sure all the pending I/O are finished */
	sync_blockdev(bdev);
	zram_reset_device(zram);
	revalidate_disk_size(zram->disk, true);
	bdput(bdev);

	mutex_lock(&bdev->bd_mutex);
	zram->claim = false;
	mutex_unlock(&bdev->bd_mutex);

	return len;
}

static int zram_open(struct block_device *bdev, fmode_t mode)
{
	int ret = 0;
	struct zram *zram;

	WARN_ON(!mutex_is_locked(&bdev->bd_mutex));

	zram = bdev->bd_disk->private_data;
	/* zram was claimed to reset so open request fails */
	if (zram->claim)
		ret = -EBUSY;

	return ret;
}

static const struct block_device_operations zram_devops = {
	.open = zram_open,
	.submit_bio = zram_submit_bio,
	.swap_slot_free_notify = zram_slot_free_notify,
	.owner = THIS_MODULE
};

static DEVICE_ATTR_WO(compact);
static DEVICE_ATTR_RW(disksize);
static DEVICE_ATTR_RO(initstate);
static DEVICE_ATTR_WO(reset);
static DEVICE_ATTR_WO(mem_limit);
static DEVICE_ATTR_WO(mem_used_max);
static DEVICE_ATTR_WO(idle);
static DEVICE_ATTR_WO(new);
static DEVICE_ATTR_RW(max_comp_streams);
static DEVICE_ATTR_RW(comp_algorithm);
#ifdef CONFIG_ZRAM_WRITEBACK
static DEVICE_ATTR_RW(backing_dev);
static DEVICE_ATTR_WO(writeback);
static DEVICE_ATTR_RW(writeback_limit);
static DEVICE_ATTR_RW(writeback_limit_enable);
#endif
#ifdef CONFIG_ZRAM_MULTI_COMP
static DEVICE_ATTR_RW(recomp_algorithm);
static DEVICE_ATTR_WO(recompress);
#endif

static struct attribute *zram_disk_attrs[] = {
	&dev_attr_disksize.attr,
	&dev_attr_initstate.attr,
	&dev_attr_reset.attr,
	&dev_attr_compact.attr,
	&dev_attr_mem_limit.attr,
	&dev_attr_mem_used_max.attr,
	&dev_attr_idle.attr,
	&dev_attr_new.attr,
	&dev_attr_max_comp_streams.attr,
	&dev_attr_comp_algorithm.attr,
#ifdef CONFIG_ZRAM_WRITEBACK
	&dev_attr_backing_dev.attr,
	&dev_attr_writeback.attr,
	&dev_attr_writeback_limit.attr,
	&dev_attr_writeback_limit_enable.attr,
	&dev_attr_pp_buckets.attr,
#endif
	&dev_attr_io_stat.attr,
	&dev_attr_mm_stat.attr,
	&dev_attr_idle_stat.attr,
	&dev_attr_new_stat.attr,
#ifdef CONFIG_ZRAM_WRITEBACK
	&dev_attr_bd_stat.attr,
#ifdef CONFIG_MI_MEMORY_FREEZE
	&dev_attr_mfz_idle_stat.attr,
	&dev_attr_mfz_enable.attr,
	&dev_attr_mfz_disk_quota.attr,
	&dev_attr_mfz_compr_data_size.attr,
#endif
#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
	&dev_attr_wb_pages_max.attr,
#endif
#endif
	&dev_attr_debug_stat.attr,
#ifdef CONFIG_ZRAM_MULTI_COMP
	&dev_attr_recomp_algorithm.attr,
	&dev_attr_recompress.attr,
#endif
#ifdef CONFIG_MIUI_ZRAM_MEMORY_TRACKING
	&dev_attr_time_list.attr,
	&dev_attr_pages_life.attr,
	&dev_attr_avg_size.attr,
	&dev_attr_origin_pages_max.attr,
	&dev_attr_low_compress_ratio.attr,
#endif
	NULL,
};

ATTRIBUTE_GROUPS(zram_disk);

/*
 * Allocate and initialize new zram device. the function returns
 * '>= 0' device_id upon success, and negative value otherwise.
 */
static int zram_add(void)
{
	struct zram *zram;
	struct request_queue *queue;
	int ret, device_id;
#ifdef CONFIG_ZRAM_WRITEBACK
	int count_index = 0;
#endif

	zram = kzalloc(sizeof(struct zram), GFP_KERNEL);
	if (!zram)
		return -ENOMEM;

	ret = idr_alloc(&zram_index_idr, zram, 0, 0, GFP_KERNEL);
	if (ret < 0)
		goto out_free_dev;
	device_id = ret;

	init_rwsem(&zram->init_lock);
#ifdef CONFIG_ZRAM_WRITEBACK
	spin_lock_init(&zram->wb_limit_lock);
	zram->writeback_pages = alloc_pages(GFP_KERNEL, MAX_WRITEBACK_ORDER);
	if (zram->writeback_pages)
		split_page(zram->writeback_pages, MAX_WRITEBACK_ORDER);
	else
		pr_err("Error allocating writeback batch pages for device %d\n",
			device_id);
	// Initialize the total_idle_count array to 0
	for (count_index = 0; count_index < ZRAM_WB_IDLE_MAX; count_index++) {
		atomic64_set(&zram->stats.total_idle_count[count_index], 0);
    }
#endif
	queue = blk_alloc_queue(NUMA_NO_NODE);
	if (!queue) {
		pr_err("Error allocating disk queue for device %d\n",
			device_id);
		ret = -ENOMEM;
		goto out_free_idr;
	}

#if defined(CONFIG_ZRAM_WRITEBACK) && defined(CONFIG_MI_MEMORY_FREEZE)
	zram->mfz_disk_quota = 0;
	zram->mfz_enable = 1;
#endif
	/* gendisk structure */
	zram->disk = alloc_disk(1);
	if (!zram->disk) {
		pr_err("Error allocating disk structure for device %d\n",
			device_id);
		ret = -ENOMEM;
		goto out_free_queue;
	}

	zram->disk->major = zram_major;
	zram->disk->first_minor = device_id;
	zram->disk->fops = &zram_devops;
	zram->disk->queue = queue;
	zram->disk->private_data = zram;
	snprintf(zram->disk->disk_name, 16, "zram%d", device_id);

	/* Actual capacity set using sysfs (/sys/block/zram<id>/disksize */
	set_capacity(zram->disk, 0);
	/* zram devices sort of resembles non-rotational disks */
	blk_queue_flag_set(QUEUE_FLAG_NONROT, zram->disk->queue);
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, zram->disk->queue);

	/*
	 * To ensure that we always get PAGE_SIZE aligned
	 * and n*PAGE_SIZED sized I/O requests.
	 */
	blk_queue_physical_block_size(zram->disk->queue, PAGE_SIZE);
	blk_queue_logical_block_size(zram->disk->queue,
					ZRAM_LOGICAL_BLOCK_SIZE);
	blk_queue_io_min(zram->disk->queue, PAGE_SIZE);
	blk_queue_io_opt(zram->disk->queue, PAGE_SIZE);
	zram->disk->queue->limits.discard_granularity = PAGE_SIZE;
	blk_queue_max_discard_sectors(zram->disk->queue, UINT_MAX);
	blk_queue_flag_set(QUEUE_FLAG_DISCARD, zram->disk->queue);

	/*
	 * zram_bio_discard() will clear all logical blocks if logical block
	 * size is identical with physical block size(PAGE_SIZE). But if it is
	 * different, we will skip discarding some parts of logical blocks in
	 * the part of the request range which isn't aligned to physical block
	 * size.  So we can't ensure that all discarded logical blocks are
	 * zeroed.
	 */
	if (ZRAM_LOGICAL_BLOCK_SIZE == PAGE_SIZE)
		blk_queue_max_write_zeroes_sectors(zram->disk->queue, UINT_MAX);

	blk_queue_flag_set(QUEUE_FLAG_STABLE_WRITES, zram->disk->queue);
	device_add_disk(NULL, zram->disk, zram_disk_groups);

	comp_algorithm_set(zram, ZRAM_PRIMARY_COMP, default_compressor);

	zram_debugfs_register(zram);
	pr_info("Added device: %s\n", zram->disk->disk_name);
	return device_id;

out_free_queue:
	blk_cleanup_queue(queue);
out_free_idr:
	idr_remove(&zram_index_idr, device_id);
out_free_dev:
	kfree(zram);
	return ret;
}

static int zram_remove(struct zram *zram)
{
	struct block_device *bdev;
	bool claimed;
#ifdef CONFIG_ZRAM_WRITEBACK
	int i;
#endif

	bdev = bdget_disk(zram->disk, 0);
	if (!bdev)
		return -ENOMEM;

	mutex_lock(&bdev->bd_mutex);
	if (bdev->bd_openers) {
		mutex_unlock(&bdev->bd_mutex);
		bdput(bdev);
		return -EBUSY;
	}

	claimed = zram->claim;
	if (!claimed)
		zram->claim = true;
	mutex_unlock(&bdev->bd_mutex);

	zram_debugfs_unregister(zram);

	if (claimed) {
		/*
		 * If we were claimed by reset_store(), del_gendisk() will
		 * wait until reset_store() is done, so nothing need to do.
		 */
		;
	} else {
		/* Make sure all the pending I/O are finished */
		sync_blockdev(bdev);
		zram_reset_device(zram);
	}
	bdput(bdev);

#ifdef CONFIG_ZRAM_WRITEBACK
	if (zram->writeback_pages)
		for (i = 0; i < MAX_WRITEBACK_SIZE; i++)
			__free_page(zram->writeback_pages + i);
#endif

	pr_info("Removed device: %s\n", zram->disk->disk_name);

	del_gendisk(zram->disk);
	blk_cleanup_queue(zram->disk->queue);

	/* del_gendisk drains pending reset_store */
	WARN_ON_ONCE(claimed && zram->claim);

	/*
	 * disksize_store() may be called in between zram_reset_device()
	 * and del_gendisk(), so run the last reset to avoid leaking
	 * anything allocated with disksize_store()
	 */
	zram_reset_device(zram);

	put_disk(zram->disk);
	kfree(zram);
	return 0;
}

/* zram-control sysfs attributes */

/*
 * NOTE: hot_add attribute is not the usual read-only sysfs attribute. In a
 * sense that reading from this file does alter the state of your system -- it
 * creates a new un-initialized zram device and returns back this device's
 * device_id (or an error code if it fails to create a new device).
 */
static ssize_t hot_add_show(struct class *class,
			struct class_attribute *attr,
			char *buf)
{
	int ret;

	mutex_lock(&zram_index_mutex);
	ret = zram_add();
	mutex_unlock(&zram_index_mutex);

	if (ret < 0)
		return ret;
	return scnprintf(buf, PAGE_SIZE, "%d\n", ret);
}
static struct class_attribute class_attr_hot_add =
	__ATTR(hot_add, 0400, hot_add_show, NULL);

static ssize_t hot_remove_store(struct class *class,
			struct class_attribute *attr,
			const char *buf,
			size_t count)
{
	struct zram *zram;
	int ret, dev_id;

	/* dev_id is gendisk->first_minor, which is `int' */
	ret = kstrtoint(buf, 10, &dev_id);
	if (ret)
		return ret;
	if (dev_id < 0)
		return -EINVAL;

	mutex_lock(&zram_index_mutex);

	zram = idr_find(&zram_index_idr, dev_id);
	if (zram) {
		ret = zram_remove(zram);
		if (!ret)
			idr_remove(&zram_index_idr, dev_id);
	} else {
		ret = -ENODEV;
	}

	mutex_unlock(&zram_index_mutex);
	return ret ? ret : count;
}
static CLASS_ATTR_WO(hot_remove);

static struct attribute *zram_control_class_attrs[] = {
	&class_attr_hot_add.attr,
	&class_attr_hot_remove.attr,
	NULL,
};
ATTRIBUTE_GROUPS(zram_control_class);

static struct class zram_control_class = {
	.name		= "zram-control",
	.class_groups	= zram_control_class_groups,
};

static int zram_remove_cb(int id, void *ptr, void *data)
{
	WARN_ON_ONCE(zram_remove(ptr));
	return 0;
}

static void destroy_devices(void)
{
	class_unregister(&zram_control_class);
	idr_for_each(&zram_index_idr, &zram_remove_cb, NULL);
	zram_debugfs_destroy();
	idr_destroy(&zram_index_idr);
	unregister_blkdev(zram_major, "zram");
	cpuhp_remove_multi_state(CPUHP_ZCOMP_PREPARE);
}

#if defined(CONFIG_ZRAM_WRITEBACK)
static u64
get_mem_cgroup_anno_writeback(struct cgroup_subsys_state *css,
			      struct cftype *cft)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);

	return memcg->android_oem_data1;
}

static int
set_mem_cgroup_anno_writeback(struct cgroup_subsys_state *css,
			      struct cftype *cft, u64 val)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);

	if (css->parent && val < __NR_ANON_WRITEBACK_FLAGS) {
		memcg->android_oem_data1 = val;
	}

	return 0;
}

static struct cftype mi_memcg_control[] = {
	{
		.name = "anno_writeback_control",
		.read_u64 = get_mem_cgroup_anno_writeback,
		.write_u64 = set_mem_cgroup_anno_writeback,
	},
	{}, /* terminate */
};
#endif

static int __init zram_init(void)
{
	int ret;

	BUILD_BUG_ON(__NR_ZRAM_PAGEFLAGS > BITS_PER_LONG);

	ret = cpuhp_setup_state_multi(CPUHP_ZCOMP_PREPARE, "block/zram:prepare",
				      zcomp_cpu_up_prepare, zcomp_cpu_dead);
	if (ret < 0)
		return ret;

	BUILD_BUG_ON(ZRAM_WB_IDLE_SHIFT + ZRAM_WB_IDLE_BITS_LEN > BITS_PER_LONG);

	ret = class_register(&zram_control_class);
	if (ret) {
		pr_err("Unable to register zram-control class\n");
		cpuhp_remove_multi_state(CPUHP_ZCOMP_PREPARE);
		return ret;
	}

	zram_debugfs_create();
	zram_major = register_blkdev(0, "zram");
	if (zram_major <= 0) {
		pr_err("Unable to get major number\n");
		class_unregister(&zram_control_class);
		cpuhp_remove_multi_state(CPUHP_ZCOMP_PREPARE);
		return -EBUSY;
	}

	while (num_devices != 0) {
		mutex_lock(&zram_index_mutex);
		ret = zram_add();
		mutex_unlock(&zram_index_mutex);
		if (ret < 0)
			goto out_error;
		num_devices--;
	}

#ifdef CONFIG_ZRAM_KSHRINK_SLABD
	zram_kshrink_slabd_init();
#endif

#if defined(CONFIG_ZRAM_WRITEBACK)
	WARN_ON(cgroup_add_legacy_cftypes(&memory_cgrp_subsys, mi_memcg_control));
#endif

#ifdef CONFIG_ZRAM_KCOMPRESSD_OPT
	kcompressd_init();
#endif
	return 0;

out_error:
	destroy_devices();
	return ret;
}

static void __exit zram_exit(void)
{
#ifdef CONFIG_ZRAM_KCOMPRESSD_OPT
	kcompressd_exit();
#endif
#ifdef CONFIG_ZRAM_KSHRINK_SLABD
	zram_kshrink_slabd_exit();
#endif
	destroy_devices();
}

module_init(zram_init);
module_exit(zram_exit);

module_param(num_devices, uint, 0);
MODULE_PARM_DESC(num_devices, "Number of pre-created zram devices");

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Nitin Gupta <ngupta@vflare.org>");
MODULE_DESCRIPTION("Compressed RAM Block Device");
