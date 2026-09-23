/* SPDX-License-Identifier: GPL-2.0 */
/**
 * drivers/block/zram/internal.h - ZRAM Depend Func Wrapper
 * @Desc: Some of the functions we depend on cannot be directly
 *        applied to the kernel. which would break the KABI of
 *        the Android Common Kernel Tree. Therefore, we need to
 *        implement the functions that ZRAM depends internal.h.
 * @Author: zhaoyuenan <amktiao030215@gmail.com>
 */

#ifdef MODULE
static void zram_bio_add_page(struct bio *bio, struct page *page,
		unsigned int len, unsigned int off)
{
	struct bio_vec *bv = &bio->bi_io_vec[bio->bi_vcnt];

	WARN_ON_ONCE(bio_flagged(bio, BIO_CLONED));
	WARN_ON_ONCE(bio_full(bio, len));

	bv->bv_page = page;
	bv->bv_offset = off;
	bv->bv_len = len;

	bio->bi_iter.bi_size += len;
	bio->bi_vcnt++;

	if (!bio_flagged(bio, BIO_WORKINGSET) && unlikely(PageWorkingset(page)))
		bio_set_flag(bio, BIO_WORKINGSET);
}
#else
#define zram_bio_add_page __bio_add_page
#endif

/**
 * A simpler version of bvec_iter_advance(), @bytes should not span
 * across multiple bvec entries, i.e. bytes <= bv[i->bi_idx].bv_len
 */
static inline void bvec_iter_advance_single(const struct bio_vec *bv,
	struct bvec_iter *iter, unsigned int bytes)
{
	unsigned int done = iter->bi_bvec_done + bytes;

	if (done == bv[iter->bi_idx].bv_len) {
		done = 0;
		iter->bi_idx++;
	}

	iter->bi_bvec_done = done;
	iter->bi_size -= bytes;
}

/* @bytes should be less or equal to bvec[i->bi_idx].bv_len */
static inline void bio_advance_iter_single(const struct bio *bio,
	struct bvec_iter *iter, unsigned int bytes)
{
	iter->bi_sector += bytes >> 9;

	if (bio_no_advance_iter(bio))
		iter->bi_size -= bytes;
	else
		bvec_iter_advance_single(bio->bi_io_vec,
			iter, bytes);
}

/**
 * memcpy_from_bvec - copy data from a bvec
 * @bvec: bvec to copy from
 *
 * Must be called on single-page bvecs only.
 */
static inline void memcpy_from_bvec(char *to, struct bio_vec *bvec)
{
	memcpy_from_page(to, bvec->bv_page, bvec->bv_offset, bvec->bv_len);
}

/**
 * memcpy_to_bvec - copy data to a bvec
 * @bvec: bvec to copy to
 *
 * Must be called on single-page bvecs only.
 */
static inline void memcpy_to_bvec(struct bio_vec *bvec, const char *from)
{
	memcpy_to_page(bvec->bv_page, bvec->bv_offset, from, bvec->bv_len);
}
