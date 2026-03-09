#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>
#include "lz4p_decompress.h"
#include "lz4pdefs.h"

/* The function prototype as given in the assembly file */
void _lz4_encode_2gb(uint8_t **dst_ptr, size_t dst_size,
                    const uint8_t **src_ptr, const uint8_t *src_begin, size_t src_size,
                    lz4_hash_entry_t hash_table[LZ4_COMPRESS_HASH_ENTRIES],
                    int skip_final_literals);

/* The function implementation in C */
void _lz4_encode_2gb(uint8_t **dst_ptr, size_t dst_size,
                    const uint8_t **src_ptr, const uint8_t *src_begin, size_t src_size,
                    lz4_hash_entry_t hash_table[LZ4_COMPRESS_HASH_ENTRIES],
                    int skip_final_literals)
{
    uint8_t *dst;
    const uint8_t *src, *src_end, *dst_end;
    const uint8_t *src_end_minus_margin, *dst_end_minus_margin;
    size_t match_position;
    uint32_t match_first_4_bytes;
    size_t hash_index;
    lz4_hash_entry_t *hash_table_entry;
    size_t match_pos, match_value;
    const uint8_t *match_begin, *match_end;
    size_t match_length, literals_length;
    size_t remaining_src, remaining_dst;

    dst = *dst_ptr;
    src = *src_ptr;
    src_end = src + src_size;
    dst_end = dst + dst_size;
    src_end_minus_margin = src_end - LZ4_GOFAST_SAFETY_MARGIN;
    dst_end_minus_margin = dst_end - LZ4_GOFAST_SAFETY_MARGIN;

    if (src_end_minus_margin < src || dst_end_minus_margin < dst) {
        /* Not enough space either in src or dst */
        return;
    }

    while (src < src_end_minus_margin) {
        match_position = (size_t)(src - src_begin);
        match_first_4_bytes = *(uint32_t *)(src);
        hash_index = (match_first_4_bytes * LZ4_COMPRESS_HASH_MULTIPLY) >> LZ4_COMPRESS_HASH_SHIFT;
        hash_table_entry = &hash_table[hash_index];

        match_pos = hash_table_entry->pos;
        match_value = hash_table_entry->value;
        hash_table_entry->pos = match_position;
        hash_table_entry->value = match_first_4_bytes;

        if (match_value == match_first_4_bytes && match_position > match_pos &&
            match_position - match_pos < 0x10000) {
            /* Match found */
            match_begin = src_begin + match_pos;
            match_end = src + 4;

            /* Expand the match forward */
            while (src + 8 <= src_end_minus_margin && match_end + 8 <= match_begin + (match_position - match_pos)) {
                if (*(uint64_t *)(src) != *(uint64_t *)(match_end)) {
                    break;
                }
                src += 8;
                match_end += 8;
            }

            /* Expand the match backward */
            while (src > match_begin && match_end > src_begin) {
                if (*(src - 1) != *(match_end - 1)) {
                    break;
                }
                src--;
                match_end--;
            }

            match_length = (size_t)(match_end - match_begin);
            literals_length = (size_t)(match_begin - src);

            if (dst + literals_length + 3 > dst_end_minus_margin) {
                /* Not enough space in dst */
                return;
            }

            /* Write the match to dst */
            if (literals_length >= 15) {
                *dst++ = 0xF0 | ((match_length - 4) & 0x0F);
                literals_length -= 15;
                while (literals_length >= 255) {
                    *dst++ = 255;
                    literals_length -= 255;
                }
                *dst++ = (uint8_t)literals_length;
            } else {
                *dst++ = (uint8_t)(literals_length << 4) | ((match_length - 4) & 0x0F);
            }

            /* Copy literals */
            memcpy(dst, src, literals_length);
            dst += literals_length;
            src += literals_length;

            /* Write match distance */
            *(uint16_t *)dst = (uint16_t)(match_position - match_pos);
            dst += 2;

            src = match_end;
        } else {
            src++;
        }
    }

    /* Write trailing literals */
    if (!skip_final_literals) {
        remaining_src = src_end - src;
        remaining_dst = dst_end - dst;

        if (remaining_src > remaining_dst) {
            return;
        }

        if (remaining_src > 15) {
            *dst++ = 0xF0;
            remaining_src -= 15;
            while (remaining_src >= 255) {
                *dst++ = 255;
                remaining_src -= 255;
            }
            *dst++ = (uint8_t)remaining_src;
        } else {
            *dst++ = (uint8_t)(remaining_src << 4);
        }

        memcpy(dst, src, remaining_src);
        dst += remaining_src;
    }

    /* Update the pointers */
    *dst_ptr = dst;
    *src_ptr = src;
}