// SPDX-License-Identifier: GPL-2.0-only
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/zstd.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/vmstat.h>
#include <linux/sched/loadavg.h>
#include <linux/mm.h>
#include <crypto/internal/scompress.h>
#include <../drivers/block/zram/zcomp.h>

#define ZSTD_MIN_LEVEL        1
#define ZSTD_MAX_LEVEL        22
#define MEM_USAGE_THRESH      75
#define CPU_USAGE_THRESH      75
#define LOW_MEM_MIN_LEVEL     1
#define LOW_MEM_MAX_LEVEL     3
#define HIGH_MEM_MIN_LEVEL    4
#define HIGH_MEM_MAX_LEVEL    9

static int __read_mostly compression_level = ZSTD_MIN_LEVEL;
static bool auto_adjust_enabled = true;
static struct task_struct *adjust_task;

static inline unsigned long get_total_mem(void)
{
    return totalram_pages() << PAGE_SHIFT;
}

static inline unsigned int get_mem_usage(void)
{
    unsigned long used = get_total_mem() - (global_zone_page_state(NR_FREE_PAGES) << PAGE_SHIFT);
    return (used * 100) / get_total_mem();
}

static inline unsigned int get_cpu_usage(void)
{
    unsigned long avg = avenrun[0] >> FSHIFT;
    unsigned int usage = avg * 100 / num_online_cpus();
    return min(usage, 100U);
}

static int calculate_compression_level(unsigned int mem, unsigned int cpu)
{
    if (mem < MEM_USAGE_THRESH && cpu < CPU_USAGE_THRESH) {
        return LOW_MEM_MAX_LEVEL - 
              (mem * (LOW_MEM_MAX_LEVEL - LOW_MEM_MIN_LEVEL) / MEM_USAGE_THRESH);
    }
    return HIGH_MEM_MAX_LEVEL - 
          (cpu * (HIGH_MEM_MAX_LEVEL - HIGH_MEM_MIN_LEVEL) / 100);
}

static int adjust_compression_thread(void *data)
{
    while (!kthread_should_stop()) {
        if (auto_adjust_enabled) {
            int new_level = clamp_val(
                calculate_compression_level(get_mem_usage(), get_cpu_usage()),
                ZSTD_MIN_LEVEL, ZSTD_MAX_LEVEL);

            if (new_level != compression_level) {
                compression_level = new_level;
                pr_info("ZSTDn: level=%d (mem=%u%%, cpu=%u%%)\n",
                       new_level, get_mem_usage(), get_cpu_usage());
            }
        }
        ssleep(5);
    }
    return 0;
}

static int set_compression_level(const char *val, const struct kernel_param *kp)
{
    int level;

    if (sysfs_streq(val, "auto")) {
        auto_adjust_enabled = true;
        return 0;
    }

    if (kstrtoint(val, 10, &level) || level < ZSTD_MIN_LEVEL || level > ZSTD_MAX_LEVEL)
        return -EINVAL;

    auto_adjust_enabled = false;
    compression_level = level;
    return 0;
}

static int get_compression_level(char *buffer, const struct kernel_param *kp)
{
    return sprintf(buffer, "%s\n", auto_adjust_enabled ? "auto" : "manual");
}

module_param_call(compression_level, set_compression_level, get_compression_level, 
                 &compression_level, 0644);

struct zstd_ctx {
    ZSTD_CCtx *cctx;
    ZSTD_DCtx *dctx;
    void *cwksp;
    void *dwksp;
};

static ZSTD_parameters get_zstd_params(void)
{
    return ZSTD_getParams(compression_level, 0, 0);
}

static int init_comp_ctx(struct zstd_ctx *ctx)
{
    const ZSTD_parameters params = get_zstd_params();
    const size_t wksp_size = ZSTD_estimateCCtxSize_usingCParams(params.cParams);
    size_t init_result;
    
    ctx->cwksp = vzalloc(wksp_size);
    if (!ctx->cwksp)
        return -ENOMEM;

    ctx->cctx = ZSTD_initStaticCCtx(ctx->cwksp, wksp_size);
    if (!ctx->cctx) {
        vfree(ctx->cwksp);
        return -EINVAL;
    }

    init_result = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_compressionLevel, compression_level);
    if (ZSTD_isError(init_result)) {
        vfree(ctx->cwksp);
        return -EINVAL;
    }

    init_result = ZSTD_CCtx_setPledgedSrcSize(ctx->cctx, ZSTD_CONTENTSIZE_UNKNOWN);
    if (ZSTD_isError(init_result)) {
        vfree(ctx->cwksp);
        return -EINVAL;
    }

    return 0;
}

static int init_decomp_ctx(struct zstd_ctx *ctx)
{
    const size_t wksp_size = ZSTD_estimateDCtxSize();
    size_t init_result;
    
    ctx->dwksp = vzalloc(wksp_size);
    if (!ctx->dwksp)
        return -ENOMEM;

    ctx->dctx = ZSTD_initStaticDCtx(ctx->dwksp, wksp_size);
    if (!ctx->dctx) {
        vfree(ctx->dwksp);
        return -EINVAL;
    }

    init_result = ZSTD_initDStream(ctx->dctx);
    if (ZSTD_isError(init_result)) {
        vfree(ctx->dwksp);
        return -EINVAL;
    }

    return 0;
}

static void free_comp_ctx(struct zstd_ctx *ctx)
{
    if (ctx->cwksp) {
        vfree(ctx->cwksp);
        ctx->cwksp = NULL;
        ctx->cctx = NULL;
    }
}

static void free_decomp_ctx(struct zstd_ctx *ctx)
{
    if (ctx->dwksp) {
        vfree(ctx->dwksp);
        ctx->dwksp = NULL;
        ctx->dctx = NULL;
    }
}

static void free_ctx_mem(struct zstd_ctx *ctx)
{
    free_comp_ctx(ctx);
    free_decomp_ctx(ctx);
}

static int zstd_init(struct crypto_tfm *tfm)
{
    struct zstd_ctx *ctx = crypto_tfm_ctx(tfm);
    int ret = init_comp_ctx(ctx);
    
    return ret ? ret : init_decomp_ctx(ctx);
}

static void zstd_exit(struct crypto_tfm *tfm)
{
    free_ctx_mem(crypto_tfm_ctx(tfm));
}

static int do_compress(struct crypto_tfm *tfm, const u8 *src, unsigned int slen,
                      u8 *dst, unsigned int *dlen)
{
    struct zstd_ctx *ctx = crypto_tfm_ctx(tfm);
    size_t out_len = ZSTD_compress2(ctx->cctx, dst, *dlen, src, slen);
    if (ZSTD_isError(out_len))
        return -EINVAL;
    
    *dlen = out_len;
    return 0;
}

static int do_decompress(struct crypto_tfm *tfm, const u8 *src, unsigned int slen,
                        u8 *dst, unsigned int *dlen)
{
    struct zstd_ctx *ctx = crypto_tfm_ctx(tfm);
    size_t out_len = ZSTD_decompressDCtx(ctx->dctx, dst, *dlen, src, slen);
    if (ZSTD_isError(out_len))
        return -EINVAL;
    
    *dlen = out_len;
    return 0;
}

static struct crypto_alg alg = {
    .cra_name       = "zstdn",
    .cra_driver_name= "zstdn-generic",
    .cra_flags      = CRYPTO_ALG_TYPE_COMPRESS,
    .cra_ctxsize    = sizeof(struct zstd_ctx),
    .cra_module     = THIS_MODULE,
    .cra_init       = zstd_init,
    .cra_exit       = zstd_exit,
    .cra_u          = {
        .compress = {
            .coa_compress   = do_compress,
            .coa_decompress = do_decompress
        }
    }
};

static void *alloc_scomp_ctx(struct crypto_scomp *tfm)
{
    struct zstd_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    int ret;

    if (!ctx)
        return ERR_PTR(-ENOMEM);

    ret = init_comp_ctx(ctx) ?: init_decomp_ctx(ctx);
    if (ret) {
        kfree(ctx);
        return ERR_PTR(ret);
    }
    return ctx;
}

static void scomp_free_ctx(struct crypto_scomp *tfm, void *ctx)
{
    struct zstd_ctx *zctx = ctx;
    free_comp_ctx(zctx);
    free_decomp_ctx(zctx);
    kfree(zctx);
}

static int scomp_compress(struct crypto_scomp *tfm, const u8 *src,
                         unsigned int slen, u8 *dst, unsigned int *dlen,
                         void *ctx)
{
    size_t out_len = ZSTD_compress2(((struct zstd_ctx *)ctx)->cctx,
                                   dst, *dlen, src, slen);
    if (ZSTD_isError(out_len))
        return -EINVAL;
    
    *dlen = out_len;
    return 0;
}

static int scomp_decompress(struct crypto_scomp *tfm, const u8 *src,
                           unsigned int slen, u8 *dst, unsigned int *dlen,
                           void *ctx)
{
    size_t out_len = ZSTD_decompressDCtx(((struct zstd_ctx *)ctx)->dctx,
                                       dst, *dlen, src, slen);
    if (ZSTD_isError(out_len))
        return -EINVAL;
    
    *dlen = out_len;
    return 0;
}

static struct scomp_alg scomp = {
    .alloc_ctx      = alloc_scomp_ctx,
    .free_ctx       = scomp_free_ctx,
    .compress       = scomp_compress,
    .decompress     = scomp_decompress,
    .base           = {
        .cra_name   = "zstdn",
        .cra_driver_name = "zstdn-scomp",
        .cra_module= THIS_MODULE,
    }
};

static int __init zstd_init_module(void)
{
    int ret;
    
    // 首先注册算法
    ret = crypto_register_alg(&alg);
    if (ret) {
        pr_err("Failed to register crypto alg\n");
        return ret;
    }

    // 然后注册 scomp
    ret = crypto_register_scomp(&scomp);
    if (ret) {
        pr_err("Failed to register scomp alg\n");
        crypto_unregister_alg(&alg);
        return ret;
    }

    adjust_task = kthread_run(adjust_compression_thread, NULL, "zstd_adjust");
    if (IS_ERR(adjust_task)) {
        adjust_task = NULL;
        pr_warn("Failed to start adjustment thread\n");
    }

    pr_info("ZSTDn compression algorithm registered\n");
    return 0;
}

static void __exit zstd_cleanup_module(void)
{
    if (adjust_task)
        kthread_stop(adjust_task);

    crypto_unregister_scomp(&scomp);
    crypto_unregister_alg(&alg);
    
    pr_info("ZSTDn compression algorithm unregistered\n");
}

module_init(zstd_init_module);
module_exit(zstd_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Zstandard Compression Algorithm");
MODULE_ALIAS_CRYPTO("zstdn");