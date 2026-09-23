# SPDX-License-Identifier: GPL-2.0-only
zram-y	:=	zcomp.o zram_drv.o
zram-$(CONFIG_ZRAM_KCOMPRESSD_OPT)	+=	kcompressd.o
zram-$(CONFIG_ZRAM_KSHRINK_SLABD)	+=	kshrink_cos.o

obj-$(CONFIG_ZRAM)	+=	zram.o
