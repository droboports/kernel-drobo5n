/*
 *  linux/arch/arm/mach-armadaxp/headsmp.S
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/linkage.h>
#include <linux/init.h>
#include <asm/memory.h>

	__INIT

/*
 * specific entry point for secondary CPUs.  This provides
 * a "holding pen" into which all secondary cores are held until we're
 * ready for them to initialise.
 */
ENTRY(axp_secondary_startup)
#ifdef CONFIG_CPU_ENDIAN_BE32
        /* convert CPU to big endian */
        .word 0x100f11ee /* mrc p15, 0, r0, c1, c0 */
        .word 0x800080e3 /* orr r0, r0, #0x80 */
        .word 0x100f01ee /* mcr p15, 0, r0, c1, c0 */
#endif
#ifdef CONFIG_BE8_ON_LE
        setend  be
#endif
	mrc	p15, 0, r0, c0, c0, 5
	and	r0, r0, #15
	adr	r4, 1f
	ldmia	r4, {r5, r6}
	sub	r4, r4, r5
	add	r6, r6, r4
#ifndef CONFIG_SHEEVA_ERRATA_ARM_CPU_4948
	/*
	 * Disable L0 on secondary CPU if flag set
	 */
	adr	r7, l0_disable_flag_addr
	ldr	r7, [r7]
	sub	r7, r7, #(PAGE_OFFSET - PLAT_PHYS_OFFSET)
	ldr	r7, [r7]
	cmp	r7, #0
	beq	l0_dis_skip
	mrc	p15, 1, r7, c15, c1, 0
	orr	r7, r7, #0x1
	mcr	p15, 1, r7, c15, c1, 0
l0_dis_skip:
#endif
#ifndef CONFIG_SHEEVA_ERRATA_ARM_CPU_5315
	/*
	 * Speculative prefetch on secondary CPU if flag set
	 * Auxiliary Functional Modes Control 0 Register
	 * Bit[7]: 0-Enable, 1-Disable (reset default)
	 */
	adr	r7, sp_enable_flag_addr
	ldr	r7, [r7]
	sub	r7, r7, #(PAGE_OFFSET - PLAT_PHYS_OFFSET)
	ldr	r7, [r7]
	cmp	r7, #0
	beq	sp_ena_skip
	mrc	p15, 1, r7, c15, c2, 0
	bic	r7, r7, #(1 << 7)
	mcr	p15, 1, r7, c15, c2, 0	
sp_ena_skip:
#endif
pen:
#if __LINUX_ARM_ARCH__ >= 7
	dsb
#else
	 mcr p15, 0, r0, c7, c10, 4
#endif
	ldr	r7, [r6]
	cmp	r7, r0
	bne	pen

	/*
	 * we've been released from the holding pen: secondary_stack
	 * should now contain the SVC stack for this core
	 */
	b	secondary_startup

1:	.long	.
	.long	pen_release
#ifndef CONFIG_SHEEVA_ERRATA_ARM_CPU_4948
l0_disable_flag_addr:
	.word	l0_disable_flag
#endif
#ifndef CONFIG_SHEEVA_ERRATA_ARM_CPU_5315
sp_enable_flag_addr:
	.word	sp_enable_flag
#endif
