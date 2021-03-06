/*
 * arch/arm/plat-armada/armadaxp_suspend.S
 *
 * CPU idle low level implementation for Marvell ARMADA-XP SoCs
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 *
 */
#include <linux/linkage.h>
#include <asm/assembler.h>
#include <mach/hardware.h>

#define GPIO_64_66_VALUE_REG			(INTER_REGS_BASE + 0x18180)
#define GPIO_64_66_CTRL_REG			(INTER_REGS_BASE + 0x18184)
#define MPP_CTRL_64_66_REG			(INTER_REGS_BASE + 0x18020)

ENTRY(armadaxp_powerdown)
	/* Save ARM registers */
	stmfd	sp!, {r4-r12, lr}		@ save registers on stack

	/*
	* Save the CP15 context
	*/
	mrc     p15, 0, r2, c1, c0, 0           @ save CP15 - CR
	mrc     p15, 0, r3, c3, c0, 0           @ save CP15 - DACR
	mrc     p15, 0, r4, c13, c0, 0          @ save CP15 - FCSE
	mrc     p15, 0, r5, c2, c0, 0           @ save CP15 - TTBR0
	mrc     p15, 0, r6, c13, c0, 1          @ save CP15 - context ID
	mrc     p15, 1, r7, c15, c1, 0          @ save CP15 - extra features
	mrc     p15, 0, r8, c1, c0, 1           @ save CP15 - Aux CR
	mov     r9, r13                         @ save resume SP
	stmfd   sp!, {r2-r9}

	mrc     p15, 0, r2, c2, c0, 1   @ save CP15 - TTBR1
	mrc	p15, 1, r3, c15, c2, 0	@ save CP15 - Aux Func Modes Ctrl 0
	mrc	p15, 1, r4, c15, c1, 2	@ save CP15 - Aux Debug Modes Ctrl 2
	mrc     p15, 1, r5, c15, c1, 1  @ save CP15 - Aux Debug Modes Ctrl 1
	mrc     p15, 0, r6, c9, c14, 0  @ save CP15 - PMC
	mrc     p15, 0, r7, c10, c2, 0  @ save CP15 - PRRR
	mrc     p15, 0, r8, c10, c2, 1  @ save CP15 - NMRR
	stmfd   sp!, {r2-r8}

	/*
	* Save the physical address of the resume SP
	*/
	mov     r0, sp
	bl      suspend_phys_addr
	ldr     r1, =suspend_saved_sp
#ifdef CONFIG_SMP
	mrc     p15, 0, r2, c0, c0, 5
	and     r2, r2, #15
	str     r0, [r1, r2, lsl #2]
#else
	str     r0, [r1]
#endif

	/*
	* Flush L1 DCache
	*/
	bl v7_flush_kern_cache_all

	/*
	* Issue a Data Synchronization Barrier instruction to ensure that all
	* state saving has been	completed.
	*/
	dsb

	/* Flush the DLB and wait ~7 usec*/
	ldr r2, =SDRAM_DLB_EVICT_REG
	ldr	r0, [r2]
	bic     r0, #0x000000FF
	str     r0, [r2]

	ldr r1, = 6000  /* WC freq =  1.6 Ghz, 2 cycles per loop */
1:	subs r1,r1,#1
	bne 1b

	/* Set DDR in battery backup mode
	 * It will exit self-refresh only on reset */
	ldr 	r2, =SDRAM_CONFIG_REG
	ldr	r0, [r2]
	bic     r0, #0x01000000
	str     r0, [r2]

	/* Prepare register for DDR Self refresh */
	ldr	r2, =(SDRAM_OPERATION_REG - INTER_REGS_BASE)
	ldr	r0, =INTER_REGS_BASE
	orr	r2, r2, r0
	ldr	r0, [r2]
#ifdef CONFIG_CPU_BIG_ENDIAN
	ldr	r3, =0x07000000
#else
	ldr	r3, =0x00000007
#endif
	orr	r0, r0, r3

	/*
	 * Write 0x1 then 0x7 through MPP 64-67 to PIC that controls power
	 * 0x1 - Power off all voltages;  0x7 - Acknowledge command
	 */
	ldr r3, =(MPP_CTRL_64_66_REG)
	ldr r4, =0x2000
	str r4, [r3]

	ldr r3, =(GPIO_64_66_VALUE_REG)
	ldr r4, =(GPIO_64_66_CTRL_REG)

	ldr r5, =0x1
	ldr r6, =0x0

	str r5, [r3]
	str r6, [r4]

	ldr r1, =200000000
	ldr r5, =0x7

	/*
	 * Wait between cmd (0x1) and cmd ack (0x7)
	 * TODO - Need to reduce this delay
	 */
1:	subs r1,r1,#1
	bne 1b

	/*
	 * Put Dram into self refresh. From here on we can perform
	 * 8 instructions to ensure executiion from I-Cache
	 */
	.align 5
	str	r0, [r2]

	/* Wait 100 cycles for DDR to enter self refresh */
	ldr r1, = 50
1:	subs r1,r1,#1
	bne 1b

	/* Issue the cmd ack. This will turn of the board */
	str r5, [r3]

	/* trap the processor */
	b .

ENDPROC(armadaxp_powerdown)

/*
* armadaxp_cpu_suspend: enter cpu deepIdle state
* input:
*/
ENTRY(armadaxp_cpu_suspend)
/* Save ARM registers */
	stmfd	sp!, {r4-r12, lr}				@ save registers on stack

/*
* Save the CP15 context
*/
	mrc     p15, 0, r2, c1, c0, 0			@ save CP15 - CR
	mrc     p15, 0, r3, c3, c0, 0			@ save CP15 - DACR
	mrc     p15, 0, r4, c13, c0, 0			@ save CP15 - FCSE
        mrc     p15, 0, r5, c2, c0, 0           @ save CP15 - TTBR0
	mrc     p15, 0, r6, c13, c0, 1			@ save CP15 - context ID
	mrc     p15, 1, r7, c15, c1, 0			@ save CP15 - extra features
	mrc     p15, 0, r8, c1, c0, 1			@ save CP15 - Aux CR
	mov     r9, r13							@ save resume SP
	stmfd   sp!, {r2-r9}
	mrc     p15, 0, r2, c2, c0, 1           @ save CP15 - TTBR1
	mrc	p15, 1, r3, c15, c2, 0				@ save CP15 - Aux Func Modes Ctrl 0
	mrc	p15, 1, r4, c15, c1, 2				@ save CP15 - Aux Debug Modes Ctrl 2
	mrc     p15, 1, r5, c15, c1, 1			@ save CP15 - Aux Debug Modes Ctrl 1
	mrc     p15, 0, r6, c9, c14, 0			@ save CP15 - PMC
	mrc     p15, 0, r7, c10, c2, 0			@ save CP15 - PRRR
	mrc     p15, 0, r8, c10, c2, 1			@ save CP15 - NMRR
	
        stmfd   sp!, {r2-r8}

/*
* TODO: Save Debug Registers
*/

/*
* Save the physical address of the resume SP
*/
        mov     r0, sp
        bl      suspend_phys_addr
        ldr     r1, =suspend_saved_sp
#ifdef CONFIG_SMP
        mrc     p15, 0, r2, c0, c0, 5
        and     r2, r2, #15
        str     r0, [r1, r2, lsl #2]
#else
        str     r0, [r1]
#endif

/*
* Flush L1 DCache
*/

#ifdef CONFIG_CPU_V6
	bl v6_flush_kern_cache_all
#elif CONFIG_CPU_V7
	bl v7_flush_kern_cache_all
#else
#error "CPU Arch version not defined!\n"
#endif

/* Prepare Deep Idle Function - Set PMU Configurations*/
	bl armadaxp_fabric_prepare_deepIdle

/*
* Issue a Data Synchronization Barrier instruction to ensure that all
* state saving has been	completed.
*/
#ifdef CONFIG_CPU_V6
	mcr     p15, 0, r0, c7, c10, 4	@ Data Synchronization Barrier
#elif defined (CONFIG_CPU_V7)
	dsb				@ Data Synchronization Barrier
#endif

/* Lock Semaphore */
	mrc	15, 0, r1, cr0, cr0, 5
	and	r1, r1, #15
	ldr	r4, =0xFBB20500
1:
	ldr	r2, [r4]
	and	r2, r2, #0xF
	cmp	r1, r2
	bne	1b

/* Disable SnoopEna */
	mrc	15, 0, r1, cr0, cr0, 5
	and	r1, r1, #15
	mov	r6, #1
	add	r7, r1, #24
	ldr	r2, =0xFBB20200
	ldr	r3, [r2]
	bic	r3, r3, r6, lsl r7
	str	r3, [r2]

/* Release Semaphore */
	ldr	r2, =0xFBB20500
	ldr 	r0, =0xff
	strb	r0, [r2]

dowfi:
/* WFI */
#ifdef CONFIG_CPU_V6
	mcr     p15, 0, r1, c7, c0, 4	@ wait for interrupt
#elif defined (CONFIG_CPU_V7)
	wfi				@ wait for interrupt
#endif

	/* After disabling the SnoopEna by SW regret is not allowed!! */
	b dowfi

#if 0
	/* if we reach this point then deepIdle returned from regret mode and cpu
	* state retained
	*/
	mov	r0, #1
	ldmfd   sp!, {r3-r8}
	ldmfd   sp!, {r2-r9}
	
	ldmfd   sp!, {r4-r12, pc}
#endif
ENDPROC(armadaxp_cpu_suspend)

/*
* armadaxp_cpu_resume: resume from cpu deepIdle state
* input:
*/
ENTRY(armadaxp_cpu_resume)

#ifdef CONFIG_CPU_ENDIAN_BE32
	/* convert CPU to big endian */
	.word 0x100f11ee /* mrc p15, 0, r0, c1, c0 */
	.word 0x800080e3 /* orr r0, r0, #0x80 */
	.word 0x100f01ee /* mcr p15, 0, r0, c1, c0 */
#endif
#ifdef CONFIG_CPU_ENDIAN_BE8
	setend  be
#endif

/* Lock Semaphore */
	mrc	15, 0, r1, cr0, cr0, 5
	and	r1, r1, #15
	ldr	r4, =0xD0020500
1:
	ldr	r2, [r4]
	and	r2, r2, #0xF
	cmp	r1, r2
	bne	1b

/* Enable SnoopEna */
	mrc	15, 0, r1, cr0, cr0, 5
	and	r1, r1, #15
	mov	r6, #1
	add	r7, r1, #24
	ldr	r2, =0xD0020200
	ldr	r3, [r2]
	orr	r3, r3, r6, lsl r7
	str	r3, [r2]

/* Release Semaphore */
	ldr	r2, =0xD0020500
	ldr 	r0, =0xff
	strb	r0, [r2]

#ifdef CONFIG_SMP
	adr     r0, suspend_saved_sp
	mrc     p15, 0, r1, c0, c0, 5
	and     r1, r1, #15
	ldr     r0, [r0, r1, lsl #2]    @ stack phys addr
#else
	ldr     r0, suspend_saved_sp            @ stack phys addr
#endif

	ldmfd   r0!, {r2-r8}
	mcr     p15, 0, r2, c2, c0, 1           @ restore CP15 - TTBR1
	mcr     p15, 1, r3, c15, c2, 0          @ restore CP15 - Aux Func Modes Ctrl 0
	mcr     p15, 1, r4, c15, c1, 2          @ restore CP15 - Aux Debug Modes Ctrl 2
	mcr     p15, 1, r5, c15, c1, 1          @ restore CP15 - Aux Debug Modes Ctrl 1
	mcr     p15, 0, r6, c9, c14, 0          @ restore CP15 - PMC
	mcr     p15, 0, r7, c10, c2, 0          @ restore CP15 - PRRR
	mcr     p15, 0, r8, c10, c2, 1          @ restore CP15 - NMRR
	ldmfd   r0!, {r2-r9}
	mcr	p15, 0, r8, c1, c0, 1		@ restore CP15 - Aux CR
	mcr	p15, 1, r7, c15, c1, 0		@ restore CP15 - extra features
	mcr	p15, 0, r4, c13, c0, 0		@ restore CP15 - FCSE
	mcr	p15, 0, r3, c3, c0, 0		@ restore CP15 - DACR

	/* load identity page table */
	ldr	r3, identity_page_table_phys
	mcr	p15, 0, r3, c2, c0, 0		@ set CP15 - TTBR
	mov	r3, #0
	mcr	p15, 0, r3, c13, c0, 1          @ set 0 in CP15 - context ID
	mcr	p15, 0, r2, c1, c0, 0		@ restore CP15 - CR  @enable mmu
	mrc     p15, 0, r3, c0, c0, 0           @ read id reg

	ldr	r3, resume2
	mov	pc, r3
ENDPROC(armadaxp_cpu_resume)

	/* stage 2 of the resume function that runs from PAGE_OFFSET virtual space */
ENTRY(armadaxp_cpu_resume2)	
	/* restore original page table*/

	mcr	p15, 0, r5, c2, c0, 0		@ restore CP15 - TTBR
	mcr	p15, 0, r6, c13, c0, 1          @ restore CP15 - context ID
	mcr     p15, 0, r0, c8, c7, 0           @ TLB invalidate
	mov	sp, r9				@ restore virtual sp
	mov	r0, #0

	ldmfd   sp!, {r4-r12, pc}               @ restore SVC registers

ENDPROC(armadaxp_cpu_resume2)
	
resume2:
	.long	armadaxp_cpu_resume2

suspend_saved_sp:
#ifdef CONFIG_SMP
	.rept	CONFIG_NR_CPUS
#endif
	.long	0	@ physical SP saved here
#ifdef CONFIG_SMP
	.endr
#endif
	.global identity_page_table_phys
identity_page_table_phys:
	.long	0
