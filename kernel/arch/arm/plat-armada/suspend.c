/*
 * arch/arm/plat-armada/cpuidle.c
 *
 * CPU idle implementation for Marvell ARMADA-XP SoCs
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 *
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/cpuidle.h>
#include <asm/io.h>
#include <asm/proc-fns.h>
#include <plat/cache-aurora-l2.h>
#include <mach/smp.h>
#include <asm/vfp.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/pgalloc.h>
#include <asm/sections.h>
#include <linux/export.h>
#include <asm/sections.h>

#include <../cpuidle.h>
#include "ctrlEnv/sys/mvCpuIfRegs.h"
#include "ctrlEnv/mvCtrlEnvLib.h"
#include "ctrlEnv/sys/mvCpuIf.h"
#include "mvOs.h"

void armadaxp_powerdown(void);
void armadaxp_cpu_resume(void);

/*
 * Store boot information used by bin header
 */
#define  BOOT_INFO_ADDR		(0x3000)
#define  BOOT_MAGIC_WORD	(0xDEADB002)
#define  REG_LIST_END		(0xFFFFFFFF)

#define SDRAM_WIN_BASE_REG(x)	(0x20180 + (0x8*x))
#define SDRAM_WIN_CTRL_REG(x)	(0x20184 + (0x8*x))
#define MAX_CS_COUNT		4

void armadaxp_store_boot_info(void)
{
	int *store_addr = (int *)BOOT_INFO_ADDR;
	int *resume_pc, win;

	store_addr = phys_to_virt(store_addr);
	resume_pc = virt_to_phys(armadaxp_cpu_resume);

	/*
	 * Store magic word indicating suspend to ram
	 * and return address
	 */
	*store_addr++ = (int)(BOOT_MAGIC_WORD);
	*store_addr++ = resume_pc;

	/*
	 * Now store registers that need to be proggrammed before
	 * comming back to linux. format is addr->value
	 */
	for (win = 0; win < 4; win++) {
		*store_addr++ = INTER_REGS_PHYS_BASE + SDRAM_WIN_BASE_REG(win);
		*store_addr++ = MV_REG_READ(SDRAM_WIN_BASE_REG(win));

		*store_addr++ = INTER_REGS_PHYS_BASE + SDRAM_WIN_CTRL_REG(win);
		*store_addr++ = MV_REG_READ(SDRAM_WIN_CTRL_REG(win));
	}

	/* Mark the end of the boot info*/
	*store_addr = REG_LIST_END;
}
/*
 * Save SOC & CPU register data before powering down board
 */
void armadaxp_suspend()
{
#if defined(CONFIG_VFP)
	vfp_save();
#endif
	aurora_l2_pm_enter();

	armadaxp_store_boot_info();

	armadaxp_powerdown();

	cpu_init();

	armadaxp_fabric_restore_deepIdle();

	aurora_l2_pm_exit();

#if defined(CONFIG_VFP)
	vfp_restore();
#endif
}
