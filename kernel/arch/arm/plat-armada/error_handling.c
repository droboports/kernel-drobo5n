/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/irq.h>
#include <linux/notifier.h>
#include <linux/module.h>
#include <asm/io.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#define MAX_ERRORS 8
#define COHERENCY_FBRIC_ERROR_MASK 0x2025c
#define COHERENCY_FBRIC_ERROR_CAUSE 0x20258
#define COHERENCY_FBRIC_LOCAL_CAUSE 0x20260
#define SOC_MAIN_INTR_ERROR_CAUSE 0x20a20

#define AXP_SOC_MAIN_INT_ERR_MASK(cpu)    ((0x218c0+(cpu)*0x100))

#define AXP_COHERENCY_FBRIC_LCL_INT_MASK(cpu)    ((0x218c4+(cpu)*0x100))
#define COHERENCY_FBRIC_ERROR_SUM_MASK 	(0x1 << 27)

struct error_notification{
	bool    mbus_error;
        u32     cause_register;
};

struct error_info {
       struct work_struct error_handling_work;
	bool	mbus_error;
        u32	cause_register;
};

struct axp_error_info_struct{
        struct error_info axp_error_info_array[8];
        int head;
        int tail;
	int size;
	spinlock_t	lock;
};

struct axp_error_info_struct axp_error_info;

struct unit_error{
	/*the unit_cause_reg, unit_maks_reg, and mask values represent
        the cause, and mask registers, in addition to the maks that are responsible
	for enabling / masking the interrupt, it's also used
	for acking the the interrupt when it's received */
	u32 unit_cause_reg;
	u32 unit_mask_reg;
	u32 mask;
	/*the place in the casue register
	are represnted with the error value */
	u32 error_val;
	struct list_head list; /* kernel's list structure */
};

struct unit_error mbusunit_error_list;
BLOCKING_NOTIFIER_HEAD(armadaxp_error_notifier_chain);
EXPORT_SYMBOL(armadaxp_error_notifier_chain);
static struct workqueue_struct * error_workqueue;



static void error_notifier(struct work_struct *work)
{
	struct error_notification nt;
	struct error_info *temp_error=container_of(work, struct error_info, error_handling_work);
	nt.mbus_error = temp_error->mbus_error;
	nt.cause_register = temp_error->cause_register;
	blocking_notifier_call_chain(&armadaxp_error_notifier_chain,0,&nt);
	return;
}


/*
this function is a helper function to handle the Mbus unit error without
having to modify any of the MBUS unit drivers.

how to use:
Each driver (or even any other module), should pass a reg offset,a mask, and an error ID.
the mask will be writen to the  register offset  to enabled the dersired error in the unit level.


the ID will represet the error offset ( i.e. bit 0 will be represented as 0) in the Main interrupt
error casue ( offset 20A20 in AXP based on table 37 in the Spec).
in case of an ISR, the mask will be used to ack the interrupt
in the unit level and this also means that next error will not trigger an interrupt !!!

for example:
to enable errors from CESA, which will trigger bits 0x7f at register 0x908c8, and can be unmasked by 0x908cc, while
eventually setting bit 0 at the main interrupt error cause, the following IO_error_register call should be used:  
IO_error_register(0x7f,0x908c8,0x908cc,0x0);
*/

int IO_error_register(u32 mask,u32 unit_cause_reg, u32 unit_mask_reg, int error_val){

	struct unit_error *new_error;
	int cpu;
	new_error = kmalloc(sizeof(struct unit_error),GFP_KERNEL);
	new_error->unit_cause_reg=unit_cause_reg;
	new_error->unit_mask_reg=unit_mask_reg;
	new_error->mask=mask;
	new_error->error_val=error_val;
	INIT_LIST_HEAD(&new_error->list);
	list_add(&new_error->list,&mbusunit_error_list.list);

	/*unamsk for each possbile CPU, this can overriden by setting affinity*/	
	for_each_possible_cpu(cpu){
		writel(( 0x1 << error_val) , INTER_REGS_BASE | AXP_SOC_MAIN_INT_ERR_MASK(cpu));
	}
	
	/*write the mask to the reg passed by the unit
	 assuming that this will unmaks the desired errors per unit*/
	writel(mask,INTER_REGS_BASE | unit_mask_reg);
	return 0;
}
EXPORT_SYMBOL(IO_error_register);



static irqreturn_t armadaxp_mbusunit_error_isr(int irq, void *arg){

	u32 error_cause;
	u32 cause_value;
	unsigned long flags;
	struct unit_error* entry;
	error_cause=readl(INTER_REGS_BASE | SOC_MAIN_INTR_ERROR_CAUSE);
	list_for_each_entry(entry,&mbusunit_error_list.list,list){
		/*will have to pass the type of error to
		  differentiate MBUs and "system" errors
		*/
		if(error_cause == (0x1 << entry->error_val)){
			spin_lock_irqsave(&axp_error_info.lock,flags);
			if(((axp_error_info.head + 1) % MAX_ERRORS )== axp_error_info.tail)
				panic(" ARMADA XP error handler: ERROR RATE is too high");
			axp_error_info.axp_error_info_array[axp_error_info.head].cause_register=error_cause;
			axp_error_info.axp_error_info_array[axp_error_info.head].mbus_error=1;
			/*the actual ack*/
			cause_value=readl(INTER_REGS_BASE | entry->unit_cause_reg);
			/*very important to notice that we mask the error after first time it happens,
			this will resolve the case that no one acks the error, which will compromise the
			overall system stability ( i.e. interrupt without ack ) which is highly undesirable.
			the "customized" function, registered with the notification call chain can
			unmask the error, which will cause it to happen again. */
			writel(((~cause_value) & entry->mask), (INTER_REGS_BASE | entry->unit_mask_reg));
		
                queue_work(error_workqueue, (struct work_struct *) &axp_error_info.axp_error_info_array[axp_error_info.head] );
		axp_error_info.head = (axp_error_info.head + 1) % MAX_ERRORS;
			spin_unlock_irqrestore(&axp_error_info.lock,flags);
		}
	}
		return IRQ_HANDLED;
}


static irqreturn_t armadaxp_error_event_isr(int irq, void *arg)
{
	u32 error_cause, fabric_error_cause;
	unsigned long flags;
        error_cause=readl(INTER_REGS_BASE | COHERENCY_FBRIC_LOCAL_CAUSE);
	fabric_error_cause = readl(INTER_REGS_BASE | COHERENCY_FBRIC_ERROR_CAUSE);
	if(error_cause & 0x8000000){
		spin_lock_irqsave(&axp_error_info.lock,flags);
		if(((axp_error_info.head + 1) % MAX_ERRORS )== axp_error_info.tail)
			panic(" ARMADA XP error handler: ERROR RATE is too high");
		fabric_error_cause = readl(INTER_REGS_BASE | COHERENCY_FBRIC_ERROR_CAUSE);
		axp_error_info.axp_error_info_array[axp_error_info.head].cause_register=fabric_error_cause;
		axp_error_info.axp_error_info_array[axp_error_info.head].mbus_error=0;
		/*very important to notice that we mask the error after first time it happens,
		this will resolve the case that no one acks the error, which will compromise the
		overall system stability ( i.e. interrupt without ack ) which is highly undesirable.
		the "customized" function, registered with the notification call chain can
		unmask the error, which will cause it to happen again. */
		writel(((~fabric_error_cause) & readl(INTER_REGS_BASE | COHERENCY_FBRIC_ERROR_MASK) ), (INTER_REGS_BASE | COHERENCY_FBRIC_ERROR_MASK));
	
		writel(~(fabric_error_cause) ,INTER_REGS_BASE | COHERENCY_FBRIC_ERROR_CAUSE);

		queue_work(error_workqueue,(struct work_struct *) &axp_error_info.axp_error_info_array[axp_error_info.head] );
		axp_error_info.head = (axp_error_info.head + 1) % MAX_ERRORS;
		spin_unlock_irqrestore(&axp_error_info.lock,flags);
		return IRQ_HANDLED;
	}else
		return IRQ_NONE;
}

static int armadaxp_error_event(struct notifier_block *this, unsigned long event,
         void *ptr)
{
	unsigned long flags;
	spin_lock_irqsave(&axp_error_info.lock,flags);
	printk("ARMADA XP error handler is reading value %X from offset %X \n",axp_error_info.axp_error_info_array[axp_error_info.tail].cause_register,
								axp_error_info.axp_error_info_array[axp_error_info.tail].mbus_error==1?0x20A20:0x20258);
	axp_error_info.tail = (axp_error_info.tail + 1) % MAX_ERRORS;
	spin_unlock_irqrestore(&axp_error_info.lock,flags);

        return NOTIFY_DONE;

}

static struct notifier_block error_handling_block = {
        .notifier_call  = armadaxp_error_event,
};

static int __init errorhandling_notification_setup(void)
{
	int err;
	u32 temp_reg;
	int cpu;
	int i;
	/*
		nothing specal is need to enabling error handling first
	*/
	err = request_irq(IRQ_AURORA_MP, armadaxp_error_event_isr,IRQF_SHARED , "Armada Error Handler", armadaxp_error_event_isr );
	if(err)
	{
		printk("opps: request_irq failed to requestin IRQ# %d, returning now ! \n", IRQ_AURORA_MP);
		return err;
	}
	/*clear the error casue register, and unmask interrupt
	   to trigger the coherency fabric error interrupt */
	writel(0x0,INTER_REGS_BASE | COHERENCY_FBRIC_ERROR_CAUSE);

	/*ERRATA 6349 need to be taken into consideration*/
#ifdef CONFIG_ARMADA_XP_REV_A0
	writel(0xFFF0FFFF ,INTER_REGS_BASE |COHERENCY_FBRIC_ERROR_MASK);
#else
	writel(0xFFFFFFFF ,INTER_REGS_BASE |COHERENCY_FBRIC_ERROR_MASK);
#endif
	/*bit 27 in COHERENCY_FBRIC_LOCAL_CAUSE is responsible for the errors from COHERENCY_FBRIC_ERROR_CAUSE
	 thus must unmaks it in the per cpu Coherency Fabric Local Interrupt Mask Register */
 	
	for_each_possible_cpu(cpu){
		temp_reg=readl( INTER_REGS_BASE | AXP_COHERENCY_FBRIC_LCL_INT_MASK(cpu));
                writel( temp_reg | COHERENCY_FBRIC_ERROR_SUM_MASK , INTER_REGS_BASE | AXP_COHERENCY_FBRIC_LCL_INT_MASK(cpu));
        }

		/* the MBUS units part of the error handling setup*/
	INIT_LIST_HEAD(&mbusunit_error_list.list);
	err = request_irq(IRQ_AURORA_SOC_ERROR, armadaxp_mbusunit_error_isr,IRQF_DISABLED , "Armada MBUS unit Error Handler", NULL );
        if(err)
        {
		 printk("opps: request_irq failed to requestin IRQ# %d, returning now ! \n", IRQ_AURORA_SOC_ERROR);
                return err;
        }
	/*setup the axp_error_info struct */
	axp_error_info.head=0;
	axp_error_info.tail=0;
	spin_lock_init(&axp_error_info.lock);

	  /* Setup notifier */
        blocking_notifier_chain_register(&armadaxp_error_notifier_chain, &error_handling_block);
	error_workqueue=create_workqueue("error handling");

	for (i=0; i < MAX_ERRORS; i++)
		INIT_WORK(&(axp_error_info.axp_error_info_array[i].error_handling_work),error_notifier);

	// IO_error_register(0x7f,0x908c8,0x908cc,0x0);	
	printk("ARMADA XP error handling module was loaded \n");
        return 0;
}
postcore_initcall(errorhandling_notification_setup);
