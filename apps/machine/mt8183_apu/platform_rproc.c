/*
 * Copyright (c) 2020 BayLibre SAS
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <metal/atomic.h>
#include <metal/device.h>
#include <metal/irq.h>
#include <metal/sys.h>
#include <openamp/remoteproc.h>

#include "platform_info.h"
#include "rsc_table.h"

static unsigned long xtensa_phys_to_offset(struct metal_io_region *io,
					   metal_phys_addr_t phys)
{
	return phys - (metal_phys_addr_t)*io->physmap;
}

struct metal_io_ops xtensa_io = {
	.phys_to_offset = xtensa_phys_to_offset,
};

int irq_handler(int irq, void *data)
{
	struct remoteproc *rproc = data;
	metal_unused(irq);

	remoteproc_get_notification(rproc, RSC_NOTIFY_ID_ANY);

	return METAL_IRQ_HANDLED;
}

static struct remoteproc *
xtensa_rproc_init(struct remoteproc *rproc,
		  struct remoteproc_ops *ops, void *arg)
{
	metal_unused(arg);

	if (!rproc || !ops)
		return NULL;

	rproc->ops = ops;

	metal_irq_register(0, irq_handler, rproc);
	metal_irq_register(1, irq_handler, rproc);
	metal_irq_enable(0);
	metal_irq_enable(1);

	metal_log(METAL_LOG_INFO, "Successfully intialize remoteproc.\n");

	return rproc;
}

static void xtensa_rproc_remove(struct remoteproc *rproc)
{
	if (!rproc)
		return;

	metal_irq_disable(0);
	metal_irq_disable(1);
	metal_irq_unregister(0);
	metal_irq_unregister(1);
}

static void *
xtensa_rproc_mmap(struct remoteproc *rproc, metal_phys_addr_t *pa,
		  metal_phys_addr_t *da, size_t size,
		  unsigned int attribute, struct metal_io_region **io)
{
	struct remoteproc_mem *mem;
	metal_phys_addr_t lpa, lda;
	struct metal_io_region *tmpio;
	void *virt;

	lpa = *pa;
	lda = *da;

	if (lpa == METAL_BAD_PHYS && lda == METAL_BAD_PHYS)
		return NULL;
	if (lpa == METAL_BAD_PHYS)
		lpa = lda;
	if (lda == METAL_BAD_PHYS)
		lda = lpa;

	mem = metal_allocate_memory(sizeof(*mem));
	if (!mem)
		return NULL;

	tmpio = metal_allocate_memory(sizeof(*tmpio));
	if (!tmpio) {
		metal_free_memory(mem);
		return NULL;
	}

	remoteproc_init_mem(mem, NULL, lpa, lda, size, tmpio);

	/* va is the same as pa in this platform */
	metal_io_init(tmpio, (void *)mem->da, &mem->pa, size,
		      -1, attribute, &xtensa_io);

	remoteproc_add_mem(rproc, mem);

	*pa = lpa;
	*da = lda;
	if (io)
		*io = tmpio;

	virt = metal_io_phys_to_virt(tmpio, mem->pa);
	if (!virt) {
		metal_free_memory(tmpio);
		metal_free_memory(mem);
	}

	return virt;
}

static int mt8183_rproc_notify(struct remoteproc *rproc, uint32_t id)
{
	metal_unused(rproc);
	metal_unused(id);

	mt8183_write_reg(VPU_CORE_XTENSA_INT, 1);
	mt8183_write_reg(VPU_CORE_XTENSA_INT, 0);

	return 0;
}

struct remoteproc_ops mt8183_rproc_ops = {
	.init = xtensa_rproc_init,
	.remove = xtensa_rproc_remove,
	.mmap = xtensa_rproc_mmap,
	.notify = mt8183_rproc_notify,
	.start = NULL,
	.stop = NULL,
	.shutdown = NULL,
};
