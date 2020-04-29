/*
 * Copyright (c) 2020 BayLibre SAS
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <metal/sys.h>
#include <metal/irq.h>
#include "platform_info.h"

int init_system(void)
{
	struct metal_init_params metal_param = METAL_INIT_DEFAULTS;

	/* Low level abstraction layer for openamp initialization */
	metal_init(&metal_param);

	/* configure the interrupt controller */
	mt8183_irq_init();
	
	return 0;
}

void cleanup_system()
{
	metal_finish();
}
