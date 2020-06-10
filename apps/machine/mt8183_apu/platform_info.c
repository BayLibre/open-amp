/*
 * Copyright (c) 2020 BayLibre SAS
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <metal/atomic.h>
#include <metal/device.h>
#include <metal/io.h>
#include <metal/irq.h>
#include <metal/sys.h>
#include <openamp/remoteproc.h>
#include <openamp/rpmsg_virtio.h>

#include "platform_info.h"
#include "rsc_table.h"

/* Remoteproc instance */
static struct remoteproc rproc_inst;

static struct remoteproc * platform_create_proc(int proc_index, int rsc_index)
{
	void *rsc_table;
	int rsc_size;
	int ret;
	metal_phys_addr_t pa;
	metal_phys_addr_t da;

	metal_unused( proc_index);
	rsc_table = get_resource_table(rsc_index, &rsc_size);

	if (!remoteproc_init(&rproc_inst, &mt8183_rproc_ops, NULL))
		return NULL;	

	/*
	 * Mmap resource table
	 * All other shared memories will be mapped using the resource table.
	 */
	pa = (metal_phys_addr_t)rsc_table;
	da = (metal_phys_addr_t)rsc_table;
	(void *)remoteproc_mmap(&rproc_inst, &pa, &da, rsc_size, 0, NULL);

	/*
	 * Disable the cache management in order to ease the development.
	 * TODO: Only disable the cache for some zone in order to get better
	 *       performances.
	 */
	xthal_set_region_attribute((void *)da,
				   0x10000000,
				   XCHAL_CA_BYPASS, 0);

	/* parse resource table to remoteproc */
	ret = remoteproc_set_rsc_table(&rproc_inst, rsc_table, rsc_size);
	if (ret) {
		metal_log(METAL_LOG_ERROR,
			  "Failed to intialize remoteproc\n");
		remoteproc_remove(&rproc_inst);
		return NULL;
	}

	metal_log(METAL_LOG_INFO, "Initialize remoteproc successfully.\n");

	return &rproc_inst;
}

int platform_init(int argc, char *argv[], void **platform)
{
	struct remote_resource_table *table;
	unsigned long proc_id = 0;
	unsigned long rsc_id = 0;
	struct remoteproc *rproc;
	int len;

	metal_unused(argc);
	metal_unused(argv);

	/* Initialize the logger */
	table = get_resource_table(0, &len);
	mt8183_trace_init((void *)table->logbuf_hdr.da, table->logbuf_hdr.len,
			  METAL_LOG_INFO);

	if (!platform) {
		metal_log(METAL_LOG_ERROR, 
			  "Failed to initialize platform,"
			  "NULL pointer to store platform data.\n");
		return -EINVAL;
	}

	/* Initialize HW system components */
	init_system();

	rproc = platform_create_proc(proc_id, rsc_id);
	if (!rproc) {
		metal_log(METAL_LOG_ERROR,
			  "Failed to create remoteproc device.\n");
		return -EINVAL;
	}
	*platform = rproc;

	return 0;
}

struct  rpmsg_device *
platform_create_rpmsg_vdev(void *platform, unsigned int vdev_index,
			   unsigned int role,
			   void (*rst_cb)(struct virtio_device *vdev),
			   rpmsg_ns_bind_cb ns_bind_cb)
{
	struct remoteproc *rproc = platform;
	struct rpmsg_virtio_device *rpmsg_vdev;
	struct virtio_device *vdev;
	struct metal_io_region *shbuf_io;
	unsigned long offset;
	int ret;

	rpmsg_vdev = metal_allocate_memory(sizeof(*rpmsg_vdev));
	if (!rpmsg_vdev)
		return NULL;

	shbuf_io = remoteproc_get_io_with_da(rproc, VDEV_BUFFER_DA, &offset);
	if (!shbuf_io) {
		metal_log(METAL_LOG_ERROR, "Failed to get vdev0buffer io\n");
		goto err_free_rpmsg_vdev;
	}

	metal_log(METAL_LOG_INFO, "creating remoteproc virtio\n");
	vdev = remoteproc_create_virtio(rproc, vdev_index, role, rst_cb);
	if (!vdev) {
		metal_log(METAL_LOG_ERROR,
			  "failed remoteproc_create_virtio\n");
		goto err_free_rpmsg_vdev;
	}

	metal_log(METAL_LOG_INFO, "initializing rpmsg vdev\n");
	ret =  rpmsg_init_vdev(rpmsg_vdev, vdev, ns_bind_cb,
				       shbuf_io, NULL);
	if (ret) {
		metal_log(METAL_LOG_ERROR, "failed rpmsg_init_vdev\n");
		goto err_rm_virtio;
	}

	metal_log(METAL_LOG_INFO, "initialized rpmsg vdev successfully\n");
	return rpmsg_virtio_get_rpmsg_device(rpmsg_vdev);

err_free_rpmsg_vdev:
	remoteproc_remove_virtio(rproc, vdev);
err_rm_virtio:
	metal_free_memory(rpmsg_vdev);

	return NULL;
}


int platform_poll(void *priv)
{
	metal_unused(priv);

	return 0;
}

void platform_release_rpmsg_vdev(struct rpmsg_device *rpdev)
{
	struct rpmsg_virtio_device *rpmsg_vdev;

	rpmsg_vdev = metal_container_of(rpdev, struct rpmsg_virtio_device, rdev);

	remoteproc_remove_virtio(NULL, rpmsg_vdev->vdev);
	metal_free_memory(rpmsg_vdev);
}

void platform_cleanup(void *platform)
{
	struct remoteproc *rproc = platform;

	if (rproc)
		remoteproc_remove(rproc);
	cleanup_system();
}
