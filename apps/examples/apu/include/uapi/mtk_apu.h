/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2020 BayLibre
 */

#ifndef _UAPI_RPMSG_APU_H_
#define _UAPI_RPMSG_APU_H_

#include <linux/ioctl.h>
#include <linux/types.h>

struct apu_request {
	__u16 cmd;
	__u16 result;
	__u16 size_in;
	__u16 size_out;
	__u16 count;
	__u16 reserved;
	__u8 data[0];
};

struct apu_version {
	__u16 major;
	__u16 minor;
};

#define APU_VERSION_IOCTL	_IOWR(0xb7, 0x1, struct apu_version)
#define APU_SEND_REQ_IOCTL	_IOWR(0xb7, 0x2, struct apu_request)

#endif
