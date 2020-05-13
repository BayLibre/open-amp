/*
 * Copyright (C) 2020 BayLibre SAS
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __RICH_IOT_NN_H__
#define __RICH_IOT_NN_H__

struct  apu_request {
	uint16_t id;
	uint16_t cmd;
	uint16_t result;
	uint16_t size_in;
	uint16_t size_out;
	uint16_t count;
	uint8_t data[0];
}__attribute__((packed));


#define APU_RPMSG_SERVICE "rpmsg-mt8183-apu0"
#define APU_CTRL_SRC 1
#define APU_CTRL_DST 1

#define APU_CTRL_VERSION 0xffff

#endif /* __RICH_IOT_NN_H__ */
