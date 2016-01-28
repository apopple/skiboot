/* Copyright 2013-2015 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <skiboot.h>
#include <io.h>
#include <timebase.h>
#include <pci.h>
#include <pci-cfg.h>
#include <interrupts.h>
#include <opal.h>
#include <opal-api.h>
#include <cpu.h>
#include <device.h>
#include <ccan/str/str.h>
#include <ccan/array_size/array_size.h>
#include <affinity.h>
#include <npu-regs.h>
#include <npu-cfg.h>
#include <npu.h>
#include <lock.h>
#include <xscom.h>

/*
 * This file implements a library of PCI device config space emulation
 * functions that are common between NPU1 and NPU2.
 */
void config_space_read_raw(struct config_space *cfg,
			   uint32_t index,
			   uint32_t offset,
			   uint32_t size,
			   uint32_t *val)
{
	uint8_t *pcfg = cfg->config[index];
	uint32_t r, t, i;

	r = 0;
	for (i = 0; i < size; i++) {
		t = pcfg[offset + i];
		r |= (t << (i * 8));
	}

	*val = r;
}

void config_space_write_raw(struct config_space *cfg,
			    uint32_t index,
			    uint32_t offset,
			    uint32_t size,
			    uint32_t val)
{
	uint8_t *pcfg = cfg->config[index];
	uint32_t i;

	for (i = offset; i < (offset + size); i++) {
		pcfg[i] = val;
		val = (val >> 8);
	}
}

static int64_t config_space_check(uint32_t offset, uint32_t size)
{
	/* Sanity check */
	if (offset >= CONFIG_SPACE_SIZE)
		return OPAL_PARAMETER;
	if (offset & (size - 1))
		return OPAL_PARAMETER;

	return 0;
}

static struct config_space_trap *config_trap_check(struct config_space *cfg,
						   uint32_t offset,
						   uint32_t size,
						   bool read)
{
	struct config_space_trap *trap;

	list_for_each(&cfg->traps, trap, link) {
		if (read && !trap->read)
			continue;
		if (!read && !trap->write)
			continue;

		/* The requested region is overlapped with the one
		 * specified by the trap, to pick the trap and let it
		 * handle the request
		 */
		if (offset <= trap->end &&
		    (offset + size - 1) >= trap->start)
			return trap;
	}

	return NULL;
}

int64_t config_space_read(struct config_space *cfg,
			  uint32_t offset, uint32_t *data,
			  size_t size)
{
	struct config_space_trap *trap;
	int64_t ret;

	/* Data returned upon errors */
	*data = 0xffffffff;

	/* Sanity check */
	if (config_space_check(offset, size))
		return OPAL_PARAMETER;

	/* Retrieve trap */
	trap = config_trap_check(cfg, offset, size, true);
	if (trap) {
		ret = trap->read(cfg, trap, offset,
				 size, (uint32_t *)data);
		if (ret == OPAL_SUCCESS)
			return ret;
	}

	config_space_read_raw(cfg, CONFIG_SPACE_NORMAL, offset, size, data);

	return OPAL_SUCCESS;
}

int64_t config_space_write(struct config_space *cfg,
			   uint32_t offset, uint32_t data,
			   size_t size)
{
	struct config_space_trap *trap;
	uint32_t val, v, r, c, i;
	int64_t ret;

	/* Sanity check */
	if (config_space_check(offset, size))
		return OPAL_PARAMETER;

	/* Retrieve trap */
	trap = config_trap_check(cfg, offset, size, false);
	if (trap) {
		ret = trap->write(cfg, trap, offset,
				  size, (uint32_t)data);
		if (ret == OPAL_SUCCESS)
			return ret;
	}

	/* Handle read-only and W1C bits */
	val = data;
	for (i = 0; i < size; i++) {
		v = cfg->config[CONFIG_SPACE_NORMAL][offset + i];
		r = cfg->config[CONFIG_SPACE_RDONLY][offset + i];
		c = cfg->config[CONFIG_SPACE_W1CLR][offset + i];

		/* Drop read-only bits */
		val &= ~(r << (i * 8));
		val |= (r & v) << (i * 8);

		/* Drop W1C bits */
		val &= ~(val & ((c & v) << (i * 8)));
	}

	config_space_write_raw(cfg, CONFIG_SPACE_NORMAL, offset, size, val);

	return OPAL_SUCCESS;
}

/*
 * Add calls to trap reads and writes to a NPU config space.
 */
void config_space_add_trap(struct config_space *cfg, uint32_t start,
			   uint32_t size, void *data,
			   int64_t (*read)(struct config_space *,
					   struct config_space_trap *,
					   uint32_t,
					   uint32_t,
					   uint32_t *),
			   int64_t (*write)(struct config_space *,
					    struct config_space_trap *,
					    uint32_t,
					    uint32_t,
					    uint32_t))
{
	struct config_space_trap *trap;

	trap = zalloc(sizeof(struct config_space_trap));
	assert(trap);
	trap->start = start;
	trap->end   = start + size - 1;
	trap->read  = read;
	trap->write = write;
	trap->data  = data;
	list_add_tail(&cfg->traps, &trap->link);
}

void config_space_init(struct config_space *cfg)
{
	int j;

	/* Initialize config traps */
	list_head_init(&cfg->traps);

	/* Allocate config space */
	for (j = 0; j < CONFIG_SPACE_MAX; j++)
		cfg->config[j] = zalloc(CONFIG_SPACE_SIZE);
}
