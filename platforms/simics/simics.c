/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <skiboot.h>
#include <device.h>
#include <lpc.h>
#include <console.h>
#include <opal.h>
#include <psi.h>

#include "../astbmc/astbmc.h"

static const struct slot_table_entry simics_phb0_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "GPU0",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry simics_phb0_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Slot2",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry simics_npu0_slots[] = {
	{
		.etype = st_npu_slot,
		.location = ST_LOC_NPU_GROUP(0),
		.name = "GPU0",
	},
	{
		.etype = st_npu_slot,
		.location = ST_LOC_NPU_GROUP(1),
		.name = "NO_GPU",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry simics_phb_table[] = {
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,0),
		.children = simics_phb0_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,1),
		.children = simics_phb0_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,2),
		.children = simics_npu0_slots,
	},
};

static bool simics_probe(void)
{
	if (!dt_find_by_path(dt_root, "/simics"))
		return false;

	/* Enable a UART if we find one in the device-tree */
	uart_init();

	if (uart_enabled())
		uart_setup_opal_console();
	else
		force_dummy_console();

	/* Fake a real time clock */
	fake_rtc_init();

	slot_table_init(simics_phb_table);

	return true;
}

DECLARE_PLATFORM(qemu) = {
	.name			= "Simics",
	.probe			= simics_probe,
	.pci_get_slot_info	= slot_table_get_slot_info,
};
