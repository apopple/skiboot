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

#ifndef __NPU_H
#define __NPU_H

#include <io.h>

/* Number of PEs supported */
#define NPU_NUM_OF_PES	4

/* Each brick has 2 MMIO BARs at the maximum. BAR0 is always used to
 * map the 128KB TL/DL registers. BAR1 is used to map either the PL or
 * the AT registers which are not exposed to the OS.
 */
#define NPU_BRICK_NUM_OF_BARS	2
#define NPU_BRICK_TL_BAR_SIZE	0x20000
#define NPU_BRICK_PL_BAR_SIZE	0x200000

/* Interrupt mapping
 *
 * NPU PHB doesn't support MSI interrupts. It only supports
 * 8 LSI interrupts: [0, 3] for bricks' DL blocks. [4, 5]
 * for reporting errors from DL blocks. [6, 7] for reporting
 * errors from TL blocks, NPCQs and AT.
 */
#define NPU_LSI_IRQ_COUNT	8
#define NPU_LSI_INT_DL0         0
#define NPU_LSI_INT_DL1         1
#define NPU_LSI_INT_DL2         2
#define NPU_LSI_INT_DL3         3
#define NPU_LSI_IRQ_MIN		0x7F0
#define NPU_LSI_IRQ_MAX		(NPU_LSI_IRQ_MIN + NPU_LSI_IRQ_COUNT - 1)
#define NPU_LSI_IRQ_BASE(chip, phb)	(P8_CHIP_IRQ_PHB_BASE(chip, phb) | NPU_LSI_IRQ_MIN)
#define NPU_IRQ_NUM(irq)		(irq & 0x7FF)

/* NPU device capability descriptor. All PCI capabilities is
 * organized as linked list. Each PCI capability has specific
 * hook to populate when initializing NPU device.
 */
struct npu_dev;

struct npu_dev_bar {
	uint32_t		flags;
	uint32_t		xscom;
	uint64_t		base;
	uint64_t		size;
	uint32_t		bar_sz;
	bool			trapped;
};

/* Each device contains 2 links. The device will be exposed as
 * standard PCIE device and the config space is emulated by skiboot.
 */
struct npu_dev {
	uint32_t		flags;
	uint32_t		index;
	uint64_t		xscom;
	void			*pl_base;
	uint64_t		pl_xscom_base;
	struct npu_dev_bar	bar;
	struct phb		*phb;

	/* Device and function numbers are allocated based on GPU
	 * association. Links to connected to the same GPU will be
	 * exposed as different functions of the same bus/device. */
	uint32_t		bdfn;

	/* The link@x node */
	struct dt_node		*dt_node;

	/* The GPU PCI device this NPU device is associated with */
	struct pci_device	*pd;

	struct npu		*npu;

	/* The emulated configuration space for this device */
	struct config_space	config_space;

	/* Which PHY lanes this device is associated with */
	uint16_t		lane_mask;

	/* Used to store the currently running procedure number for
	 * this device. */
	uint16_t		procedure_number;

	/* Used to store the step within a procedure that we are up
	 * to. */
	uint16_t		procedure_step;

	/* Arbitrary data used by each procedure to track status. */
	uint64_t		procedure_data;

	/* Used to timeout long running procedures. */
	unsigned long		procedure_tb;

	uint32_t		procedure_status;

	uint8_t			pe_num;

	/* NPU2 additions below */

	/* The bdfn of the real PCI device this link is associated
	 * with. On Nvlink2 the bdfn of the PCI device is used to map
	 * PE#. */
	uint32_t		real_bdfn;

	/* MMIO equivalent of xscom */
	uint64_t		*mmio;
};

/* NPU PHB descriptor */
struct npu {
	uint32_t		flags;
	uint32_t		index;
	uint32_t		chip_id;
	uint64_t		xscom_base;
	uint64_t		at_xscom;
	void			*at_regs;
	uint32_t		base_lsi;
	uint64_t		mm_base;
	uint64_t		mm_size;
	uint32_t		total_devices;
	struct npu_dev		*devices;

	/* IODA cache */
	uint64_t		lxive_cache[8];
	uint64_t		pce_cache[6];
	uint64_t		tve_cache[NPU_NUM_OF_PES];

	bool			tx_zcal_complete[2];
	bool			fenced;

	struct phb		phb;
};

static inline struct npu *phb_to_npu(struct phb *phb)
{
	return container_of(phb, struct npu, phb);
}

void npu_scom_init(struct npu_dev *dev);

int64_t npu_dev_procedure_read(struct config_space *cfg,
			       struct config_space_trap *trap,
			       uint32_t offset,
			       uint32_t size,
			       uint32_t *data);

int64_t npu_dev_procedure_write(struct config_space *cfg,
				struct config_space_trap *trap,
				uint32_t offset,
				uint32_t size,
				uint32_t data);

#define NPUDBG(p, fmt, a...)	prlog(PR_DEBUG, "NPU%d: " fmt, \
				      (p)->phb.opal_id, ##a)
#define NPUINF(p, fmt, a...)	prlog(PR_INFO,  "NPU%d: " fmt, \
				      (p)->phb.opal_id, ##a)
#define NPUERR(p, fmt, a...)	prlog(PR_ERR,   "NPU%d: " fmt, \
				      (p)->phb.opal_id, ##a)

#define NPUDEVDBG(p, fmt, a...)	NPUDBG((p)->npu, fmt, ##a)
#define NPUDEVINF(p, fmt, a...)	NPUINF((p)->npu, fmt, ##a)
#define NPUDEVERR(p, fmt, a...)	NPUERR((p)->npu, fmt, ##a)

#endif /* __NPU_H */
