/* Copyright 2013-2016 IBM Corp.
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

#ifndef __NPU2_H
#define __NPU2_H

/* Debugging options */
#define NPU2DBG(p, fmt, a...)	prlog(PR_DEBUG, "NPU%d: " fmt, \
				      (p)->phb.opal_id, ##a)
#define NPU2INF(p, fmt, a...)	prlog(PR_INFO,  "NPU%d: " fmt, \
				      (p)->phb.opal_id, ##a)
#define NPU2ERR(p, fmt, a...)	prlog(PR_ERR,   "NPU%d: " fmt, \
				      (p)->phb.opal_id, ##a)

/* Number of PEs supported */
#define NPU2_MAX_PE_NUM		16
#define NPU2_RESERVED_PE_NUM	15

struct npu2_bar;
struct npu2_genid_bar {
#define NPU2_GENID_BAR_FLAG_SIZE_HI	0x0010
#define NPU2_GENID_BAR_FLAG_TRAPPED	0x0020
	uint64_t	flags;
	uint64_t	base;
	uint64_t	size;
	struct npu2_bar	*bar;
};

struct npu2_bar {
#define NPU2_BAR_FLAG_ENABLED	0x0010
#define NPU2_BAR_FLAG_SIZE_HI	0x0020
#define NPU2_BAR_FLAG_TRAPPED	0x0040
	uint32_t		flags;
#define NPU2_BAR_TYPE_GLOBAL	0
#define NPU2_BAR_TYPE_PHY	1
#define NPU2_BAR_TYPE_NTL	2
#define NPU2_BAR_TYPE_GENID	3
#define NPU2_BAR_TYPE_MAX	4
	uint32_t		type;
	uint64_t		reg;
	uint64_t		stack;
	uint64_t		base;
	uint64_t		size;
	struct npu2_genid_bar	*genid_bars[2];
};

struct npu2;
struct npu2_dev {
	uint32_t		index;
	uint32_t                flags;
	uint64_t                xscom;
	void			*regs;
	struct dt_node		*dt_node;
	struct npu2_bar		*bars[NPU2_BAR_TYPE_MAX];
	struct npu2		*npu;

	/* PCI virtual device and the associated GPU device */
	struct pci_virt_device	*pvd;
	struct phb		*phb;
	struct pci_device	*pd;

	/* Vendor specific capability */
	uint32_t		vendor_cap;

	/* Which PHY lanes this device is associated with */
	uint16_t		lane_mask;

	/* Track currently running procedure and step number */
	uint16_t		procedure_number;
	uint16_t		procedure_step;
	uint64_t		procedure_data;
	unsigned long		procedure_tb;
	uint32_t		procedure_status;
};

struct npu2 {
	uint32_t	index;
	uint32_t	flags;
	uint32_t	chip_id;
	uint64_t	xscom_base;
	uint64_t	at_xscom;
	void		*regs;
	uint64_t	mm_base;
	uint64_t	mm_size;
	uint32_t	base_lsi;
	uint32_t	total_devices;
	struct npu2_dev	*devices;

	/* IODA cache */
	uint64_t	lxive_cache[8];
	uint64_t	bdf2pe_cache[36];
	uint64_t	tve_cache[16];
	bool		tx_zcal_complete[2];

	/* Used to protect global MMIO space, in particular the XTS
	 * tables. */
	struct lock	lock;

	struct phb	phb;
};

static inline struct npu2 *phb_to_npu2(struct phb *phb)
{
	return container_of(phb, struct npu2, phb);
}

extern int64_t npu_dev_procedure_read(struct pci_virt_device *pvd,
				      struct pci_virt_cfg_trap *pvct,
				      uint32_t offset,
				      uint32_t size,
				      uint32_t *data);
extern int64_t npu_dev_procedure_write(struct pci_virt_device *pvd,
				       struct pci_virt_cfg_trap *pvct,
				       uint32_t offset,
				       uint32_t size,
				       uint32_t data);

#endif /* __NPU2_H */
