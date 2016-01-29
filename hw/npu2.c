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
#include <skiboot.h>
#include <io.h>
#include <timebase.h>
#include <pci-cfg.h>
#include <pci.h>
#include <pci-slot.h>
#include <pci-virt.h>
#include <interrupts.h>
#include <opal.h>
#include <opal-api.h>
#include <cpu.h>
#include <device.h>
#include <ccan/str/str.h>
#include <ccan/array_size/array_size.h>
#include <affinity.h>
#include <npu2-regs.h>
#include <npu2.h>
#include <lock.h>
#include <xscom.h>
#include <bitutils.h>
#include <chip.h>

/*
 * NPU2 BAR layout definition. We have 3 stacks and each of them contains
 * 2 bricks. So every NPU2 has 6 bricks in total. There are 2 PHY BARs
 * and each of them is shared by 3 bricks. Every brick has one NTL BAR
 * and two bricks share one GENID BAR. Besides, there is a global MMIO
 * BAR. We only expose NTL and GENID BARs and all others will be hiden
 * in skiboot.
 *
 * Before the global MMIO BAR is configured, scom is only way to access
 * the BAR registers. At NPU2 PHB probing time, we rely on scom to assign
 * all BARs. At the meanwhile, the global MMIO BAR is configured.
 *
 * We need access 4 SM registers in same stack in order to configure one
 * particular BAR.
 */
#define NPU2_DEFINE_BAR(t, n, s)					\
	{ .flags         = PCI_CFG_BAR_TYPE_MEM | PCI_CFG_BAR_MEM64,	\
	  .type          = t,						\
	  .reg           = NPU2_##n,					\
	  .stack         = s,						\
	  .base	         = 0ul,						\
	  .size          = 0ul,						\
	  .genid_bars[0] = NULL,					\
	  .genid_bars[1] = NULL						\
	}
#define NPU2_DEFINE_GENID_BAR(idx)					\
	{ .flags         = PCI_CFG_BAR_TYPE_MEM | PCI_CFG_BAR_MEM64,	\
	  .base          = 0ul,						\
	  .size          = 0ul,						\
	  .bar           = &npu2_bars[idx]				\
	}

static struct npu2_bar npu2_bars[] = {
	NPU2_DEFINE_BAR(NPU2_BAR_TYPE_GLOBAL, PHY_BAR,  NPU2_STACK_STCK_2),
	NPU2_DEFINE_BAR(NPU2_BAR_TYPE_PHY,    PHY_BAR,  NPU2_STACK_STCK_0),
	NPU2_DEFINE_BAR(NPU2_BAR_TYPE_PHY,    PHY_BAR,  NPU2_STACK_STCK_1),
	NPU2_DEFINE_BAR(NPU2_BAR_TYPE_NTL,    NTL0_BAR, NPU2_STACK_STCK_0),
	NPU2_DEFINE_BAR(NPU2_BAR_TYPE_NTL,    NTL1_BAR, NPU2_STACK_STCK_0),
	NPU2_DEFINE_BAR(NPU2_BAR_TYPE_NTL,    NTL0_BAR, NPU2_STACK_STCK_1),
	NPU2_DEFINE_BAR(NPU2_BAR_TYPE_NTL,    NTL1_BAR, NPU2_STACK_STCK_1),
	NPU2_DEFINE_BAR(NPU2_BAR_TYPE_NTL,    NTL0_BAR, NPU2_STACK_STCK_2),
	NPU2_DEFINE_BAR(NPU2_BAR_TYPE_NTL,    NTL1_BAR, NPU2_STACK_STCK_2),
	NPU2_DEFINE_BAR(NPU2_BAR_TYPE_GENID,  GENID_BAR, NPU2_STACK_STCK_0),
	NPU2_DEFINE_BAR(NPU2_BAR_TYPE_GENID,  GENID_BAR, NPU2_STACK_STCK_1),
	NPU2_DEFINE_BAR(NPU2_BAR_TYPE_GENID,  GENID_BAR, NPU2_STACK_STCK_2)
};

static struct npu2_genid_bar npu2_genid_bars[] = {
	NPU2_DEFINE_GENID_BAR(9),
	NPU2_DEFINE_GENID_BAR(9),
	NPU2_DEFINE_GENID_BAR(10),
	NPU2_DEFINE_GENID_BAR(10),
	NPU2_DEFINE_GENID_BAR(11),
	NPU2_DEFINE_GENID_BAR(11)
};

/*
 * We use the indirect method because it uses the same addresses as
 * the MMIO offsets (NPU RING)
 */
static void npu2_scom_set_addr(uint64_t gcid,
			  uint64_t scom_base,
			  uint64_t addr)
{

#if 0
	/* FIXME: SIMICS doesn't implement these correctly. You just
	 * stick the address straight in. */
	addr = SETFIELD(NPU2_MISC_DA_ADDR, 0ul, addr);
	addr = SETFIELD(NPU2_MISC_DA_LEN, addr, NPU2_MISC_DA_LEN_8B);
#endif

	xscom_write(gcid, scom_base + NPU2_MISC_SCOM_IND_SCOM_ADDR, addr);
}

static void npu2_scom_write(uint64_t gcid,
			    uint64_t scom_base,
			    uint64_t reg,
			    uint64_t val)
{
	npu2_scom_set_addr(gcid, scom_base, reg);
	xscom_write(gcid, scom_base + NPU2_MISC_SCOM_IND_SCOM_DATA, val);
}

static uint64_t npu2_scom_read(uint64_t gcid,
				    uint64_t scom_base,
				    uint64_t reg)
{
	uint64_t val;

	npu2_scom_set_addr(gcid, scom_base, reg);
	xscom_read(gcid, scom_base + NPU2_MISC_SCOM_IND_SCOM_DATA, &val);

	return val;
}

static void npu2_write(struct npu2 *p, uint64_t reg, uint64_t val)
{
#if 0
	/* FIXME: SIMICS doesn't seem to support the full MMIO address range */
	if (p->regs)
		out_be64(p->regs + reg, val);
	else
#endif
		npu2_scom_write(p->chip_id, p->xscom_base, reg, val);
}

static uint64_t npu2_read(struct npu2 *p, uint64_t reg)
{
#if 0
	/* FIXME: SIMICS doesn't seem to support the full MMIO address range */
	if (p->regs)
		return in_be64(p->regs + reg);
	else
#endif
		return npu2_scom_read(p->chip_id, p->xscom_base, reg);
}

static inline void npu2_ioda_sel(struct npu2 *p, uint32_t table,
				uint32_t index, bool autoinc)
{
	out_be64(p->regs + NPU2_ATS_IODA_TBL,
		 (autoinc ? NPU2_ATS_IODA_TBL_AUTOINC : 0ul)	|
		 SETFIELD(NPU2_ATS_IODA_TBL_SELECT, 0ul, table)	|
		 SETFIELD(NPU2_ATS_IODA_TBL_INDEX,  0ul, index));
}

static struct npu2_dev *npu2_bdf_to_dev(struct npu2 *p,
					uint32_t bdfn)
{
	struct pci_virt_device *pvd;

	/* All emulated devices are attached to root bus */
	if (bdfn & ~0xff)
		return NULL;

	pvd = pci_virt_find_device(&p->phb, bdfn);
	if (pvd)
		return pvd->data;

	return NULL;
}

static struct npu2_bar *npu2_get_bar(uint32_t type,
				     uint32_t index)
{
	int32_t i;

	if (type >= NPU2_BAR_TYPE_MAX)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(npu2_bars); i++) {
		if (npu2_bars[i].type == type) {
			if (index == 0)
				return &npu2_bars[i];

			index--;
		}
	}

	return NULL;
}

static void npu2_read_bar(struct npu2 *p,
			  struct npu2_bar *bar,
			  uint32_t gcid,
			  uint32_t scom)
{
	uint64_t val[NPU2_BLOCK_SM_3 + 1], base, size, reg;
	bool enabled;
	uint32_t block;

	for (block = 0; block < ARRAY_SIZE(val); block++) {
		reg = NPU2_REG_OFFSET(bar->stack, block, bar->reg);
		if (p)
			val[block] = npu2_read(p, reg);
		else
			val[block] = npu2_scom_read(gcid, scom, reg);

		/* There are 4 registers for one BAR. If the values in the
		 * registers are not same, we simply return zero, indicating
		 * the BAR is disabled.
		 */
		if (block > 0 && val[block] != val[block - 1]) {
			val[0] = 0ul;
			break;
		}
	}

	switch (bar->type) {
	case NPU2_BAR_TYPE_GLOBAL:
	case NPU2_BAR_TYPE_PHY:
		enabled = !!(val[0] & NPU2_PHY_BAR_ENABLE);
		base    = GETFIELD(NPU2_PHY_BAR_ADDR, val[0]) << 21;
		size    = 1ul << 21;
		break;
	case NPU2_BAR_TYPE_NTL:
		enabled = !!(val[0] & NPU2_NTL_BAR_ENABLE);
		base    = GETFIELD(NPU2_NTL_BAR_ADDR, val[0]) << 17;
		size    = 1ul << 17;
		break;
	case NPU2_BAR_TYPE_GENID:
		enabled = !!(val[0] & NPU2_GENID_BAR_ENABLE);
		base    = GETFIELD(NPU2_GENID_BAR_ADDR, val[0]) << 17;
		size    = 1ul << 17;
		break;
	default:
		enabled = false;
		base    = 0ul;
		size    = 0ul;
	}

	if (enabled)
		bar->flags |= NPU2_BAR_FLAG_ENABLED;
	else
		bar->flags &= ~NPU2_BAR_FLAG_ENABLED;
	bar->base = base;
	bar->size = size;
}

static void npu2_write_bar(struct npu2 *p,
			   struct npu2_bar *bar,
			   uint32_t gcid,
			   uint32_t scom)
{
	uint64_t reg, val, enable;
	int block;

	/* FIXME: To support group/chip IDs */
	switch (bar->type) {
	case NPU2_BAR_TYPE_GLOBAL:
	case NPU2_BAR_TYPE_PHY:
		enable = NPU2_PHY_BAR_ENABLE;
		val = SETFIELD(NPU2_PHY_BAR_ADDR, 0ul, bar->base >> 21);
		break;
	case NPU2_BAR_TYPE_NTL:
		enable = NPU2_NTL_BAR_ENABLE;
		val = SETFIELD(NPU2_NTL_BAR_ADDR, 0ul, bar->base >> 17);
		break;
	case NPU2_BAR_TYPE_GENID:
		enable = NPU2_GENID_BAR_ENABLE;
		val = SETFIELD(NPU2_GENID_BAR_ADDR, 0ul, bar->base >> 17);
		break;
	default:
		val = 0ul;
	}

	if (bar->flags & NPU2_BAR_FLAG_ENABLED)
		val |= enable;

	for (block = NPU2_BLOCK_SM_0; block <= NPU2_BLOCK_SM_3; block++) {
		reg = NPU2_REG_OFFSET(bar->stack, block, bar->reg);
		if (p)
			npu2_write(p, reg, val);
		else
			npu2_scom_write(gcid, scom, reg, val);
	}
}

/* Trap for PCI command (0x4) to enable or disable device's BARs */
static int64_t npu2_cfg_write_cmd(struct pci_virt_device *pvd,
				  struct pci_virt_cfg_trap *pvct __unused,
				  uint32_t offset, uint32_t size, uint32_t data)
{
	struct npu2_dev *dev = pvd->data;
	struct npu2_bar *bar;
	uint32_t i, bar_map[] = {NPU2_BAR_TYPE_NTL, NPU2_BAR_TYPE_GENID};
	bool was_enabled, enabled;

	if (offset != PCI_CFG_CMD)
		return OPAL_PARAMETER;
	if (size != 1 && size != 2 && size != 4)
		return OPAL_PARAMETER;

	/* Enable or disable PHY, NTL, GENID BAR. Two bricks share
	 * one GENID BAR, which is exposed via the first brick. PHY
	 * BARs won't be affect as they're invisible from users.
	 */
	enabled = !!(data & PCI_CFG_CMD_MEM_EN);
	for (i = 0; i < ARRAY_SIZE(bar_map); i++) {
		if (bar_map[i] == NPU2_BAR_TYPE_GENID &&
		    (dev->index % 2))
			continue;

		bar = dev->bars[bar_map[i]];
		if (!bar)
			continue;

		was_enabled = !!(bar->flags & NPU2_BAR_FLAG_ENABLED);
		if (was_enabled == enabled)
			continue;

		if (enabled)
			bar->flags |= NPU2_BAR_FLAG_ENABLED;
		else
			bar->flags &= ~NPU2_BAR_FLAG_ENABLED;
		npu2_write_bar(dev->npu, bar, 0, 0);
	}

	return OPAL_PARTIAL;
}

static int64_t npu2_cfg_read_bar(struct pci_virt_device *pvd __unused,
				 struct pci_virt_cfg_trap *pvct,
				 uint32_t offset, uint32_t size,
				 uint32_t *data)
{
	struct npu2_bar *bar = pvct->data;

	if (!(bar->flags & NPU2_BAR_FLAG_TRAPPED))
		return OPAL_PARTIAL;

	if ((size != 4) ||
	    (offset != pvct->start && offset != pvct->start + 4))
		return OPAL_PARAMETER;

	if (bar->flags & NPU2_BAR_FLAG_SIZE_HI)
		*data = bar->size >> 32;
	else
		*data = bar->size;
	bar->flags &= ~(NPU2_BAR_FLAG_TRAPPED | NPU2_BAR_FLAG_SIZE_HI);

	return OPAL_SUCCESS;
}

static int64_t npu2_cfg_write_bar(struct pci_virt_device *pvd,
				  struct pci_virt_cfg_trap *pvct,
				  uint32_t offset, uint32_t size,
				  uint32_t data)
{
	struct npu2_dev *dev = pvd->data;
	struct npu2_bar *bar = pvct->data;

	if ((size != 4) ||
	    (offset != pvct->start && offset != pvct->start + 4))
		return OPAL_PARAMETER;

	/* Return BAR size on next read */
	if (data == 0xffffffff) {
		bar->flags |= NPU2_BAR_FLAG_TRAPPED;
		if (offset == pvct->start + 4)
			bar->flags |= NPU2_BAR_FLAG_SIZE_HI;

		return OPAL_SUCCESS;
	}

	/* Update BAR base address */
	if (offset == pvct->start) {
		bar->base &= 0xffffffff00000000;
		bar->base |= (data & 0xfffffff0);
	} else {
		bar->base &= 0x00000000ffffffff;
		bar->base |= ((uint64_t)data << 32);

		npu2_write_bar(dev->npu, bar, 0, 0);
	}

	/* To update the config cache */
	return OPAL_PARTIAL;
}

static int64_t npu2_cfg_read_genid_bar(struct pci_virt_device *pvd __unused,
				       struct pci_virt_cfg_trap *pvct,
				       uint32_t offset, uint32_t size,
				       uint32_t *data)
{
	struct npu2_genid_bar *genid_bar = pvct->data;

	if (!(genid_bar->flags & NPU2_GENID_BAR_FLAG_TRAPPED))
		return OPAL_PARTIAL;

	if ((size != 4) ||
	    (offset != pvct->start && offset != pvct->start + 4))
		return OPAL_PARAMETER;

	if (genid_bar->flags & NPU2_GENID_BAR_FLAG_SIZE_HI)
		*data = genid_bar->size >> 32;
	else
		*data = genid_bar->size;

	genid_bar->flags &= ~(NPU2_GENID_BAR_FLAG_TRAPPED |
			      NPU2_GENID_BAR_FLAG_SIZE_HI);
	return OPAL_SUCCESS;
}

static int64_t npu2_cfg_write_genid_bar(struct pci_virt_device *pvd,
					struct pci_virt_cfg_trap *pvct,
					uint32_t offset, uint32_t size,
					uint32_t data)
{
	struct npu2_dev *dev = pvd->data;
	struct npu2_genid_bar *genid_bar = pvct->data;
	struct npu2_bar *bar = genid_bar->bar;

	if ((size != 4) ||
	    (offset != pvct->start && offset != pvct->start + 4))
		return OPAL_PARAMETER;

	/* Return BAR size on next read */
	if (data == 0xffffffff) {
		genid_bar->flags |= NPU2_GENID_BAR_FLAG_TRAPPED;
		if (offset == pvct->start + 4)
			genid_bar->flags |= NPU2_GENID_BAR_FLAG_SIZE_HI;

		return OPAL_SUCCESS;
	}

	/* Update BAR base address */
	if (offset == pvct->start) {
		genid_bar->base &= 0xffffffff00000000;
		genid_bar->base |= (data & 0xfffffff0);
	} else {
		genid_bar->base &= 0x00000000ffffffff;
		genid_bar->base |= ((uint64_t)data << 32);

		bar->base = -1UL;
		if (bar->genid_bars[0]->base < bar->base)
			bar->base = bar->genid_bars[0]->base;
		if (bar->genid_bars[1]->base < bar->base)
			bar->base = bar->genid_bars[1]->base;
		npu2_write_bar(dev->npu, bar, 0, 0);
	}

	/* To update the config cache */
	return OPAL_PARTIAL;
}

#define NPU2_CFG_READ(size, type)					\
static int64_t npu2_cfg_read##size(struct phb *phb, uint32_t bdfn,	\
				   uint32_t offset, type *data)		\
{									\
	uint32_t val;							\
	int64_t ret;							\
									\
	ret = pci_virt_cfg_read(phb, bdfn, offset,			\
				sizeof(*data), &val);			\
	*data = (type)val;						\
        return ret;							\
}
#define NPU2_CFG_WRITE(size, type)					\
static int64_t npu2_cfg_write##size(struct phb *phb, uint32_t bdfn,	\
				    uint32_t offset, type data)		\
{									\
	uint32_t val = data;						\
	int64_t ret;							\
									\
	ret = pci_virt_cfg_write(phb, bdfn, offset,			\
				 sizeof(data), val);			\
	return ret;							\
}

NPU2_CFG_READ(8, u8);
NPU2_CFG_READ(16, u16);
NPU2_CFG_READ(32, u32);
NPU2_CFG_WRITE(8, u8);
NPU2_CFG_WRITE(16, u16);
NPU2_CFG_WRITE(32, u32);

static int __npu2_bind_one_GPU(struct phb *phb __unused,
			       struct pci_device *pd,
			       void *data)
{
	struct npu2_dev *dev = data;
	struct dt_node *dn;
	uint32_t pbcq;

	/* Ignore non-Nvidia PCI devices */
	if ((pd->vdid & 0xffff) != 0x10de)
		return 0;

	/* Find the PCI devices pbcq */
	for(dn = pd->dn; dn; dn = dn->parent) {
		if (dt_find_property(dn, "ibm,pbcq"))
			break;
	}
	if (!dn)
		return 0;

	pbcq = dt_prop_get_u32(dev->dt_node, "ibm,npu-pbcq");
	if (dt_prop_get_u32(dn, "ibm,pbcq") == pbcq)
		return 1;

	return 0;
}

static void npu2_bind_one_GPU(struct npu2_dev *dev)
{
	struct phb *phb;
	struct pci_device *pd;
	uint32_t i;

#define NPU2_PCI_CFG_VENDOR_BIND	0xd

	for (i = 0; i < 64; i++) {
		phb = pci_get_phb(i);
		if (!phb || phb == &dev->npu->phb)
			continue;

		pd = pci_walk_dev(phb, NULL, __npu2_bind_one_GPU, dev);
		if (pd) {
			dev->phb = phb;
			dev->pd  = pd;
			PCI_VIRT_CFG_INIT_RO(dev->pvd,
				dev->vendor_cap + NPU2_PCI_CFG_VENDOR_BIND,
				1, 0x01);
			return;
		}
	}

	prlog(PR_ERR, "%s: NPU device %04x:00:%02x.%01x not binding to PCI device\n",
	      __func__, dev->npu->phb.opal_id, dev->index / 8, dev->index % 8);
}

static struct lock pci_npu_phandle_lock = LOCK_UNLOCKED;

static void npu2_append_phandle(struct dt_node *dn,
				u32 phandle)
{
	struct dt_property *prop;
	uint32_t *npu_phandles;
	size_t len;

	/* Use a lock to make sure no one else has a reference to an
	 * ibm,npu property (this assumes this is the only function
	 * that holds a reference to it)
	 */
	lock(&pci_npu_phandle_lock);

	/* This function shouldn't be called unless ibm,npu exists */
	prop = (struct dt_property *)dt_require_property(dn, "ibm,npu", -1);

	/* Need to append to the properties */
	len = prop->len + sizeof(*npu_phandles);
	dt_resize_property(&prop, len);
	prop->len = len;

	npu_phandles = (uint32_t *)prop->prop;
	npu_phandles[len / sizeof(*npu_phandles) - 1] = phandle;
	unlock(&pci_npu_phandle_lock);
}

static int npu2_bind_GPU(struct phb *phb,
			 struct pci_device *pd,
			 void *data __unused)
{
	struct npu2 *p = phb_to_npu2(phb);
	struct npu2_dev *dev;

	dev = npu2_bdf_to_dev(p, pd->bdfn);
	assert(dev);
	if (dev->phb || dev->pd)
		return 0;

	/* Bind the emulated PCI device with the real one, which can't
	 * be done until the PCI devices are populated. Once the real
	 * PCI device is identified, we also need fix the device-tree
	 * for it
	 */
	npu2_bind_one_GPU(dev);
	if (dev->phb && dev->pd && dev->pd->dn) {
		if (dt_find_property(dev->pd->dn, "ibm,npu"))
			npu2_append_phandle(dev->pd->dn, pd->dn->phandle);
		else
			dt_add_property_cells(dev->pd->dn, "ibm,npu", pd->dn->phandle);

		dt_add_property_cells(pd->dn, "ibm,gpu", dev->pd->dn->phandle);
	}

	return 0;
}

static void npu2_phb_final_fixup(struct phb *phb)
{
	pci_walk_dev(phb, NULL, npu2_bind_GPU, NULL);
}

static void npu2_init_ioda_cache(struct npu2 *p)
{
	uint64_t val[2];
	uint32_t i;

	/* PE mapping: there are two sets of registers. One of them
	 * is used to map PEs for transactions. Another set is used
	 * for error routing. We should have consistent setting in
	 * both of them. Note that each brick can support 3 PEs at
	 * the maximal degree. For now, we just support one PE per
	 * brick.
	 */
	val[0] = NPU2_CQ_BRICK_BDF2PE_MAP_ENABLE;
	val[0] = SETFIELD(NPU2_CQ_BRICK_BDF2PE_MAP_PE,
			  val[0], NPU2_RESERVED_PE_NUM);
	val[1] = NPU2_MISC_BRICK_BDF2PE_MAP_ENABLE;
	val[1] = SETFIELD(NPU2_MISC_BRICK_BDF2PE_MAP_PE,
			  val[1], NPU2_RESERVED_PE_NUM);
	for (i = 0; i < ARRAY_SIZE(p->bdf2pe_cache); i++) {
		if (i < ARRAY_SIZE(p->bdf2pe_cache))
			p->bdf2pe_cache[i] = SETFIELD(NPU2_CQ_BRICK_BDF2PE_MAP_BDF,
						      val[0], i / 3);
		else
			p->bdf2pe_cache[i] = SETFIELD(NPU2_MISC_BRICK_BDF2PE_MAP_BDF,
						      val[1], i / 3);

		if (i % 3)
			p->bdf2pe_cache[i] = 0ul;
	}

	/* TVT */
	memset(p->tve_cache, 0, sizeof(p->tve_cache));
}

static int64_t npu2_ioda_reset(struct phb *phb, bool purge)
{
	struct npu2 *p = phb_to_npu2(phb);
	uint32_t i;

	if (purge) {
		NPU2DBG(p, "Purging all IODA tables...\n");
		npu2_init_ioda_cache(p);
	}

	/* FIXME: Update with default PE mappings */

	/* TVT */
	npu2_ioda_sel(p, NPU2_ATS_IODA_TBL_TVT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->tve_cache); i++)
		out_be64(p->regs + NPU2_ATS_IODA_DATA, p->tve_cache[i]);

	return OPAL_SUCCESS;
}


static void npu2_hw_init(struct npu2 *p)
{
	npu2_ioda_reset(&p->phb, false);
}

static int64_t npu2_map_pe_dma_window_real(struct phb *phb,
					   uint16_t pe_num,
					   uint16_t window_id,
					   uint64_t pci_start_addr,
					   uint64_t pci_mem_size)
{
	struct npu2 *p = phb_to_npu2(phb);
	uint64_t end;
	uint64_t tve;

	/* Sanity check. Each PE has one corresponding TVE */
	if (pe_num >= NPU2_MAX_PE_NUM ||
	    window_id != pe_num)
		return OPAL_PARAMETER;

	if (pci_mem_size) {
		/* Enable */

		end = pci_start_addr + pci_mem_size;

		/* We have to be 16M aligned */
		if ((pci_start_addr & 0x00ffffff) ||
		    (pci_mem_size & 0x00ffffff))
			return OPAL_PARAMETER;

		/*
		 * It *looks* like this is the max we can support (we need
		 * to verify this. Also we are not checking for rollover,
		 * but then we aren't trying too hard to protect ourselves
		 * againt a completely broken OS.
		 */
		if (end > 0x0003ffffffffffffull)
			return OPAL_PARAMETER;

		/*
		 * Put start address bits 49:24 into TVE[52:53]||[0:23]
		 * and end address bits 49:24 into TVE[54:55]||[24:47]
		 * and set TVE[51]
		 */
		tve  = (pci_start_addr << 16) & (0xffffffull << 48);
		tve |= (pci_start_addr >> 38) & (3ull << 10);
		tve |= (end >>  8) & (0xfffffful << 16);
		tve |= (end >> 40) & (3ull << 8);
		tve |= PPC_BIT(51);
	} else {
		/* Disable */
		tve = 0;
	}

	npu2_ioda_sel(p, NPU2_ATS_IODA_TBL_TVT, window_id, false);
	out_be64(p->regs + NPU2_ATS_IODA_DATA, tve);
	p->tve_cache[window_id] = tve;

	return OPAL_SUCCESS;
}

static int64_t npu2_map_pe_dma_window(struct phb *phb,
				      uint16_t pe_num,
				      uint16_t window_id,
				      uint16_t tce_levels,
				      uint64_t tce_table_addr,
				      uint64_t tce_table_size,
				      uint64_t tce_page_size)
{
	struct npu2 *p = phb_to_npu2(phb);
	uint64_t tts_encoded;
	uint64_t data64 = 0;

	/* Sanity check. Each PE has one corresponding TVE */
	if (pe_num >= NPU2_MAX_PE_NUM ||
	    window_id != pe_num)
		return OPAL_PARAMETER;

	/* Special condition, zero TCE table size used to disable
	 * the TVE.
	 */
	if (!tce_table_size) {
		npu2_ioda_sel(p, NPU2_ATS_IODA_TBL_TVT, window_id, false);
		out_be64(p->regs + NPU2_ATS_IODA_DATA, 0ul);
		p->tve_cache[window_id] = 0ul;
		return OPAL_SUCCESS;
	}

	/* Additional arguments validation */
	if (tce_levels < 1 ||
	    tce_levels > 4 ||
	    !is_pow2(tce_table_size) ||
	    tce_table_size < 0x1000)
		return OPAL_PARAMETER;

	/* TCE table size */
	data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_TTA, 0ul, tce_table_addr >> 12);
	tts_encoded = ilog2(tce_table_size) - 11;
	if (tts_encoded > 39)
		return OPAL_PARAMETER;
	data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_SIZE, data64, tts_encoded);

	/* TCE page size */
	switch (tce_page_size) {
	case 0x10000:		/* 64K */
		data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_PSIZE, data64, 5);
		break;
	case 0x1000000:		/* 16M */
		data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_PSIZE, data64, 13);
		break;
	case 0x10000000:	/* 256M */
		data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_PSIZE, data64, 17);
		break;
	case 0x1000:		/* 4K */
	default:
		data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_PSIZE, data64, 1);
	}

	/* Number of levels */
	data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_LEVEL, data64, tce_levels - 1);

	/* Update to hardware */
	npu2_ioda_sel(p, NPU2_ATS_IODA_TBL_TVT, window_id, false);
	out_be64(p->regs + NPU2_ATS_IODA_DATA, data64);
	p->tve_cache[window_id] = data64;

	return OPAL_SUCCESS;
}

static int64_t npu2_set_pe(struct phb *phb,
			   uint64_t pe_num,
			   uint64_t bdfn,
			   uint8_t bcompare,
			   uint8_t dcompare,
			   uint8_t fcompare,
			   uint8_t action)
{
	struct npu2 *p = phb_to_npu2(phb);
	struct npu2_dev *dev;
	uint64_t reg, val;
	int i, index = -1;

	/* Sanity check */
	if (action != OPAL_MAP_PE && action != OPAL_UNMAP_PE)
		return OPAL_PARAMETER;
	if (pe_num >= NPU2_MAX_PE_NUM)
		return OPAL_PARAMETER;
	if (bdfn >> 8)
		return OPAL_PARAMETER;
	if (bcompare != OpalPciBusAll ||
	    dcompare != OPAL_COMPARE_RID_DEVICE_NUMBER ||
	    fcompare != OPAL_COMPARE_RID_FUNCTION_NUMBER)
		return OPAL_UNSUPPORTED;

	/* Get the NPU2 device */
	dev = npu2_bdf_to_dev(p, bdfn);
	if (!dev)
		return OPAL_PARAMETER;

	/* Check if the PE number has been used or not */
	for (i = 0; i < ARRAY_SIZE(p->bdf2pe_cache) / 2; i++) {
		val = p->bdf2pe_cache[i];
		if (!(val & NPU2_CQ_BRICK_BDF2PE_MAP_ENABLE)) {
			if (index < 0 &&
			    i >= dev->index * 3 &&
			    i < (dev->index + 1) * 3)
				index = i;
			continue;
		}

		if (val & NPU2_CQ_BRICK_BDF2PE_MAP_WILDCARD)
			return OPAL_PARAMETER;

		if (GETFIELD(NPU2_CQ_BRICK_BDF2PE_MAP_PE, val) != pe_num)
			continue;
		if (GETFIELD(NPU2_CQ_BRICK_BDF2PE_MAP_BDF, val) != bdfn)
			return OPAL_RESOURCE;
		else
			return OPAL_BUSY;
	}

	val = NPU2_CQ_BRICK_BDF2PE_MAP_ENABLE;
	val = SETFIELD(NPU2_CQ_BRICK_BDF2PE_MAP_PE, val, pe_num);
	val = SETFIELD(NPU2_CQ_BRICK_BDF2PE_MAP_BDF, val, bdfn);

	if (!(index % 2))
		reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0 + index/2,
				      NPU2_BLOCK_CTL, NPU2_CQ_BRICK0_BDF2PE_MAP0);
	else
		reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0 + index/2,
				      NPU2_BLOCK_CTL, NPU2_CQ_BRICK1_BDF2PE_MAP0);
	p->bdf2pe_cache[i] = val;
	npu2_write(p, reg, val);
	val = NPU2_MISC_BRICK_BDF2PE_MAP_ENABLE;
	val = SETFIELD(NPU2_MISC_BRICK_BDF2PE_MAP_PE, val, pe_num);
	val = SETFIELD(NPU2_MISC_BRICK_BDF2PE_MAP_BDF, val, bdfn);

	reg = NPU2_REG_OFFSET(NPU2_STACK_MISC, NPU2_BLOCK_MISC,
			      NPU2_MISC_BRICK0_BDF2PE_MAP0 + (index * 8));
	p->bdf2pe_cache[index + 18] = val;
	npu2_write(p, reg, val);

	return OPAL_SUCCESS;
}

static int64_t npu2_get_link_state(struct pci_slot *slot __unused, uint8_t *val)
{
	/* As we're emulating all PCI stuff, the link bandwidth
	 * isn't big deal anyway.
	 */
	*val = OPAL_SHPC_LINK_UP_x1;
	return OPAL_SUCCESS;
}

static int64_t npu2_get_power_state(struct pci_slot *slot __unused, uint8_t *val)
{
	*val = PCI_SLOT_POWER_ON;
	return OPAL_SUCCESS;
}

static int64_t npu2_hreset(struct pci_slot *slot __unused)
{
	prlog(PR_DEBUG, "NPU: driver should call reset procedure here\n");

	return OPAL_SUCCESS;
}

static int64_t npu2_freset(struct pci_slot *slot __unused)
{
	/* FIXME: PHB fundamental reset, which need to be
	 * figured out later. It's used by EEH recovery
	 * upon fenced AT.
	 */
	return OPAL_SUCCESS;
}

static struct pci_slot *npu2_slot_create(struct phb *phb)
{
	struct pci_slot *slot;

	slot = pci_slot_alloc(phb, NULL);
	if (!slot)
		return slot;

	/* Elementary functions */
	slot->ops.get_presence_state  = NULL;
	slot->ops.get_link_state      = npu2_get_link_state;
	slot->ops.get_power_state     = npu2_get_power_state;
	slot->ops.get_attention_state = NULL;
	slot->ops.get_latch_state     = NULL;
	slot->ops.set_power_state     = NULL;
	slot->ops.set_attention_state = NULL;

	slot->ops.prepare_link_change = NULL;
	slot->ops.poll_link           = NULL;
	slot->ops.hreset              = npu2_hreset;
	slot->ops.freset              = npu2_freset;
	slot->ops.pfreset             = NULL;
	slot->ops.creset              = NULL;

	return slot;
}

static int64_t npu2_freeze_status(struct phb *phb __unused,
				  uint64_t pe_number __unused,
				  uint8_t *freeze_state,
				  uint16_t *pci_error_type __unused,
				  uint16_t *severity __unused,
				  uint64_t *phb_status __unused)
{
	/* FIXME: When it's called by skiboot PCI config accessor,
	 * the PE number is fixed to 0, which is incorrect. We need
	 * introduce another PHB callback to translate it. For now,
	 * it keeps the skiboot PCI enumeration going.
	 */
	*freeze_state = OPAL_EEH_STOPPED_NOT_FROZEN;
	return OPAL_SUCCESS;
}

static const struct phb_ops npu_ops = {
	.cfg_read8		= npu2_cfg_read8,
	.cfg_read16		= npu2_cfg_read16,
	.cfg_read32		= npu2_cfg_read32,
	.cfg_write8		= npu2_cfg_write8,
	.cfg_write16		= npu2_cfg_write16,
	.cfg_write32		= npu2_cfg_write32,
	.choose_bus		= NULL,
	.device_init		= NULL,
	.phb_final_fixup	= npu2_phb_final_fixup,
	.ioda_reset		= npu2_ioda_reset,
	.papr_errinjct_reset	= NULL,
	.pci_reinit		= NULL,
	.set_phb_mem_window	= NULL,
	.phb_mmio_enable	= NULL,
	.map_pe_mmio_window	= NULL,
	.map_pe_dma_window	= npu2_map_pe_dma_window,
	.map_pe_dma_window_real	= npu2_map_pe_dma_window_real,
	.pci_msi_eoi		= NULL,
	.set_xive_pe		= NULL,
	.get_msi_32		= NULL,
	.get_msi_64		= NULL,
	.set_pe			= npu2_set_pe,
	.set_peltv		= NULL,
	.eeh_freeze_status	= npu2_freeze_status,
	.eeh_freeze_clear	= NULL,
	.eeh_freeze_set		= NULL,
	.next_error		= NULL,
	.err_inject		= NULL,
	.get_diag_data		= NULL,
	.get_diag_data2		= NULL,
	.set_capi_mode		= NULL,
	.set_capp_recovery	= NULL,
};

static void assign_mmio_bars(uint32_t gcid,
			     uint32_t scom)
{
	uint64_t mem_start;
	struct npu2_bar *bar;
	uint32_t i;

	/* Associate with GENID BARs */
	bar = npu2_get_bar(NPU2_BAR_TYPE_GENID, 0);
	for (i = 0; i < ARRAY_SIZE(npu2_genid_bars); i += 2) {
		bar->genid_bars[0] = &npu2_genid_bars[i];
		bar->genid_bars[1] = &npu2_genid_bars[i + 1];

		bar++;
	}

	/* The hostboot might have assigned the BARs for us. However,
	 * that layout isn't what we want. We need figure out the
	 * valid MMIO regions and reassign them by ourselves. On
	 * the other hand, we have to reassign the fixed regions
	 * if hostboot (or simulator) didn't assign the BARs.
	 */
	mem_start = -1UL;
	for (i = 0; i < ARRAY_SIZE(npu2_bars); i++) {
		bar = &npu2_bars[i];
		npu2_read_bar(NULL, bar, gcid, scom);

		if ((bar->flags & NPU2_BAR_FLAG_ENABLED) &&
		    bar->base && bar->base < mem_start)
			mem_start = bar->base;
	}

	if (mem_start == -1UL)
		mem_start = 0x6030200000000;

	/* We're going to assign the BARs in reversed order according
	 * to their sizes, just like the order we have in npu_bars[].
	 * In that way, all BARs will be aligned perfectly without
	 * wasting resources. Also, the Linux kernel won't change
	 * anything though it attempts to reassign the BARs that
	 * it can see, which are NTL and GENID BARs.
	 *
	 * GLOBAL MMIO (16MB)
	 *        PHY0 (2MB)
	 *        PHB1 (2MB)
	 *        NTL0 (128KB)
	 *        NTL1 (128KB)
	 *        NTL2 (128KB)
	 *        NTL3 (128KB)
	 *        NTL4 (128KB)
	 *        NTL5 (128KB)
	 *      GENID0 (128KB)
	 *      GENID1 (128KB)
	 *      GENID2 (128KB)
	 */
	for (i = 0; i < ARRAY_SIZE(npu2_bars); i++) {
		bar = &npu2_bars[i];
		switch (bar->type) {
		case NPU2_BAR_TYPE_GLOBAL:
			bar->flags |= NPU2_BAR_FLAG_ENABLED;
			bar->size = 0x1000000;
			break;
		case NPU2_BAR_TYPE_PHY:
			bar->flags |= NPU2_BAR_FLAG_ENABLED;
			bar->size = 0x200000;
			break;
		case NPU2_BAR_TYPE_NTL:
			bar->flags &= ~NPU2_BAR_FLAG_ENABLED;
			bar->size = 0x20000;
			break;
		case NPU2_BAR_TYPE_GENID:
			bar->flags &= ~NPU2_BAR_FLAG_ENABLED;
			bar->size = 0x20000;
			bar->genid_bars[0]->base = mem_start;
			bar->genid_bars[0]->size = 0x10000;
			bar->genid_bars[1]->base = mem_start + 0x10000;
			bar->genid_bars[1]->size = 0x10000;
			break;
		default:
			bar->size = 0ul;
		}

		bar->base = mem_start;
		mem_start += bar->size;
		npu2_write_bar(NULL, bar, gcid, scom);
	}
}

/* Probe NPU device node and create PCI root device node
 * accordingly. The NPU deivce node should specify number
 * of links and xscom base address to access links.
 */
static void npu2_probe_phb(struct dt_node *dn)
{
	struct dt_node *np;
	uint32_t gcid, scom, index, links;
	uint64_t reg[2], mm_win[2];
	char *path;

	/* Retrieve chip id */
	path = dt_get_path(dn);
	gcid = dt_get_chip_id(dn);
	index = dt_prop_get_u32(dn, "ibm,npu-index");
	links = dt_prop_get_u32(dn, "ibm,npu-links");
	prlog(PR_INFO, "Chip %d Found NPU%d (%d links) at %s\n",
	      gcid, index, links, path);
	free(path);

	/* Retrieve scom base address */
	scom = dt_get_address(dn, 0, NULL);
	prlog(PR_INFO, "   SCOM Base:  %08x\n", scom);

	/* Reassign the BARs */
	assign_mmio_bars(gcid, scom);

	/* Global MMIO BAR */
	reg[0] = npu2_bars[0].base;
	reg[1] = npu2_bars[0].size;
	if (reg[0] && reg[1])
		prlog(PR_INFO, "   Global MMIO BAR:  %016llx (%lldMB)\n",
		      reg[0], reg[1] >> 20);
	else
		prlog(PR_ERR, "    Global MMIO BAR: Disabled\n");

	/* NTL and GENID BARs are exposed to kernel */
	mm_win[0] = npu2_bars[3].base;
	mm_win[1] = npu2_bars[ARRAY_SIZE(npu2_bars) - 1].base +
		    npu2_bars[ARRAY_SIZE(npu2_bars) - 1].size -
		    mm_win[0];

	/* Populate PCI root device node */
	np = dt_new_addr(dt_root, "pciex", reg[0]);
	assert(np);
	dt_add_property_strings(np,
				"compatible",
				"ibm,power9-npu-pciex",
				"ibm,ioda2-npu-phb");
	dt_add_property_strings(np, "device_type", "pciex");
	dt_add_property(np, "reg", reg, sizeof(reg));
	dt_add_property_cells(np, "ibm,phb-index", index);
	dt_add_property_cells(np, "ibm,chip-id", gcid);
	dt_add_property_cells(np, "ibm,xscom-base", scom);
	dt_add_property_cells(np, "ibm,npcq", dn->phandle);
	dt_add_property_cells(np, "ibm,links", links);
	dt_add_property(np, "ibm,mmio-window", mm_win, sizeof(mm_win));
}

static uint32_t npu2_populate_pcie_cap(struct npu2_dev *dev,
				       uint32_t start,
				       uint32_t prev_cap)
{
	struct pci_virt_device *pvd = dev->pvd;
	uint32_t val;

	/* Add capability list */
	PCI_VIRT_CFG_INIT_RO(pvd, prev_cap, 1, start);
	PCI_VIRT_CFG_INIT_RO(pvd, start, 1, PCI_CFG_CAP_ID_EXP);

	/* 0x00 - ID/PCIE capability */
	val = PCI_CFG_CAP_ID_EXP;
	val |= ((0x2 << 16) | (PCIE_TYPE_ENDPOINT << 20));
	PCI_VIRT_CFG_INIT_RO(pvd, start, 4, val);

	/* 0x04 - Device capability
	 *
	 * We should support FLR. Oterwhsie, it might have
	 * problem passing it through to userland via Linux
	 * VFIO infrastructure
	 */
	val = ((PCIE_MPSS_128) |
	       (PCIE_PHANTOM_NONE << 3) |
	       (PCIE_L0SL_MAX_NO_LIMIT << 6) |
	       (PCIE_L1L_MAX_NO_LIMIT << 9) |
	       (PCICAP_EXP_DEVCAP_FUNC_RESET));
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_DEVCAP, 4, val);

	/* 0x08 - Device control and status */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_DEVCTL, 4, 0x00002810,
			  0xffff0000, 0x000f0000);

	/* 0x0c - Link capability */
	val = (PCIE_LSPEED_VECBIT_2 | (PCIE_LWIDTH_1X << 4));
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_LCAP, 4, val);

	/* 0x10 - Link control and status */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_LCTL, 4, 0x00130000,
			 0xfffff000, 0xc0000000);

	/* 0x14 - Slot capability */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_SLOTCAP, 4, 0x00000000);

	/* 0x18 - Slot control and status */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_SLOTCTL, 4, 0x00000000);

	/* 0x1c - Root control and capability */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_RC, 4, 0x00000000,
			  0xffffffe0, 0x00000000);

	/* 0x20 - Root status */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_RSTAT, 4, 0x00000000,
			 0xffffffff, 0x00010000);

	/* 0x24 - Device capability 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCIECAP_EXP_DCAP2, 4, 0x00000000);

	/* 0x28 - Device Control and status 2 */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_DCTL2, 4, 0x00070000,
			 0xffff0000, 0x00000000);

	/* 0x2c - Link capability 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_LCAP2, 4, 0x00000007);

	/* 0x30 - Link control and status 2 */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_LCTL2, 4, 0x00000003,
			 0xffff0000, 0x00200000);

	/* 0x34 - Slot capability 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_SCAP2, 4, 0x00000000);

	/* 0x38 - Slot control and status 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_SCTL2, 4, 0x00000000);

	return start + PCICAP_EXP_SCTL2 + 4;
}

static uint32_t npu2_populate_vendor_cap(struct npu2_dev *dev,
					 uint32_t start,
					 uint32_t prev_cap)
{
	struct pci_virt_device *pvd = dev->pvd;

#define NPU2_VENDOR_CAP_VERSION	0x00
#define NPU2_VENDOR_CAP_LEN	0x10

	/* Capbility list */
	PCI_VIRT_CFG_INIT_RO(pvd, prev_cap, 1, start);
	PCI_VIRT_CFG_INIT_RO(pvd, start, 1, PCI_CFG_CAP_ID_VENDOR);
	dev->vendor_cap = start;

	/* Length and version */
	PCI_VIRT_CFG_INIT_RO(pvd, start + 2, 1, NPU2_VENDOR_CAP_LEN);
	PCI_VIRT_CFG_INIT_RO(pvd, start + 3, 1, NPU2_VENDOR_CAP_VERSION);

	/* Defaults when the trap can't handle the read/write (eg. due
	 * to reading/writing less than 4 bytes). */
	PCI_VIRT_CFG_INIT_RO(pvd, start + 4, 4, 0);
	PCI_VIRT_CFG_INIT_RO(pvd, start + 8, 4, 0);

	/* TODO: NVLink2 PHY procedures are unknown at this point in time. */
//	pci_virt_add_trap(pvd, start + 4, 8,
//			  npu_dev_procedure_read,
//			  npu_dev_procedure_write,
//			  NULL);

	/* Link index */
	PCI_VIRT_CFG_INIT_RO(pvd, start + 0xc, 1, dev->index);

	return start + NPU2_VENDOR_CAP_LEN;
}

static void npu2_populate_cfg(struct npu2_dev *dev)
{
	struct pci_virt_device *pvd = dev->pvd;
	struct npu2_bar *bar;
	struct npu2_genid_bar *genid_bar;
	uint32_t pos;

	/* 0x00 - Vendor/Device ID */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_VENDOR_ID, 4, 0x04ea1014);

	/* 0x04 - Command/Status */
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_CMD, 4, 0x00100000, 0xffb802b8,
			 0xf9000000);

	pci_virt_add_trap(pvd, PCI_CFG_CMD, 1,
			  NULL, npu2_cfg_write_cmd, NULL);

	/* 0x08 - Rev/Class/Cache */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_REV_ID, 4, 0x06800001);

	/* 0x0c - CLS/Latency Timer/Header/BIST */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_CACHE_LINE_SIZE, 4, 0x00800000);

	/* 0x10/14 - BAR#0, NTL BAR */
	bar = npu2_get_bar(NPU2_BAR_TYPE_NTL, dev->index);
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR0, 4,
			  (bar->base & 0xfffffff0) | (bar->flags & 0xF),
			  0x0000000f, 0x00000000);
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR1, 4, (bar->base >> 32),
			  0x00000000, 0x00000000);
	pci_virt_add_trap(pvd, PCI_CFG_BAR0, 8,
			  npu2_cfg_read_bar, npu2_cfg_write_bar, bar);

	/* 0x18/1c - BAR#1, GENID BAR */
	genid_bar = &npu2_genid_bars[dev->index];
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR2, 4,
			  (genid_bar->base & 0xfffffff0) |
			  (genid_bar->flags & 0xF),
			  0x0000000f, 0x00000000);
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR3, 4,
			  (genid_bar->base >> 32),
			  0x00000000, 0x00000000);
	pci_virt_add_trap(pvd, PCI_CFG_BAR2, 8,
			  npu2_cfg_read_genid_bar,
			  npu2_cfg_write_genid_bar,
			  genid_bar);

	/* 0x20/0x24 - BARs, disabled */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_BAR4, 4, 0x00000000);
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_BAR5, 4, 0x00000000);

	/* 0x28 - Cardbus CIS pointer */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_CARDBUS_CIS, 4, 0x00000000);

	/* 0x2c - Subsystem ID */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_SUBSYS_VENDOR_ID, 4, 0x00000000);

	/* 0x30 - ROM BAR, zero sized */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_ROMBAR, 4, 0xffffffff);

	/* 0x34 - PCI Capability */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_CAP, 4, 0x00000000);

	/* 0x38 - Reserved */
	PCI_VIRT_CFG_INIT_RO(pvd, 0x38, 4, 0x00000000);

	/* 0x3c - INT line/pin/Minimal grant/Maximal latency */
	if (!(dev->index % 2))
		PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_INT_LINE, 4, 0x00000100);
	else
		PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_INT_LINE, 4, 0x00000200);

	/* PCIE and vendor specific capability */
	pos = npu2_populate_pcie_cap(dev, 0x40, PCI_CFG_CAP);
	npu2_populate_vendor_cap(dev, pos, 0x41);
	PCI_VIRT_CFG_INIT_RO(pvd, pos + 1, 1, 0);
}

static uint32_t npu_allocate_bdfn(struct npu2 *p, uint32_t pbcq)
{
	int i;
	int dev = -1;
	int bdfn = -1;

	/* Find the highest function number alloacted to emulated PCI
	 * devices associated with this GPU. */
	for(i = 0; i < p->total_devices; i++) {
		int dev_bdfn;

		if (!p->devices[i].pvd)
			continue;

		dev_bdfn = p->devices[i].pvd->bdfn;
		dev = MAX(dev, dev_bdfn & 0xf8);

		if (dt_prop_get_u32(p->devices[i].dt_node,
				    "ibm,npu-pbcq") == pbcq)
			bdfn = MAX(bdfn, dev_bdfn);
	}

	if (bdfn >= 0)
		/* Device has already been allocated for this GPU so
		 * assign the emulated PCI device the next
		 * function. */
		return bdfn + 1;
	else if (dev >= 0)
		/* Otherwise allocate a new device and allocate
		 * function 0. */
		return dev + (1 << 3);
	else
		return 0;
}

static void npu2_populate_devices(struct npu2 *p,
				  struct dt_node *dn)
{
	struct npu2_dev *dev;
	struct dt_node *pbcq, *link;

	/* Retrieve the PBCQ device node */
	pbcq = dt_find_by_phandle(dt_root,
				  dt_prop_get_u32(dn, "ibm,npcq"));
	assert(pbcq);

	/* Walk the link@x nodes to initialize devices */
	p->total_devices = 0;
	p->phb.scan_map = 0;
	dt_for_each_compatible(pbcq, link, "ibm,npu-link") {
		dev = &p->devices[p->total_devices++];
		dev->npu = p;
		dev->dt_node = link;
		dev->index = dt_prop_get_u32(link, "ibm,npu-link-index");

		/* FIXME: These are used by the hardware procedures
		 * (npu-hw-procedures.c). Need to find the appropriate
		 * SCOM offsets and confirm if they've change from
		 * NVLink1. */
		//dev->xscom = p->xscom_base + NPU2_SCOM_CQ_SM_MISC_CFG0 +
		//	     NPU2_SCOM_STACK_STRIDE * (dev->index >> 1);
		//dev->regs = p->regs + NPU2_CQ_SM_MISC_CFG0 +
		//	     NPU2_STACK_STRIDE * (dev->index >> 1);

		dev->lane_mask = dt_prop_get_u32(link, "ibm,npu-lane-mask");

		/* Populate BARs */
		dev->bars[NPU2_BAR_TYPE_PHY]   = &npu2_bars[1 + dev->index / 3];
		dev->bars[NPU2_BAR_TYPE_NTL]   = &npu2_bars[3 + dev->index];
		dev->bars[NPU2_BAR_TYPE_GENID] = &npu2_bars[9 + dev->index / 2];

		/* Initialize PCI virtual device */
		dev->pvd = pci_virt_add_device(&p->phb,
			npu_allocate_bdfn(p, dt_prop_get_u32(link, "ibm,npu-pbcq")),
			0x100, dev);
		if (dev->pvd) {
			p->phb.scan_map |=
				0x1 << ((dev->pvd->bdfn & 0xf8) >> 3);
			npu2_populate_cfg(dev);
		}
	}
}

static void npu2_add_phb_properties(struct npu2 *p)
{
	struct dt_node *np = p->phb.dt_node;
	uint32_t icsp = get_ics_phandle();
	uint64_t mm_base, mm_size, tkill, mmio_atsd;

	/* Add various properties that HB doesn't have to
	 * add, some of them simply because they result from
	 * policy decisions made in skiboot rather than in HB
	 * such as the MMIO windows going to PCI, interrupts,
	 * etc.
	 */
	dt_add_property_cells(np, "#address-cells", 3);
	dt_add_property_cells(np, "#size-cells", 2);
	dt_add_property_cells(np, "#interrupt-cells", 1);
	dt_add_property_cells(np, "bus-range", 0, 0xff);
	dt_add_property_cells(np, "clock-frequency", 0x200, 0);
        dt_add_property_cells(np, "interrupt-parent", icsp);

	/* NPU PHB properties */
	dt_add_property_cells(np, "ibm,opal-num-pes",
			      NPU2_MAX_PE_NUM);
	dt_add_property_cells(np, "ibm,opal-reserved-pe",
			      NPU2_RESERVED_PE_NUM);
	tkill = cleanup_addr((uint64_t)p->regs) + NPU2_ATS_TCE_KILL;
	dt_add_property_cells(np, "ibm,opal-tce-kill",
			      hi32(tkill), lo32(tkill));

	mmio_atsd = (u64) p->regs +
		NPU2_REG_OFFSET(NPU2_STACK_ATSD, NPU2_BLOCK_ATSD0, NPU2_XTS_MMIO_ATSD_LAUNCH);
	dt_add_property_cells(np, "ibm,mmio-atsd", hi32(mmio_atsd),
			      lo32(mmio_atsd));

	/* Memory window is exposed as 64-bits non-prefetchable
	 * one because 64-bits prefetchable one is kind of special
	 * to kernel.
	 */
	mm_base = p->mm_base;
	mm_size = p->mm_size;
	dt_add_property_cells(np, "ranges", 0x02000000,
			      hi32(mm_base), lo32(mm_base),
			      hi32(mm_base), lo32(mm_base),
			      hi32(mm_size), lo32(mm_size));
}

static void npu2_create_phb(struct dt_node *dn)
{
	const struct dt_property *prop;
	struct npu2 *p;
	struct pci_slot *slot;
	uint32_t links;
	void *pmem;

	/* Retrieve number of devices */
	links = dt_prop_get_u32(dn, "ibm,links");
	pmem = zalloc(sizeof(struct npu2) + links * sizeof(struct npu2_dev));
	assert(pmem);

	/* Populate PHB */
	p = pmem;
	p->index = dt_prop_get_u32(dn, "ibm,phb-index");
	p->chip_id = dt_prop_get_u32(dn, "ibm,chip-id");
	p->xscom_base = dt_prop_get_u32(dn, "ibm,xscom-base");
	p->total_devices = links;

	p->regs = (void *)dt_get_address(dn, 0, NULL);

	prop = dt_require_property(dn, "ibm,mmio-window", -1);
	assert(prop->len >= (2 * sizeof(uint64_t)));
	p->mm_base = ((const uint64_t *)prop->prop)[0];
	p->mm_size = ((const uint64_t *)prop->prop)[1];

	p->devices = pmem + sizeof(struct npu2);

	/* Generic PHB */
	p->phb.dt_node = dn;
	p->phb.ops = &npu_ops;
	p->phb.phb_type = phb_type_npu_v2;
	init_lock(&p->lock);
	init_lock(&p->phb.lock);
	list_head_init(&p->phb.devices);
	list_head_init(&p->phb.virt_devices);

	npu2_populate_devices(p, dn);
	npu2_add_phb_properties(p);

	slot = npu2_slot_create(&p->phb);
	if (!slot)
	{
		/**
		 * @fwts-label NPUCannotCreatePHBSlot
		 * @fwts-advice Firmware probably ran out of memory creating
		 * NPU slot. NVLink functionality could be broken.
		 */
		prlog(PR_ERR, "NPU: Cannot create PHB slot\n");
	}

	pci_register_phb(&p->phb, OPAL_DYNAMIC_PHB_ID);

	npu2_init_ioda_cache(p);
	npu2_hw_init(p);
}

void probe_npu2(void)
{
	struct dt_node *np;

	/* Scan NPU XSCOM nodes */
	dt_for_each_compatible(dt_root, np, "ibm,power9-npu")
		npu2_probe_phb(np);

	/* Scan newly created PHB nodes */
	dt_for_each_compatible(dt_root, np, "ibm,power9-npu-pciex")
		npu2_create_phb(np);
}

/*
 * Search a table for an entry with matching value under mask. Returns
 * the index and the current value in *value.
 */
static int npu_table_search(struct npu2 *p, uint64_t table_addr,
			    int table_size, uint64_t *value, uint64_t mask)
{
	int i;
	uint64_t val;

	assert(value);

	for (i = 0; i < table_size; i++) {
		val = npu2_read(p, table_addr + i*8);
		if ((val & mask) == *value) {
			*value = val;
			return i;
		}
	}

	return -1;
}

/*
 * Allocate a context ID and initialise the tables with the relevant
 * information. Returns the ID on or error if one couldn't be
 * allocated.
 */
static int64_t opal_npu_init_context(uint64_t phb_id, int pasid, uint64_t msr,
				     uint64_t lpid)
{
	struct phb *phb = pci_get_phb(phb_id);
	struct npu2 *p = phb_to_npu2(phb);
	uint64_t xts_bdf, xts_bdf_pid = 0;
	int id, lparshort;

	if (!phb || phb->phb_type != phb_type_npu_v2)
		return OPAL_PARAMETER;

	/*
	 * We need to setup the context information in the tables for
	 * the given lpid. There are possibly several chips in this
	 * system with different BDF->LPID mappings. We need to search
	 * all chips for a matching LPID and setup the contexts to
	 * match those appropriately.
	 */

	/*
	 * Need to get LPARSHORT.
	 */
	lock(&p->lock);
	xts_bdf = SETFIELD(NPU2_XTS_BDF_MAP_LPARID, 0, lpid);
	if (npu_table_search(p, NPU2_XTS_BDF_MAP, NPU2_XTS_BDF_MAP_SIZE,
			     &xts_bdf, NPU2_XTS_BDF_MAP_LPARID) < 0) {
		NPU2ERR(p, "LPARID not associated with any GPU\n");
		id = OPAL_PARAMETER;
		goto out;
	}

	lparshort = GETFIELD(NPU2_XTS_BDF_MAP_LPARSHORT, xts_bdf);
	NPU2DBG(p, "Found LPARSHORT = 0x%x for LPID = 0x%03llx\n", lparshort,
		lpid);

	/*
	 * Need to find a free context.
	 */
	id = npu_table_search(p, NPU2_XTS_PID_MAP, NPU2_XTS_PID_MAP_SIZE,
			      &xts_bdf_pid, -1UL);
	if (id < 0) {
		NPU2ERR(p, "No XTS contexts available\n");
		id = OPAL_RESOURCE;
		goto out;
	}

	/* Enable this mapping for both real and virtual addresses */
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_VALID_ATRGPA0, 0UL, 1);
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_VALID_ATRGPA1, xts_bdf_pid, 1);

	/* Enables TLBIE/MMIOSD forwarding for this entry */
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_VALID_ATSD, xts_bdf_pid, 1);
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_LPARSHORT, xts_bdf_pid,
			       lparshort);

	/* Set the relevant MSR bits */
	//msr = MSR_DR | MSR_PR;
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_DR, xts_bdf_pid,
			       !!(msr & MSR_DR));
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_TA, xts_bdf_pid,
			       !!(msr & MSR_TA));
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_HV, xts_bdf_pid,
			       !!(msr & MSR_HV));
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_PR, xts_bdf_pid,
			       !!(msr & MSR_PR));
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_US, xts_bdf_pid,
			       !!(msr & MSR_US));
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_SF, xts_bdf_pid,
			       !!(msr & MSR_SF));
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_UV, xts_bdf_pid,
			       !!(msr & MSR_UV));

	/* Finally set the PID/PASID */
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_PASID, xts_bdf_pid, pasid);

	/* Write the entry */
	NPU2DBG(p, "XTS_PID_MAP[%03d] = 0x%08llx\n", id, xts_bdf_pid);
	npu2_write(p, NPU2_XTS_PID_MAP + id*0x20, xts_bdf_pid);

out:
	unlock(&p->lock);
	return id;
}
opal_call(OPAL_NPU_INIT_CONTEXT, opal_npu_init_context, 4);

static int opal_npu_destroy_context(uint64_t phb_id, uint64_t id)
{
	struct phb *phb = pci_get_phb(phb_id);
	struct npu2 *p = phb_to_npu2(phb);

	if (!phb || phb->phb_type != phb_type_npu_v2)
		return OPAL_PARAMETER;

	if (id >= NPU2_XTS_PID_MAP_SIZE)
		return OPAL_PARAMETER;

	lock(&p->lock);
	npu2_write(p, NPU2_XTS_PID_MAP + id*0x20, 0);
	unlock(&p->lock);

	return OPAL_SUCCESS;
}
opal_call(OPAL_NPU_DESTROY_CONTEXT, opal_npu_destroy_context, 2);

/*
 * Map the given virtual bdf to lparid with given lpcr.
 */
static int opal_npu_map_lpar(uint64_t phb_id, uint64_t bdf, uint64_t lparid,
	uint64_t lpcr)
{
	struct phb *phb = pci_get_phb(phb_id);
	struct npu2 *p = phb_to_npu2(phb);
	uint64_t xts_bdf_lpar, rc;
	int id;

	if (!phb || phb->phb_type != phb_type_npu_v2)
		return OPAL_PARAMETER;

	lock(&p->lock);

	/* Find any existing entries and update them */
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_VALID, 0UL, 1);
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_LPARID, xts_bdf_lpar, lparid);
	id = npu_table_search(p, NPU2_XTS_BDF_MAP, NPU2_XTS_BDF_MAP_SIZE,
			      &xts_bdf_lpar,
			      NPU2_XTS_BDF_MAP_VALID |
			      NPU2_XTS_BDF_MAP_LPARID);
	if (id < 0) {
		/* No existing mapping found, find space for a new one */
		xts_bdf_lpar = 0;
		id = npu_table_search(p, NPU2_XTS_BDF_MAP, NPU2_XTS_BDF_MAP_SIZE,
				      &xts_bdf_lpar, -1UL);
	}

	if (id < 0) {
		/* Unable to find a free mapping */
		NPU2ERR(p, "No free XTS_BDF[] entry\n");
		rc = OPAL_RESOURCE;
		goto out;
	}

	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_VALID, 0UL, 1);
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_BDF, xts_bdf_lpar, bdf);
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_LPARID, xts_bdf_lpar, lparid);

	/* TODO: Work out LPCR bits and copy them across as required */
	NPU2DBG(p, "XTS_BDF_MAP[%03d] = 0x%08llx\n", id, xts_bdf_lpar);
	npu2_write(p, NPU2_XTS_BDF_MAP + id*8, xts_bdf_lpar);

out:
	unlock(&p->lock);
	return rc;
}
opal_call(OPAL_NPU_MAP_LPAR, opal_npu_map_lpar, 4);

/*
 * Setup the the Nest MMU PTCR register.
 */
#define NMMU_CFG_XLAT_CTL_PTCR 0x5012c4b
static int opal_nmmu_set_ptcr(uint64_t ptcr)
{
	struct proc_chip *chip;

	for_each_chip(chip)
		xscom_write(chip->id, NMMU_CFG_XLAT_CTL_PTCR, ptcr);

	return OPAL_SUCCESS;
}
opal_call(OPAL_NMMU_SET_PTCR, opal_nmmu_set_ptcr, 1);
