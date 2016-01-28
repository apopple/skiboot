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
#include <pci.h>
#include <pci-virt.h>

void pci_virt_cfg_read_raw(struct pci_virt_device *pvd,
			   uint32_t index, uint32_t offset,
			   uint32_t size, uint32_t *data)
{
	uint32_t tmp, read, i;

	if ((index >= PCI_VIRT_CFG_MAX)	||
	    !pvd->config[index]		||
	    ((offset + size) > pvd->cfg_size))
		return;

	for (read = 0, i = 0; i < size; i++) {
		tmp = pvd->config[index][offset + i];
		read |= (tmp << (i * 8));
	}

	*data = read;
}

void pci_virt_cfg_write_raw(struct pci_virt_device *pvd,
			    uint32_t index, uint32_t offset,
			    uint32_t size, uint32_t data)
{
	int i;

	if ((index >= PCI_VIRT_CFG_MAX)	||
	    !pvd->config[index]		||
	    ((offset + size) > pvd->cfg_size))
		return;

	for (i = 0; i < size; i++) {
		pvd->config[index][offset + i] = data;
		data = (data >> 8);
	}
}

static struct pci_virt_cfg_trap *pci_virt_find_trap(struct pci_virt_device *pvd,
						    uint32_t start,
						    uint32_t size)
{
	struct pci_virt_cfg_trap *pvct;

	if (!pvd || !size)
		return NULL;

	list_for_each(&pvd->traps, pvct, link) {
		if (start >= pvct->start && (start + size) <= pvct->end)
			return pvct;
	}

	return NULL;
}

struct pci_virt_cfg_trap *pci_virt_add_trap(struct pci_virt_device *pvd,
					    uint32_t start, uint32_t size,
					    pci_virt_read_func read,
					    pci_virt_write_func write,
					    void *data)
{
	struct pci_virt_cfg_trap *pvct;

	if (!pvd || !size || (start + size) >= pvd->cfg_size)
		return NULL;
	if (!read && !write)
		return NULL;

	pvct = pci_virt_find_trap(pvd, start, size);
	if (pvct) {
		prlog(PR_WARNING, "%s: Trap [%x, %x] already registered\n",
		      __func__, start, start + size);
		return NULL;
	}

	pvct = zalloc(sizeof(*pvct));
	if (!pvct) {
		prlog(PR_ERR, "%s: Cannnot alloc trap\n", __func__);
		return NULL;
	}

	pvct->start = start;
	pvct->end   = start + size;
	pvct->read  = read;
	pvct->write = write;
	pvct->data  = data;
	list_add_tail(&pvd->traps, &pvct->link);

	return pvct;
}

struct pci_virt_device *pci_virt_find_device(struct phb *phb,
					     uint32_t bdfn)
{
	struct pci_virt_device *pvd;

	list_for_each(&phb->virt_devices, pvd, link) {
		if (pvd->bdfn == bdfn)
			return pvd;
	}

	return NULL;
}

static bool pci_virt_cfg_valid(struct pci_virt_device *pvd,
			       uint32_t offset, uint32_t size)
{
	if ((offset + size) >= pvd->cfg_size)
		return false;
	if (offset & (size -1))
		return false;

	return true;
}

int64_t pci_virt_cfg_read(struct phb *phb, uint32_t bdfn,
			  uint32_t offset, uint32_t size,
			  uint32_t *data)
{
	struct pci_virt_device *pvd;
	struct pci_virt_cfg_trap *pvct;
	int64_t ret = OPAL_SUCCESS;

	*data = 0xffffffff;

	/* Search for PCI virtual device */
	pvd = pci_virt_find_device(phb, bdfn);
	if (!pvd)
		return OPAL_PARAMETER;

	/* Check if config address is valid or not */
	if (!pci_virt_cfg_valid(pvd, offset, size))
		return OPAL_PARAMETER;

	/*
	 * Let trap handle it if necessary. If the trap's handler
	 * returns OPAL_PARTIAL, the value is fetched from the
	 * NORMAL config space. Otherwise, the value from the
	 * trap's handler is returned.
	 */
	pvct = pci_virt_find_trap(pvd, offset, size);
	if (pvct && pvct->read) {
		ret = pvct->read(pvd, pvct, offset, size, data);
		if (ret != OPAL_PARTIAL)
			return ret;
	}

	pci_virt_cfg_read_raw(pvd, PCI_VIRT_CFG_NORMAL, offset, size, data);

	return OPAL_SUCCESS;
}

int64_t pci_virt_cfg_write(struct phb *phb, uint32_t bdfn,
			   uint32_t offset, uint32_t size,
			   uint32_t data)
{
	struct pci_virt_device *pvd;
	struct pci_virt_cfg_trap *pvct;
	uint32_t val, v, r, c, i;
	int64_t ret = OPAL_SUCCESS;

	/* Search for PCI virtual device */
	pvd = pci_virt_find_device(phb, bdfn);
	if (!pvd)
		return OPAL_PARAMETER;

	/* Check if config address is valid or not */
	if (!pci_virt_cfg_valid(pvd, offset, size))
		return OPAL_PARAMETER;

	/*
	 * Let trap handle it if necessary. If the trap's handler
	 * returns OPAL_PARTIAL, the value is stored to the virtual
	 * config space as well. Otherwise, that is dropped.
	 */
	pvct = pci_virt_find_trap(pvd, offset, size);
	if (pvct && pvct->write) {
		ret = pvct->write(pvd, pvct, offset, size, data);
		if (ret != OPAL_PARTIAL)
			return ret;
	}

	val = data;
	for (i = 0; i < size; i++) {
		PCI_VIRT_CFG_NORMAL_RD(pvd, offset + i, 1, &v);
		PCI_VIRT_CFG_RDONLY_RD(pvd, offset + i, 1, &r);
		PCI_VIRT_CFG_W1CLR_RD(pvd, offset + i, 1, &c);

		/* Drop read-only bits */
		val &= ~(r << (i * 8));
		val |= (r & v) << (i * 8);

		/* Drop W1C bits */
		val &= ~(val & ((c & v) << (i * 8)));
	}

	PCI_VIRT_CFG_NORMAL_WR(pvd, offset, size, val);

	return OPAL_SUCCESS;
}

struct pci_virt_device *pci_virt_add_device(struct phb *phb,
					    uint32_t bdfn,
					    uint32_t cfg_size,
					    void *data)
{
	struct pci_virt_device *pvd;
	uint8_t *cfg;
	uint32_t i;

	/* The standard config header size is 64 bytes */
	if (!phb || (bdfn & 0xffff0000) || (cfg_size < 64))
		return NULL;

	/* Check if the bdfn has been used */
	pvd = pci_virt_find_device(phb, bdfn);
	if (pvd) {
		prlog(PR_WARNING, "%s: bdfn 0x%x not available\n",
		      __func__, bdfn);
		return NULL;
	}

	/* Populate the PCI virtual device */
	pvd = zalloc(sizeof(*pvd));
	if (!pvd) {
		prlog(PR_ERR, "%s: Cannot alloc device\n", __func__);
		return NULL;
	}

	cfg = zalloc(cfg_size * PCI_VIRT_CFG_MAX);
	if (!cfg) {
		prlog(PR_ERR, "%s: Cannot alloc config space\n", __func__);
		return NULL;
	}

	for (i = 0; i < PCI_VIRT_CFG_MAX; i++, cfg += cfg_size)
		pvd->config[i] = cfg;

	pvd->bdfn     = bdfn;
	pvd->cfg_size = cfg_size;
	pvd->data     = data;
	list_head_init(&pvd->traps);
	list_add_tail(&phb->virt_devices, &pvd->link);

	return pvd;
}
