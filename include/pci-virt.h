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

#ifndef __PCI_VIRT_H
#define __PCI_VIRT_H

#include <ccan/list/list.h>

struct pci_virt_device;
struct pci_virt_cfg_trap;
typedef int64_t (*pci_virt_read_func)(struct pci_virt_device *pvd,
				      struct pci_virt_cfg_trap *pvct,
				      uint32_t offset, uint32_t size,
				      uint32_t *data);
typedef int64_t (*pci_virt_write_func)(struct pci_virt_device *pvd,
				       struct pci_virt_cfg_trap *pvct,
				       uint32_t offset, uint32_t size,
				       uint32_t data);
struct pci_virt_cfg_trap {
	uint32_t		flags;
	uint32_t		start;
	uint32_t		end;
	pci_virt_read_func	read;
	pci_virt_write_func	write;
	struct list_node	link;
	void			*data;
};

struct pci_virt_device {
	uint32_t		bdfn;
	uint32_t		cfg_size;
#define PCI_VIRT_CFG_NORMAL	0
#define PCI_VIRT_CFG_RDONLY	1
#define PCI_VIRT_CFG_W1CLR	2
#define PCI_VIRT_CFG_MAX	3
	uint8_t			*config[PCI_VIRT_CFG_MAX];
	struct list_head	traps;
	struct list_node	link;
	void			*data;
};

extern void pci_virt_cfg_read_raw(struct pci_virt_device *pvd,
				  uint32_t index, uint32_t offset,
				  uint32_t size, uint32_t *data);
extern void pci_virt_cfg_write_raw(struct pci_virt_device *pvd,
				   uint32_t index, uint32_t offset,
				   uint32_t size, uint32_t data);
extern struct pci_virt_cfg_trap *pci_virt_add_trap(struct pci_virt_device *pvd,
						   uint32_t start,
						   uint32_t size,
						   pci_virt_read_func read,
						   pci_virt_write_func write,
						   void *data);
extern int64_t pci_virt_cfg_read(struct phb *phb, uint32_t bdfn,
				 uint32_t offset, uint32_t size,
				 uint32_t *data);
extern int64_t pci_virt_cfg_write(struct phb *phb, uint32_t bdfn,
				  uint32_t offset, uint32_t size,
				  uint32_t data);
extern struct pci_virt_device *pci_virt_find_device(struct phb *phb,
						    uint32_t bdfn);
extern struct pci_virt_device *pci_virt_add_device(struct phb *phb,
						   uint32_t bdfn,
						   uint32_t cfg_size,
						   void *data);

/* Config space accessors */
#define PCI_VIRT_CFG_NORMAL_RD(d, o, s, v)	\
	pci_virt_cfg_read_raw(d, PCI_VIRT_CFG_NORMAL, o, s, v)
#define PCI_VIRT_CFG_NORMAL_WR(d, o, s, v)	\
	pci_virt_cfg_write_raw(d, PCI_VIRT_CFG_NORMAL, o, s, v)
#define PCI_VIRT_CFG_RDONLY_RD(d, o, s, v)	\
	pci_virt_cfg_read_raw(d, PCI_VIRT_CFG_RDONLY, o, s, v)
#define PCI_VIRT_CFG_RDONLY_WR(d, o, s, v)	\
	pci_virt_cfg_write_raw(d, PCI_VIRT_CFG_RDONLY, o, s, v)
#define PCI_VIRT_CFG_W1CLR_RD(d, o, s, v)	\
	pci_virt_cfg_read_raw(d, PCI_VIRT_CFG_W1CLR, o, s, v)
#define PCI_VIRT_CFG_W1CLR_WR(d, o, s, v)	\
	pci_virt_cfg_write_raw(d, PCI_VIRT_CFG_W1CLR, o, s, v)

#define PCI_VIRT_CFG_INIT(pvd, off, sz, val, ro, w1c)			\
	do {								\
		PCI_VIRT_CFG_NORMAL_WR(pvd, off, sz, val);		\
		PCI_VIRT_CFG_RDONLY_WR(pvd, off, sz, ro);		\
		PCI_VIRT_CFG_W1CLR_WR(pvd, off, sz, w1c);		\
	} while (0)
#define PCI_VIRT_CFG_INIT_RO(pvd, off, sz, val)				\
	PCI_VIRT_CFG_INIT(pvd, off, sz, val, 0xffffffff, 0)

#endif /* __VIRT_PCI_H */
