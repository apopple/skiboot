/* Copyright 2015 IBM Corp.
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

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>

#include <ccan/container_of/container_of.h>

#include <libflash/libflash.h>
#include <libflash/file.h>
#include "ast.h"
#include "arch_flash.h"

struct flash_chip;

static struct arch_arm_data {
	int fd;
	void *ahb_reg_map;
	void *gpio_ctrl;
	size_t ahb_flash_base;
	size_t ahb_flash_size;
	void *ahb_flash_map;
	int bmc;
	struct flash_chip *flash_chip;
	struct blocklevel_device *init_bl;
} arch_data;

uint32_t ast_ahb_readl(uint32_t offset)
{
	assert(((offset ^ AHB_REGS_BASE) & ~(AHB_REGS_SIZE - 1)) == 0);

	return readl(arch_data.ahb_reg_map + (offset - AHB_REGS_BASE));
}

void ast_ahb_writel(uint32_t val, uint32_t offset)
{
	assert(((offset ^ AHB_REGS_BASE) & ~(AHB_REGS_SIZE - 1)) == 0);

	writel(val, arch_data.ahb_reg_map + (offset - AHB_REGS_BASE));
}

int ast_copy_to_ahb(uint32_t reg, const void *src, uint32_t len)
{
	if (reg < arch_data.ahb_flash_base ||
	    (reg + len) > (arch_data.ahb_flash_base + arch_data.ahb_flash_size))
		return -1;
	reg -= arch_data.ahb_flash_base;

	if (((reg | (unsigned long)src | len) & 3) == 0) {
		while(len > 3) {
			uint32_t val = *(uint32_t *)src;
			writel(val, arch_data.ahb_flash_map + reg);
			src += 4;
			reg += 4;
			len -= 4;
		}
	}

	while(len--) {
		uint8_t val = *(uint8_t *)src;
		writeb(val, arch_data.ahb_flash_map + reg++);
		src += 1;
	}
	return 0;
}

/*
 * GPIO stuff to be replaced by higher level accessors for
 * controlling the flash write lock via sysfs
 */

static inline uint32_t gpio_ctl_readl(uint32_t offset)
{
	return readl(arch_data.gpio_ctrl + offset);
}

static inline void gpio_ctl_writel(uint32_t val, uint32_t offset)
{
	writel(val, arch_data.gpio_ctrl + offset);
}

static bool set_wrprotect(bool protect)
{
	uint32_t reg;
	bool was_protected;

	reg = gpio_ctl_readl(0x20);
	was_protected = !!(reg & 0x00004000);
	if (protect)
		reg |= 0x00004000; /* GPIOF[6] value */
	else
		reg &= ~0x00004000; /* GPIOF[6] value */
	gpio_ctl_writel(reg, 0x20);
	reg = gpio_ctl_readl(0x24);
	reg |= 0x00004000; /* GPIOF[6] direction */
	gpio_ctl_writel(reg, 0x24);

	return was_protected;
}

int ast_copy_from_ahb(void *dst, uint32_t reg, uint32_t len)
{
	if (reg < arch_data.ahb_flash_base ||
	    (reg + len) > (arch_data.ahb_flash_base + arch_data.ahb_flash_size))
		return -1;
	reg -= arch_data.ahb_flash_base;

	if (((reg | (unsigned long)dst | len) & 3) == 0) {
		while(len > 3) {
			*(uint32_t *)dst = readl(arch_data.ahb_flash_map + reg);
			dst += 4;
			reg += 4;
			len -= 4;
		}
	}

	while(len--) {
		*(uint8_t *)dst = readb(arch_data.ahb_flash_map + reg++);
		dst += 1;
	}
	return 0;
}

static void close_devs(void)
{
	/*
	 * Old code doesn't do this, not sure why not
	 *
	 * munmap(arch_data.ahb_flash_map, arch_data.ahb_flash_size);
	 * munmap(arch_data.gpio_ctrl, GPIO_CTRL_SIZE);
	 * munmap(arch_data.ahb_reg_map, AHB_REGS_SIZE);
	 * close(arch_data.fd);
	 */
}

static int open_devs(int bmc)
{
	arch_data.fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (arch_data.fd < 0) {
		perror("can't open /dev/mem");
		return -1;
	}

	arch_data.ahb_reg_map = mmap(0, AHB_REGS_SIZE, PROT_READ | PROT_WRITE,
			MAP_SHARED, arch_data.fd, AHB_REGS_BASE);
	if (arch_data.ahb_reg_map == MAP_FAILED) {
		perror("can't map AHB registers /dev/mem");
		return -1;
	}
	arch_data.gpio_ctrl = mmap(0, GPIO_CTRL_SIZE, PROT_READ | PROT_WRITE,
			 MAP_SHARED, arch_data.fd, GPIO_CTRL_BASE);
	if (arch_data.gpio_ctrl == MAP_FAILED) {
		perror("can't map GPIO control via /dev/mem");
		return -1;
	}
	arch_data.ahb_flash_base = bmc ? BMC_FLASH_BASE : PNOR_FLASH_BASE;
	arch_data.ahb_flash_size = bmc ? BMC_FLASH_SIZE : PNOR_FLASH_SIZE;
	arch_data.ahb_flash_map = mmap(0, arch_data.ahb_flash_size, PROT_READ |
			PROT_WRITE, MAP_SHARED, arch_data.fd, arch_data.ahb_flash_base);
	if (arch_data.ahb_flash_map == MAP_FAILED) {
		perror("can't map flash via /dev/mem");
		return -1;
	}
	return 0;
}

static struct blocklevel_device *flash_setup(int bmc)
{
	int rc;
	struct blocklevel_device *bl;
	struct spi_flash_ctrl *fl;

	/* Open and map devices */
	open_devs(bmc);

	/* Create the AST flash controller */
	rc = ast_sf_open(bmc ? AST_SF_TYPE_BMC : AST_SF_TYPE_PNOR, &fl);
	if (rc) {
		fprintf(stderr, "Failed to open controller\n");
		return NULL;
	}

	/* Open flash chip */
	rc = flash_init(fl, &bl, &arch_data.flash_chip);
	if (rc) {
		fprintf(stderr, "Failed to open flash chip\n");
		return NULL;
	}

	return bl;
}

int arch_flash_bmc(struct blocklevel_device *bl, int bmc)
{
	if (!arch_data.init_bl) {
		arch_data.bmc = bmc;
		return 0;
	}

	/* Called with a BL not inited here, bail */
	if (arch_data.init_bl != bl)
		return -1;

	return arch_data.flash_chip ? arch_data.bmc : -1;
}

int arch_flash_erase_chip(struct blocklevel_device *bl)
{
	/* Called with a BL not inited here, bail */
	if (!arch_data.init_bl || arch_data.init_bl != bl)
		return -1;

	if (!arch_data.flash_chip)
		return -1;

	return flash_erase_chip(arch_data.flash_chip);
}

int arch_flash_4b_mode(struct blocklevel_device *bl, int set_4b)
{
	/* Called with a BL not inited here, bail */
	if (!arch_data.init_bl || arch_data.init_bl != bl)
		return -1;

	if (!arch_data.flash_chip)
		return -1;

	return flash_force_4b_mode(arch_data.flash_chip, set_4b);
}

int arch_flash_set_wrprotect(struct blocklevel_device *bl, int set)
{
	/* Called with a BL not inited here, bail */
	if (!arch_data.init_bl || arch_data.init_bl != bl)
		return -1;

	if (!arch_data.flash_chip)
		return -1;

	return set_wrprotect(set);
}

int arch_flash_init(struct blocklevel_device **r_bl, const char *file)
{
	struct blocklevel_device *new_bl;

	/* Check we haven't already inited */
	if (arch_data.init_bl)
		return -1;

	if (file) {
		file_init_path(file, NULL, &new_bl);
	} else {
		new_bl = flash_setup(arch_data.bmc);
	}
	if (!new_bl)
		return -1;

	arch_data.init_bl = new_bl;
	*r_bl = new_bl;
	return 0;
}

void arch_flash_close(struct blocklevel_device *bl, const char *file)
{
	if (file) {
		file_exit_close(bl);
	} else {
		flash_exit_close(bl, &ast_sf_close);
		close_devs();
	}
}
