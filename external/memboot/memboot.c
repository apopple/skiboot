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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "libflash/libflash.h"
#include "libflash/libffs.h"
#include "progress.h"
#include "ast.h"

/* Where to put the firmware image if booting from memory */
#define MEM_IMG_BASE (0x5c000000)

/* Start of flash memory if booting from flash */
#define FLASH_IMG_BASE (0x30000000)

/* LPC registers */
#define LPC_BASE		0x1e789000

#define LPC_HICR7_VAL		(MEM_IMG_BASE | 0xe00)

#define __aligned(x)			__attribute__((aligned(x)))
#define FILE_BUF_SIZE	0x10000
static uint8_t file_buf[FILE_BUF_SIZE] __aligned(FILE_BUF_SIZE);

static struct spi_flash_ctrl	*fl_ctrl;
static struct flash_chip	*fl_chip;
static struct ffs_handle	*ffsh;

static int mem_fd;

void copy_flash_img(int mem_fd, int flash_fd, unsigned int size)
{
	static void *memimg, *fwimg;
	size_t pagesize = getpagesize();

	memimg = mmap(NULL, ((size/pagesize)+1)*pagesize,
		      PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, MEM_IMG_BASE);
	if (memimg == MAP_FAILED) {
		perror("Unable to map image destination memory");
		exit(1);
	}

	fwimg = mmap(NULL,size, PROT_READ, MAP_SHARED, flash_fd, 0);
	if (fwimg == MAP_FAILED) {
		perror("Unable to open image source memory");
		exit(1);
	}

	/* Copy boot image */
	memcpy(memimg, fwimg, size);
}

void boot_firmware_image(int mem_fd, char *filename)
{
	int fw_fd;
	struct stat st;

	fw_fd = open(filename, O_RDONLY);
	if (fw_fd < 0) {
		perror("Unable to open flash image\n");
		exit(1);
	}

	if (stat(filename, &st)) {
		perror("Unable to determine size of firmware image");
		exit(1);
	}

	if (st.st_size > 32*1024*1024) {
		fprintf(stderr, "Flash too large (> 32MB)");
		exit(1);
	}

	copy_flash_img(mem_fd, fw_fd, st.st_size);
	close(fw_fd);
}

static void do_read_flash(uint32_t start, uint32_t size)
{
	void *memimg;
	int rc;
	ssize_t len;
	uint32_t done = 0;
	size_t pagesize = getpagesize();

	size = ((size/pagesize)+1)*pagesize;
	memimg = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd,
			MEM_IMG_BASE);
	if (memimg == MAP_FAILED) {
		perror("Unable to map image destination memory");
		exit(1);
	}

        printf("Reading to 0x%08x from 0x%08x..0x%08x !\n",
	       MEM_IMG_BASE, start, size);

	progress_init(size);
	while(size) {
		len = size > FILE_BUF_SIZE ? FILE_BUF_SIZE : size;
		rc = flash_read(fl_chip, start, file_buf, len);
		if (rc) {
			fprintf(stderr, "Flash read error %d for"
				" chunk at 0x%08x\n", rc, start);
			exit(1);
		}
		memmove(memimg + done/4, file_buf, len);
		start += len;
		size -= len;
		done += len;
		progress_tick(done);
	}
	progress_end();
	munmap(memimg, size);
}

static uint32_t lookup_partition(const char *name)
{
	uint32_t index;
	int rc;

        assert(ffsh != NULL);

	/* Find partition */
	rc = ffs_lookup_part(ffsh, name, &index);
	if (rc == FFS_ERR_PART_NOT_FOUND) {
		fprintf(stderr, "Partition '%s' not found !\n", name);
		exit(1);
	}
	if (rc) {
		fprintf(stderr, "Error %d looking for partition '%s' !\n",
			rc, name);
		exit(1);
	}
	return index;
}


int replace_part(const char *filename, uint32_t flash_size)
{
	uint32_t pstart, pmaxsz, pactsize, pindex;
	struct stat st;
	ssize_t file_size;
	int part_fd;
	int rc;
	const char *part_name = "PAYLOAD";
	void *fwimg, *pdest;

	/* Open the file */
	part_fd = open(filename, O_RDONLY);
	if (part_fd < 0) {
		perror("Unable to open flash image\n");
		exit(1);
	}

	if (stat(filename, &st)) {
		perror("Unable to determine size of firmware image");
		exit(1);
	}

	file_size = st.st_size;

	/* We have an in-memory image of the flash. Parse the header */
	ffs_open_image((void *)MEM_IMG_BASE, flash_size, 0, &ffsh);

        pindex = lookup_partition(part_name);

	rc = ffs_part_info(ffsh, pindex, NULL,
			&pstart, &pmaxsz, &pactsize);
	if (rc) {
		fprintf(stderr,"Failed to get partition info\n");
		exit(1);
	}

	pdest = (uint8_t *)MEM_IMG_BASE + pstart;

	/* Fail if partition is larger than image */
	if (file_size > pmaxsz) {
		printf("ERROR: Image size (%zd bytes) larger than partition"
				" (%d bytes)\n",
				file_size, pmaxsz);
		exit(1);
	}

	fwimg = mmap(NULL, file_size, PROT_READ, MAP_SHARED, part_fd, 0);
	if (fwimg == MAP_FAILED) {
		perror("Unable to open image source memory");
		exit(1);
	}

	/* Copy partition into image */
	memset(pdest, 0, pmaxsz);
	memcpy(pdest, fwimg, file_size);

	/* Update header */
	printf("Updating actual file size in partition header...\n");
	ffs_update_act_size(ffsh, pindex, file_size);

	return 0;
}

static void flash_access_cleanup_pnor(void)
{
	if (ffsh)
		ffs_close(ffsh);
	flash_exit(fl_chip);

	ast_sf_close(fl_ctrl);

	close_devs();
}

static void flash_access_setup_pnor(void)
{
	int rc;

	/* Open and map devices */
	open_devs(true, false);

	/* Create the AST flash controller */
	rc = ast_sf_open(AST_SF_TYPE_PNOR, &fl_ctrl);
	if (rc) {
		fprintf(stderr, "Failed to open controller\n");
		exit(1);
	}

	/* Open flash chip */
	rc = flash_init(fl_ctrl, &fl_chip);
	if (rc) {
		fprintf(stderr, "Failed to open flash chip\n");
		exit(1);
	}

	/* Setup cleanup function */
	atexit(flash_access_cleanup_pnor);
}

int main(int argc, char *argv[])
{
	void *lpcreg;

        /* TODO: parse the args */
	if (argc != 2 && argc != 3) {
		printf("Usage: %s <flash image> | -p <skiboot image>\n", argv[0]);
		exit(1);
	}

	mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (mem_fd < 0) {
		perror("Unable to open /dev/mem");
		exit(1);
	}

	if (argc == 3) {
		flash_access_setup_pnor();

		/* TODO: get flash size. For now, assume 32 MB */
		int flash_size = 32 * 1024 * 1024;

		/* TODO: Only read the non-payload partitions to save time */
		do_read_flash(0, flash_size);

		replace_part(argv[3], flash_size);
	}

	lpcreg = mmap(NULL, getpagesize(),
		      PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, LPC_BASE);
	if (lpcreg == MAP_FAILED) {
		perror("Unable to map LPC register memory");
		exit(1);
	}

	boot_firmware_image(mem_fd, argv[1]);

	if (readl(lpcreg + LPC_HICR7) != LPC_HICR7_VAL) {
		printf("Resetting LPC_HICR7 to 0x%x\n", LPC_HICR7_VAL);
		writel(LPC_HICR7_VAL, lpcreg+LPC_HICR7);
	}

	printf("Ready to boot from memory after power cycle\n");

	return 0;
}
