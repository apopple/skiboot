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
#ifndef __LIBFFS_H
#define __LIBFFS_H

#include <libflash/libflash.h>
#include <libflash/ffs.h>

/* FFS handle, opaque */
struct ffs_handle;

/* Error codes:
 *
 * < 0 = flash controller errors
 *   0 = success
 * > 0 = libffs / libflash errors
 */
#define FFS_ERR_BAD_MAGIC	100
#define FFS_ERR_BAD_VERSION	101
#define FFS_ERR_BAD_CKSUM	102
#define FFS_ERR_PART_NOT_FOUND	103

void ffs_add_user(struct ffs_handle *ffs, uint32_t index,
		  uint32_t data[FFS_USER_WORDS]);
int ffs_get_user(struct ffs_handle *ffs, uint32_t index,
		 uint32_t data[FFS_USER_WORDS]);
int ffs_add_part(uint32_t index, const char *name, uint32_t offset, uint32_t size,
		 uint32_t type, uint32_t flags, struct ffs_handle *ffs);

int ffs_create_image(void *image, uint32_t size, uint32_t block_size,
		     uint32_t offset, struct ffs_handle **ffs);
int ffs_write_image(void *image, uint32_t size, uint32_t offset,
		    struct ffs_handle *ffs);

int ffs_open_flash(struct flash_chip *chip, uint32_t offset,
		   uint32_t max_size, struct ffs_handle **ffs);

int ffs_open_image(void *image, uint32_t size, uint32_t offset,
		   struct ffs_handle **ffs);

void ffs_close(struct ffs_handle *ffs);

int ffs_lookup_part(struct ffs_handle *ffs, const char *name,
		    uint32_t *part_idx);

void ffs_info(struct ffs_handle *ffs, uint32_t *size,
	     uint32_t *entry_count, uint32_t *block_size);

int ffs_part_info(struct ffs_handle *ffs, uint32_t part_idx,
		  char **name, uint32_t *start,
		  uint32_t *total_size, uint32_t *act_size);

int ffs_update_act_size(struct ffs_handle *ffs, uint32_t part_idx,
			uint32_t act_size);


#endif /* __LIBFFS_H */
