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
/*
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <ccan/endian/endian.h>

#include "libffs.h"

#define MAX(a, b)     ((a) > (b) ? (a) : (b))

enum ffs_type {
	ffs_type_flash,
	ffs_type_image,
};

struct ffs_handle {
	struct ffs_hdr		hdr;	/* Converted header */
	enum ffs_type		type;
	struct flash_chip	*chip;
	uint32_t		flash_offset;
	uint32_t		max_size;
	void			*cache;
	uint32_t		cached_size;
};

static uint32_t ffs_checksum(void* data, size_t size)
{
	uint32_t i, csum = 0;

	for (i = csum = 0; i < (size/4); i++)
		csum ^= ((uint32_t *)data)[i];
	return csum;
}

static int ffs_check_convert_header(struct ffs_hdr *dst, struct ffs_hdr *src)
{
	dst->magic = be32_to_cpu(src->magic);
	if (dst->magic != FFS_MAGIC)
		return FFS_ERR_BAD_MAGIC;
	dst->version = be32_to_cpu(src->version);
	if (dst->version != FFS_VERSION_1)
		return FFS_ERR_BAD_VERSION;
	if (ffs_checksum(src, FFS_HDR_SIZE) != 0)
		return FFS_ERR_BAD_CKSUM;
	dst->size = be32_to_cpu(src->size);
	dst->entry_size = be32_to_cpu(src->entry_size);
	dst->entry_count = be32_to_cpu(src->entry_count);
	dst->block_size = be32_to_cpu(src->block_size);
	dst->block_count = be32_to_cpu(src->block_count);

	return 0;
}

int ffs_open_flash(struct flash_chip *chip, uint32_t offset,
		   uint32_t max_size, struct ffs_handle **ffs)
{
	struct ffs_hdr hdr;
	struct ffs_handle *f;
	uint32_t fl_size, erase_size;
	int rc;

	if (!ffs)
		return FLASH_ERR_PARM_ERROR;
	*ffs = NULL;

	/* Grab some info about our flash chip */
	rc = flash_get_info(chip, NULL, &fl_size, &erase_size);
	if (rc) {
		FL_ERR("FFS: Error %d retrieving flash info\n", rc);
		return rc;
	}
	if ((offset + max_size) < offset)
		return FLASH_ERR_PARM_ERROR;
	if ((offset + max_size) > fl_size)
		return FLASH_ERR_PARM_ERROR;

	/* Read flash header */
	rc = flash_read(chip, offset, &hdr, sizeof(hdr));
	if (rc) {
		FL_ERR("FFS: Error %d reading flash header\n", rc);
		return rc;
	}

	/* Allocate ffs_handle structure and start populating */
	f = malloc(sizeof(*f));
	if (!f)
		return FLASH_ERR_MALLOC_FAILED;
	memset(f, 0, sizeof(*f));
	f->type = ffs_type_flash;
	f->flash_offset = offset;
	f->max_size = max_size ? max_size : (fl_size - offset);
	f->chip = chip;

	/* Convert and check flash header */
	rc = ffs_check_convert_header(&f->hdr, &hdr);
	if (rc) {
		FL_ERR("FFS: Error %d checking flash header\n", rc);
		free(f);
		return rc;
	}

	/*
	 * Decide how much of the image to grab to get the whole
	 * partition map.
	 */
	f->cached_size = f->hdr.block_size * f->hdr.size;
	FL_DBG("FFS: Partition map size: 0x%x\n", f->cached_size);

	/* Align to erase size */
	f->cached_size |= (erase_size - 1);
	f->cached_size &= ~(erase_size - 1);
	FL_DBG("FFS:         Aligned to: 0x%x\n", f->cached_size);

	/* Allocate cache */
	f->cache = malloc(f->cached_size);
	if (!f->cache) {
		free(f);
		return FLASH_ERR_MALLOC_FAILED;
	}

	/* Read the cached map */
	rc = flash_read(chip, offset, f->cache, f->cached_size);
	if (rc) {
		FL_ERR("FFS: Error %d reading flash partition map\n", rc);
		free(f);
	}
	if (rc == 0)
		*ffs = f;
	return rc;
}

int ffs_open_image(void *image, uint32_t size, uint32_t offset,
		   struct ffs_handle **ffs)
{
	struct ffs_hdr hdr;
	struct ffs_handle *f;
	int rc;

	if (!ffs)
		return FLASH_ERR_PARM_ERROR;
	*ffs = NULL;

	if ((offset + size) < offset)
		return FLASH_ERR_PARM_ERROR;

	/* Read flash header */
	memcpy(&hdr, image + offset, sizeof(hdr));

	/* Allocate ffs_handle structure and start populating */
	f = malloc(sizeof(*f));
	if (!f)
		return FLASH_ERR_MALLOC_FAILED;
	memset(f, 0, sizeof(*f));
	f->type = ffs_type_image;
	f->flash_offset = offset;
	f->max_size = size;
	f->chip = NULL;

	/* Convert and check flash header */
	rc = ffs_check_convert_header(&f->hdr, &hdr);
	if (rc) {
		FL_ERR("FFS: Error %d checking flash header\n", rc);
		free(f);
		return rc;
	}

	f->cached_size = size - offset;
	f->cache = image + offset;
	*ffs = f;

	return 0;
}

static int ffs_write_header(void *cache, uint32_t size, struct ffs_hdr *hdr)
{
	struct ffs_hdr new_hdr;

	if (size < sizeof(*hdr))
	    return FLASH_ERR_PARM_ERROR;

	new_hdr.magic = cpu_to_be32(hdr->magic);
	new_hdr.version = cpu_to_be32(hdr->version);
	new_hdr.size = cpu_to_be32(hdr->size);
	new_hdr.entry_size = cpu_to_be32(hdr->entry_size);
	new_hdr.entry_count = cpu_to_be32(hdr->entry_count);
	new_hdr.block_size = cpu_to_be32(hdr->block_size);
	new_hdr.block_count = cpu_to_be32(hdr->block_count);
	memset(new_hdr.resvd, 0, sizeof(new_hdr.resvd));
	new_hdr.checksum = ffs_checksum(&new_hdr, sizeof(new_hdr)
					- sizeof(new_hdr.checksum));
	memcpy(cache, &new_hdr, sizeof(new_hdr));
	return 0;
}

static int ffs_write_entry(void *cache, struct ffs_entry *entry)
{
	int i;
	struct ffs_entry new_entry;

	strncpy(new_entry.name, entry->name, PART_NAME_MAX + 1);
	new_entry.base = cpu_to_be32(entry->base);
	new_entry.size = cpu_to_be32(entry->size);
	new_entry.pid = cpu_to_be32(entry->pid);
	new_entry.id = cpu_to_be32(entry->id);
	new_entry.type = cpu_to_be32(entry->type);
	new_entry.flags = cpu_to_be32(entry->flags);
	new_entry.actual = cpu_to_be32(entry->actual);
	memset(&new_entry.resvd, 0, sizeof(*new_entry.resvd));
	for(i = 0; i < FFS_USER_WORDS; i++)
		new_entry.user.data[i] = cpu_to_be32(entry->user.data[i]);
	for(i = 0; i < 4; i++)
		new_entry.resvd[i] = cpu_to_be32(entry->resvd[i]);
	new_entry.checksum = ffs_checksum(&new_entry, sizeof(new_entry)
					  - sizeof(new_entry.checksum));
	memcpy(cache, &new_entry, sizeof(new_entry));
	return 0;
}

int ffs_create_image(void *image, uint32_t size, uint32_t block_size,
		     uint32_t offset, struct ffs_handle **ffs)
{
	struct ffs_handle *f;

	if (!ffs)
		return FLASH_ERR_PARM_ERROR;
	*ffs = NULL;

	if ((offset + size) < offset)
		return FLASH_ERR_PARM_ERROR;

	/* Allocate ffs_handle structure and start populating */
	f = malloc(sizeof(*f) + 10*sizeof(struct ffs_entry));
	if (!f)
		return FLASH_ERR_MALLOC_FAILED;
	memset(f, 0, sizeof(*f));
	f->type = ffs_type_image;
	f->flash_offset = offset;
	f->max_size = size;
	f->chip = NULL;

	/* Create the header */
	f->hdr.magic = FFS_MAGIC;
	f->hdr.version = 1;
	f->hdr.size = 1;
	f->hdr.entry_size = sizeof(struct ffs_entry);
	f->hdr.entry_count = 0;
	f->hdr.block_size = block_size;
	f->hdr.block_count = size/block_size;
	f->hdr.checksum = ffs_checksum(&f->hdr, sizeof(f->hdr)
				       - sizeof(f->hdr.checksum));
	f->cache = image + offset;
	f->cached_size = size - offset;
	*ffs = f;
	ffs_write_header(f->cache, f->cached_size, &f->hdr);

	return 0;
}

void ffs_close(struct ffs_handle *ffs)
{
//	if (ffs->cache)
//		free(ffs->cache);
	free(ffs);
}

static struct ffs_entry *ffs_get_part(struct ffs_handle *ffs, uint32_t index,
				      uint32_t *out_offset)
{
	uint32_t esize = ffs->hdr.entry_size;
	uint32_t offset = FFS_HDR_SIZE + index * esize;

	if (index > ffs->hdr.entry_count)
		return NULL;
	if (out_offset)
		*out_offset = offset;
	return (struct ffs_entry *)(ffs->cache + offset);
}

int ffs_add_part(uint32_t index, const char *name, uint32_t offset, uint32_t size,
		 uint32_t type, uint32_t flags, struct ffs_handle *ffs)
{
	struct ffs_entry entry;
	uint32_t block_size = ffs->hdr.block_size;

	if (offset % block_size)
		return FLASH_ERR_PARM_ERROR;

	ffs->hdr.entry_count = MAX(index + 1, ffs->hdr.entry_count);
	ffs_write_header(ffs->cache, ffs->cached_size, &ffs->hdr);

	strncpy(entry.name, name, PART_NAME_MAX + 1);
	entry.base = offset/block_size;
	entry.size = size % block_size ? (size/block_size) + 1 :
		size/block_size;
	entry.pid = FFS_PID_TOPLEVEL;
	entry.id = index + 1;
	entry.type = type;
	entry.flags = flags;
	entry.actual = size;
	memset(entry.resvd, 0, sizeof(entry.resvd));
	memset(entry.user.data, 0, sizeof(entry.user.data));
	entry.checksum = ffs_checksum(&entry, sizeof(entry)
				      - sizeof(entry.checksum));
	ffs_write_entry(ffs_get_part(ffs, index, NULL), &entry);
	return 0;
}

int ffs_get_user(struct ffs_handle *ffs, uint32_t index, uint32_t data[FFS_USER_WORDS])
{
	struct ffs_entry *entry = ffs_get_part(ffs, index, NULL);
	int i;

	for(i = 0; i < FFS_USER_WORDS; i++)
		data[i] = be32_to_cpu(entry->user.data[i]);
	return 0;
}

void ffs_add_user(struct ffs_handle *ffs, uint32_t index, uint32_t data[FFS_USER_WORDS])
{
	struct ffs_entry *entry = ffs_get_part(ffs, index, NULL);
	int i;

	for(i = 0; i < FFS_USER_WORDS; i++)
		entry->user.data[i] = cpu_to_be32(data[i]);
	entry->checksum = ffs_checksum(entry, sizeof(*entry) -
				       sizeof(entry->checksum));
}

static int ffs_check_convert_entry(struct ffs_entry *dst, struct ffs_entry *src)
{
	if (ffs_checksum(src, FFS_ENTRY_SIZE) != 0)
		return FFS_ERR_BAD_CKSUM;
	memcpy(dst->name, src->name, sizeof(dst->name));
	dst->base = be32_to_cpu(src->base);
	dst->size = be32_to_cpu(src->size);
	dst->pid = be32_to_cpu(src->pid);
	dst->id = be32_to_cpu(src->id);
	dst->type = be32_to_cpu(src->type);
	dst->flags = be32_to_cpu(src->flags);
	dst->actual = be32_to_cpu(src->actual);

	return 0;
}

int ffs_lookup_part(struct ffs_handle *ffs, const char *name,
		    uint32_t *part_idx)
{
	struct ffs_entry ent;
	uint32_t i;
	int rc;

	/* Lookup the requested partition */
	for (i = 0; i < ffs->hdr.entry_count; i++) {
		struct ffs_entry *src_ent  = ffs_get_part(ffs, i, NULL);
		rc = ffs_check_convert_entry(&ent, src_ent);
		if (rc) {
			FL_ERR("FFS: Bad entry %d in partition map\n", i);
			continue;
		}
		if (!strncmp(name, ent.name, sizeof(ent.name)))
			break;
	}
	if (i >= ffs->hdr.entry_count)
		return FFS_ERR_PART_NOT_FOUND;
	if (part_idx)
		*part_idx = i;
	return 0;
}

int ffs_part_info(struct ffs_handle *ffs, uint32_t part_idx,
		  char **name, uint32_t *start,
		  uint32_t *total_size, uint32_t *act_size)
{
	struct ffs_entry *raw_ent;
	struct ffs_entry ent;
	char *n;
	int rc;

	if (part_idx >= ffs->hdr.entry_count)
		return FFS_ERR_PART_NOT_FOUND;

	raw_ent = ffs_get_part(ffs, part_idx, NULL);
	if (!raw_ent)
		return FFS_ERR_PART_NOT_FOUND;

	rc = ffs_check_convert_entry(&ent, raw_ent);
	if (rc) {
		FL_ERR("FFS: Bad entry %d in partition map\n", part_idx);
		return rc;
	}
	if (start)
		*start = ent.base * ffs->hdr.block_size;
	if (total_size)
		*total_size = ent.size * ffs->hdr.block_size;
	if (act_size)
		*act_size = ent.actual;
	if (name) {
		n = malloc(PART_NAME_MAX + 1);
		memset(n, 0, PART_NAME_MAX + 1);
		strncpy(n, ent.name, PART_NAME_MAX);
		*name = n;
	}
	return 0;
}

void ffs_info(struct ffs_handle *ffs, uint32_t *size,
	     uint32_t *entry_count, uint32_t *block_size)
{
	if (size)
		*size = ffs->hdr.size;
	if (entry_count)
		*entry_count = ffs->hdr.entry_count;
	if (block_size)
		*block_size = ffs->hdr.block_size;
}

int ffs_update_act_size(struct ffs_handle *ffs, uint32_t part_idx,
			uint32_t act_size)
{
	struct ffs_entry *ent;
	uint32_t offset;

	if (part_idx >= ffs->hdr.entry_count) {
		FL_DBG("FFS: Entry out of bound\n");
		return FFS_ERR_PART_NOT_FOUND;
	}

	ent = ffs_get_part(ffs, part_idx, &offset);
	if (!ent) {
		FL_DBG("FFS: Entry not found\n");
		return FFS_ERR_PART_NOT_FOUND;
	}
	FL_DBG("FFS: part index %d at offset 0x%08x\n",
	       part_idx, offset);

	if (ent->actual == cpu_to_be32(act_size)) {
		FL_DBG("FFS: ent->actual alrady matches: 0x%08x==0x%08x\n",
		       cpu_to_be32(act_size), ent->actual);
		return 0;
	}
	ent->actual = cpu_to_be32(act_size);
	ent->checksum = ffs_checksum(ent, FFS_ENTRY_SIZE_CSUM);
	if (!ffs->chip)
		return 0;
	return flash_smart_write(ffs->chip, offset, ent, FFS_ENTRY_SIZE);
}
