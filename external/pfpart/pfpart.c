#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <errno.h>
#include <libgen.h>

#include "libflash/libffs.h"
#include "libflash/ffs.h"

enum command {create, add, delete, erase, list, trunc, user, copy};

struct ffs_image {
	struct ffs_handle *ffs;
	int fd;
	void *image;
	off_t size;
};

struct args {
	enum command cmd;
	char *target;
	char *part_name;
	char *copy_file;
	uint32_t offset;
	uint32_t size;
	uint32_t part_offset;
	uint32_t block_size;
	uint32_t part_flags;
	uint32_t user_data;
	uint32_t user_value;
};

static int mmap_image(struct ffs_image *ffs_image, char *target, uint32_t part_offset)
{
	struct stat stat;
	off_t size;
	int rc = 0;

	ffs_image->fd = open(target, O_RDWR);
	if (ffs_image->fd < 0) {
		perror("Unable to open image");
		return 1;
	}

	if (fstat(ffs_image->fd, &stat)) {
		perror("Unable to get file size");
		rc = 1;
		goto out;
	}
	size = stat.st_size;

	ffs_image->image = mmap(NULL, size, PROT_READ | PROT_WRITE,
				MAP_SHARED, ffs_image->fd, 0);
	if (ffs_image->image == MAP_FAILED) {
		perror("Unable to mmap file");
		rc = 1;
		goto out;
	}

	ffs_open_image(ffs_image->image, size, part_offset, &ffs_image->ffs);
	ffs_image->size = size;

	return 0;

out:
	close(ffs_image->fd);
	return rc;
}

static int munmap_image(struct ffs_image *ffs_image)
{
	int rc = 0;

	ffs_close(ffs_image->ffs);
	rc = munmap(ffs_image->image, ffs_image->size);
	close(ffs_image->fd);
	return rc;
}

static int create_new_image(struct ffs_image *ffs_image, char *target,
			    uint32_t size) {
	void *buf;

	ffs_image->fd = open(target, O_RDWR | O_CREAT, 0664);
	if (ffs_image->fd < 0) {
		perror("Unable to open image");
		return 1;
	}

	buf = malloc(size);
	if (!buf) {
		perror("Unable to allocate memory");
		return 1;
	}

	memset(buf, 0xff, size);
	if (write(ffs_image->fd, buf, size) != size)
		perror("Unable to write file");

	free(buf);
	return 0;
}

static int create_image(char *target, uint32_t size, uint32_t block_size,
			uint32_t part_offset)
{
	struct ffs_image ffs_image;
	int rc = 0;

	ffs_image.fd = open(target, O_RDWR);
	if (ffs_image.fd < 0) {
		if (errno == ENOENT) {
			create_new_image(&ffs_image, target, size);
		} else {
			perror("Unable to open image");
			return 1;
		}
	}

	ffs_image.image = mmap(NULL, size, PROT_READ | PROT_WRITE,
				MAP_SHARED, ffs_image.fd, 0);
	if (ffs_image.image == MAP_FAILED) {
		perror("Unable to mmap file");
		rc = 1;
		goto out;
	}

	ffs_create_image(ffs_image.image, size, block_size, part_offset,
			 &ffs_image.ffs);
	ffs_close(ffs_image.ffs);
	munmap(ffs_image.image, ffs_image.size);

out:
	close(ffs_image.fd);
	return rc;
}

static void print_info(struct ffs_image *ffs_image)
{
	char *name;
	uint32_t i, start, end, act;

	printf("Partitions:\n");
	printf("-----------\n");

	for(i = 0;; i++) {
		if (ffs_part_info(ffs_image->ffs, i, &name, &start, &end, &act))
			break;

		printf("ID=%02d %15s %08x..%08x (actual=%08x)\n",
		       i, name, start, end, act);
		free(name);
	}
}

static int list_info(char *target, uint32_t part_offset)
{
	struct ffs_image ffs_image;

	if (mmap_image(&ffs_image, target, part_offset))
		return 1;

	print_info(&ffs_image);
	munmap_image(&ffs_image);

	return 0;
}

static int add_part(char *target, char *name, uint32_t offset, uint32_t size,
		    uint32_t type, uint32_t flags, uint32_t part_offset)
{
	struct ffs_image ffs_image;
	uint32_t entry_count;
	int rc = 0;

	if (mmap_image(&ffs_image, target, part_offset))
		return 1;

	ffs_info(ffs_image.ffs, NULL, &entry_count, NULL);
	if (ffs_add_part(entry_count, name, offset, size, type, flags,
			 ffs_image.ffs)) {
		fprintf(stderr, "Error adding partition\n");
		rc = 1;
		goto out;
	}

out:
	munmap_image(&ffs_image);
	return rc;
}

int update_user(char *target, char *name, uint32_t user_data, uint32_t user_value,
		uint32_t part_offset)
{
	uint32_t data[FFS_USER_WORDS];
	struct ffs_image ffs_image;
	uint32_t index;
	int rc = 0;

	if (user_data >= FFS_USER_WORDS) {
		fprintf(stderr, "Invalid user word number %d\n", user);
		return 1;
	}

	if (mmap_image(&ffs_image, target, part_offset))
		return 1;

	if (ffs_lookup_part(ffs_image.ffs, name, &index)) {
		fprintf(stderr, "Couldn't locate existing partition entry\n");
		rc = 1;
		goto out;
	}

	ffs_get_user(ffs_image.ffs, index, data);
	data[user_data] = user_value;
	ffs_add_user(ffs_image.ffs, index, data);

out:
	munmap_image(&ffs_image);
	return rc;
}

int copy_data(char *target, char *source, char *name, uint32_t part_offset)
{
	struct ffs_image ffs_image;
	uint32_t index, start, act_size;
	int source_file;
	uint32_t *source_data;
	struct stat stat;
	off_t size;
	int rc = 0;

	source_file = open(source, O_RDONLY);
	if (source_file < 0) {
		perror("Unable to open source file");
		return 1;
	}
	if (fstat(source_file, &stat)) {
		perror("Unable to determine source file size");
		rc = 1;
		goto out;
	}

	if (mmap_image(&ffs_image, target, part_offset)) {
		rc = 1;
		goto out;
	}

	if (ffs_lookup_part(ffs_image.ffs, name, &index)) {
		fprintf(stderr, "Couldn't locate existing partition entry\n");
		rc = 1;
		goto out1;
	}

	ffs_part_info(ffs_image.ffs, index, NULL, &start, NULL, &act_size);

	size = stat.st_size;
	if (size < act_size)
		fprintf(stderr, "WARNING: Source file is smaller than "
			"partition size!\n");
	else if (size > act_size)
		fprintf(stderr, "WARNING: Source file is larger than "
			"partition size and will be truncated!\n");

	size = MIN(size, act_size);
	source_data = malloc(size);
	if (!source_data) {
		fprintf(stderr, "Unable to allocate memory\n");
		rc = 1;
		goto out1;
	}
	if (read(source_file, source_data, size) != size) {
		fprintf(stderr, "Unable to read source file\n");
		rc = 1;
		goto out2;
	}

	memcpy(ffs_image.image + start, source_data, size);

out2:
	free(source_data);
out1:
	munmap_image(&ffs_image);
out:
	close(source_file);
	return rc;
}

int parse_fpart_args(struct args *args, int argc, char *argv[])
{
	while(1) {
		static struct option long_opts[] = {
			{"create", no_argument, NULL, 'C'},
			{"add", no_argument, NULL, 'A'},
			{"delete", no_argument, NULL, 'D'},
			{"erase", no_argument, NULL, 'E'},
			{"list", no_argument, NULL, 'L'},
			{"trunc", no_argument, NULL, 'T'},
			{"user", required_argument, NULL, 'U'},
			{"copy", required_argument, NULL, 'Y'},
			{"partition-offset", required_argument, NULL, 'p'},
			{"target", required_argument, NULL, 't'},
			{"name", required_argument, NULL, 'n'},
			{"offset", required_argument, NULL, 'o'},
			{"size", required_argument, NULL, 's'},
			{"block-size", required_argument, NULL, 'b'},
			{"value", required_argument, NULL, 'u'},
			{"flags", required_argument, NULL, 'g'},
			{"pad", required_argument, NULL, 'a'},
			{"force", no_argument, NULL, 'f'},
			{"logical", no_argument, NULL, 'l'},
			{"verbose", no_argument, NULL, 'v'},
			{"debug", no_argument, NULL, 'd'},
			{"help", no_argument, NULL, 'h'},
		};
		int c, oidx = 0;

		c = getopt_long(argc, argv, "CADELTUY:p:t:n:o:s:b:u:g:a:flvdh",
				long_opts, &oidx);
		if (c == EOF)
			break;
		switch(c) {
		case 'C':
			args->cmd = create;
			break;
		case 'A':
			args->cmd = add;
			break;
		case 'D':
			args->cmd = delete;
			break;
		case 'E':
			args->cmd = erase;
			break;
		case 'L':
			args->cmd = list;
			break;
		case 'T':
			args->cmd = trunc;
			break;
		case 'U':
			args->cmd = user;
			args->user_data = strtoll(optarg, NULL, 0);
			if (args->user_data >= FFS_USER_WORDS) {
				fprintf(stderr, "Invalid user word %" PRIu32 "\n",
					args->user_data);
				return 1;
			}
			break;
		case 'Y':
			args->cmd = copy;
			args->copy_file = strdup(optarg);
			break;
		case 'p':
			args->part_offset = strtoll(optarg, NULL, 0);
			break;
		case 't':
			args->target = strdup(optarg);
			break;
		case 'n':
			args->part_name = strdup(optarg);
			break;
		case 'o':
			args->offset = strtoll(optarg, NULL, 0);
			break;
		case 's':
			args->size = strtoll(optarg, NULL, 0);
			break;
		case 'b':
			args->block_size = strtoll(optarg, NULL, 0);
			break;
		case 'g':
			args->part_flags = strtoll(optarg, NULL, 0);
			break;
		case 'u':
			args->user_value = strtoll(optarg, NULL, 0);
			break;
		case 'f':
			break;
		case 'a':
		case 'l':
			fprintf(stderr, "Unsupported option %c\n", c);
			return 1;
			break;
		}
	}

	return 0;
}

int parse_fcp_args(struct args *args, int argc, char *argv[])
{
	while(1) {
		static struct option long_opts[] = {
			{"probe", no_argument, NULL, 'P'},
			{"list", no_argument, NULL, 'L'},
			{"read", no_argument, NULL, 'R'},
			{"write", no_argument, NULL, 'W'},
			{"erase", required_argument, NULL, 'E'},
			{"copy", no_argument, NULL, 'C'},
			{"trunc", required_argument, NULL, 'T'},
			{"compare", required_argument, NULL, 'M'},
			{"user", required_argument, NULL, 'U'},
			{"offset", required_argument, NULL, 'o'},
			{"buffer", required_argument, NULL, 'b'},
			{"force", no_argument, NULL, 'f'},
			{"protected", no_argument, NULL, 'p'},
			{"verbose", no_argument, NULL, 'v'},
			{"debug", no_argument, NULL, 'd'},
			{"help", no_argument, NULL, 'h'},
		};
		int c, oidx = 0;

		c = getopt_long(argc, argv, "-PLRWE:CT:M:U:o:b:fpvdh",
				long_opts, &oidx);
		if (c == EOF)
			break;
		switch(c) {
		case 1:
			if (!args->copy_file[0])
				args->copy_file = strdup(optarg);
			else if (!args->target[0]) {
				char *str;
				args->target = strdup(strtok(optarg, ":"));
				str = strtok(NULL, ":");
				if (!str) {
					fprintf(stderr, "Target partition not "
						"specified\n");
					return 1;
				}
				args->part_name = strdup(str);

				if (strtok(NULL, ":")) {
					fprintf(stderr, "Invalid partition name\n");
					return 1;
				}
			} else {
				fprintf(stderr, "Too many arguments\n");
				return 1;
			}
			break;
		case 'W':
			args->cmd = copy;
			break;
		case 'P':
		case 'L':
		case 'R':
		case 'E':
		case 'C':
		case 'T':
		case 'M':
		case 'U':
			fprintf(stderr, "Option %c not implemented!\n", c);
			return 1;
			break;
		case 'o':
			args->part_offset = strtoll(optarg, NULL, 0);
			break;
		}
	}

	return 0;
}


int main(int argc, char *argv[])
{
	int rc = 0;
	struct args args = {0, "", "", "", 0, 0, 0, 0, 0, 0, 0};

	if (strcmp(basename(argv[0]), "fcp") == 0) {
		if (parse_fcp_args(&args, argc, argv))
			return 1;
	} else {
		if (parse_fpart_args(&args, argc, argv))
			return 1;
	}

	switch(args.cmd) {
	case create:
		if (args.size < sizeof(struct ffs_hdr)) {
			fprintf(stderr, "Flash size too small\n");
			return 1;
		}
		if (args.size % args.block_size) {
			fprintf(stderr, "Flash size is not a multiple of block"
				" size\n");
			return 1;
		}
		rc = create_image(args.target, args.size, args.block_size,
				  args.part_offset);
		if (rc)
			break;
		rc = add_part(args.target, "part", args.part_offset,
			      args.block_size, FFS_TYPE_PARTITION,
			      FFS_FLAGS_PROTECTED, args.part_offset);
		break;
	case add:
		rc = add_part(args.target, args.part_name, args.offset,
			      args.size, FFS_TYPE_DATA, args.part_flags,
			      args.part_offset);
		break;
	case delete:
		break;
	case erase:
		break;
	case list:
		rc = list_info(args.target, args.part_offset);
		break;
	case trunc:
		break;
	case user:
		rc = update_user(args.target, args.part_name, args.user_data,
				 args.user_value, args.part_offset);
		break;
	case copy:
		rc = copy_data(args.target, args.copy_file, args.part_name,
			       args.part_offset);
		break;
	}

	return rc;
}
