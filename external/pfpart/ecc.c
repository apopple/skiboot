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

#include "ecc.h"

enum command {cmd_inject, cmd_remove, cmd_hexdump, cmd_help};

struct args {
	enum command cmd;
	char *input;
	char *output;
};

static int file_inject_ecc(char *output, char *input)
{
	int input_fd, output_fd, rc = 0;
	uint8_t *input_buf, *output_buf;
	size_t input_size, output_size;
	struct stat stat;

	input_fd = open(input, O_RDONLY);
	if (input_fd < 0) {
		perror("Unable to open input file");
		return 1;
	}

	if (fstat(input_fd, &stat)) {
		perror("Unable to determine input file size");
		rc = 1;
		goto out;
	}
	input_size = stat.st_size;

	/* One ecc byte for every 8 input bytes */
	output_size = input_size + input_size/8;
	output_fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0664);
	if (output_fd < 0) {
		perror("Unable to open output file");
		rc = 1;
		goto out;
	}

	output_buf = malloc(output_size);
	if (!output_buf) {
		perror("Couldn't allocate output buffer");
		rc = 1;
		goto out1;
	}

	input_buf = mmap(NULL, input_size, PROT_READ, MAP_SHARED, input_fd, 0);
	if (input_buf == MAP_FAILED) {
		perror("Unable to mmap input file");
		rc = 1;
		goto out2;
	}

	p8_ecc_inject(output_buf, output_size, input_buf, input_size);
	munmap(input, input_size);

out2:
	free(output_buf);
out1:
	close(output_fd);
out:
	close(input_fd);
	return rc;
}

static int parse_ecc_args(struct args *args, int argc, char *argv[])
{
	while(1) {
		static struct option long_opts[] = {
			{"inject", required_argument, NULL, 'I'},
			{"remove", required_argument, NULL, 'R'},
			{"hexdump", required_argument, NULL, 'H'},
			{"output", required_argument, NULL, 'o'},
			{"help", no_argument, NULL, 'h'},
			{"p8", no_argument, NULL, 'p'},
		};
		int c, oidx = 0;

		c = getopt_long(argc, argv, "I:R:H:o:hp", long_opts, &oidx);
		if (c == EOF)
			break;
		switch(c) {
		case 'I':
			args->cmd = cmd_inject;
			args->input = strdup(optarg);
			break;
		case 'R':
			args->cmd = cmd_remove;
			args->input = strdup(optarg);
			break;
		case 'H':
			args->cmd = cmd_hexdump;
			args->input = strdup(optarg);
			break;
		case 'o':
			args->output = strdup(optarg);
			break;
		case 'h':
			args->cmd = cmd_help;
			break;
		case 'p':
			break;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct args args = {0, "", ""};

	parse_ecc_args(&args, argc, argv);

	switch(args.cmd) {
	case cmd_inject:
		return file_inject_ecc(args.output, args.input);
		break;
	case cmd_remove:
	case cmd_hexdump:
	case cmd_help:
		fprintf(stderr, "Unsupported command\n");
		return 1;
		break;
	}

	return 0;
}
