/* SPDX-License-Identifier: MIT */
#include <sys/mman.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aehneln.h"
#include "config.h"

#define handle_error(msg)           \
	do {                        \
		perror(msg);        \
		exit(EXIT_FAILURE); \
	} while (0)

void
print_usage(void)
{
	printf("Usage: " PACKAGE " RISCV-ELF\n");
}

/* map binary file into host system memory */
void
map_binary(struct elf *elf, char *name)
{
	struct stat sb = { 0 };
	off_t pa_offset = 0;
	char *addr = NULL;

	/* mmap elf file into memory */
	int fd = open(name, O_RDONLY);
	if (fd == -1)
		handle_error("open");

	if (fstat(fd, &sb) == -1)
		handle_error("fstat");

	addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, pa_offset);
	if (addr == MAP_FAILED)
		handle_error("mmap");

	close(fd);
	elf->bytes = addr;
	elf->size = sb.st_size;
}

int
mem_ctx_init(struct mem_ctx *mem)
{
	assert(mem);

	/* initialize physical memory */
	uint64_t base = 0x80000000; /* seems to be a common value */
	uint64_t size = 256 * 1024 * 1024;

	*mem = (struct mem_ctx) { 0 };
	/* give it some ram */
	char *ram = malloc(size);
	if (!ram)
		return 1;

	mem->ram = ram;
	mem->ram_phys_base = base;
	mem->ram_phys_size = size;

	return 0;
}

int
mem_ctx_copy_elf(struct mem_ctx *mem, char *elf, uint64_t base, uint64_t size)
{
	assert(mem);
	assert(elf);

	if (base < mem->ram_phys_base)
		return 1;
	if (base + size >= mem->ram_phys_base + mem->ram_phys_size)
		return 1;

	memcpy(mem->ram, elf, size);

	return 0;
}

uint64_t
mem_read64(struct mem_ctx *mem, uint64_t addr)
{
	/* TODO: I/O devices */
	if (addr < mem->ram_phys_base ||
	    addr >= mem->ram_phys_base + mem->ram_phys_size) {
		fprintf(stderr, "illegal read to 0x%" PRIx64 "\n", addr);
		exit(EXIT_FAILURE);
	}
	uint64_t data;
	memcpy(&data, &mem->ram[addr - mem->ram_phys_base], 8);
	return data;
}
void
mem_write64(struct mem_ctx *mem, uint64_t addr, uint64_t data)
{
	/* TODO: I/O devices */
	if (addr < mem->ram_phys_base ||
	    addr >= mem->ram_phys_base + mem->ram_phys_size) {
		fprintf(stderr,
		    "illegal write to 0x%" PRIx64 " with 0x%" PRIx64 "\n", addr,
		    data);
		exit(EXIT_FAILURE);
	}
	memcpy(&mem->ram[addr - mem->ram_phys_base], &data, 8);
}

void
sim(struct sim_ctx *sim, struct mem_ctx *mem)
{
}

int
main(int argc, char *argv[])
{
	int c;

	while (1) {
		__attribute__((unused)) int this_option_optind = optind ?
		    optind :
		    1;
		int option_index = 0;
		static struct option long_options[] = {
			{ "help", no_argument, 0, 'h' },
		};

		c = getopt_long(argc, argv, "?h", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			break;

		case 'h':
		case '?':
			print_usage();
			return EXIT_SUCCESS;

		default:
			printf("?? getopt returned character code 0%o ??\n", c);
		}
	}

	char *elf_name = NULL;
	if (argc - optind == 1) {
		printf("opening %s...\n", argv[optind]);
		elf_name = argv[optind];
	} else if (argc - optind >= 1) {
		fprintf(stderr, "too many arguments\n");
		print_usage();
		return EXIT_FAILURE;
	} else {
		fprintf(stderr, "missing RISCV-ELF\n");
		print_usage();
		return EXIT_FAILURE;
	}

	struct elf elf = { 0 };
	map_binary(&elf, elf_name);

	int err;
	struct mem_ctx mem = { 0 };

	err = mem_ctx_init(&mem);
	if (err) {
		fprintf(stderr, "mem_ctx_init()\n");
		return EXIT_FAILURE;
	}

	err = mem_ctx_copy_elf(&mem, elf.bytes, 0x80000000, elf.size);

	if (err) {
		fprintf(stderr, "mem_ctx_copy_elf()\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
