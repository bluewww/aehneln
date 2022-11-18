/* SPDX-License-Identifier: MIT */
#ifndef AEHNELN_H
#define AEHNELN_H

#include <stdint.h>

struct elf {
	char *bytes;
	uint64_t size;
};

struct sim_ctx {
	uint64_t pc;
	uint64_t regs[32];
};

struct mem_ctx {
	char *ram; /* read/write ram */
	uint64_t ram_phys_base;
	uint64_t ram_phys_size;
};

int mem_ctx_init(struct mem_ctx *mem);

uint64_t mem_read64(struct mem_ctx *mem, uint64_t addr);
void mem_write64(struct mem_ctx *mem, uint64_t addr, uint64_t data);

#endif /* AEHNELN_H */
