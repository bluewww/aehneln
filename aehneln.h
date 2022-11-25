/* SPDX-License-Identifier: MIT */
#ifndef AEHNELN_H
#define AEHNELN_H

#include <stdbool.h>
#include <stdint.h>

#define CORE0_HARTID 0

#define MEM_RAM_BASE 0x80000000
#define MEM_TOHOST  0x80001000

struct elf {
	char *bytes;
	uint64_t size;
};


#define AEHNELN_TRACE_INSN (1 << 0)
#define AEHNELN_TRACE_MEM (1 << 1)
#define AEHNELN_TRACE_ILLEGAL (1 << 2)
#define AEHNELN_TRACE_UNKNOWN_CSR (1 << 3)

/* valid mcause values */
#define MCAUSE_MASK 0x80000000000000ff

struct sim_ctx {
	/* machine state */
	uint64_t pc;
	uint64_t regs[32];

	uint64_t mtvec;
	uint64_t satp;
	int priv;
	uint64_t mstatus;
	uint64_t medeleg;
	uint64_t mideleg;
	uint64_t mip;
	uint64_t mie;
	uint64_t mepc;
	uint64_t mcause;
	uint64_t mtval;
	uint64_t mtime;
	uint64_t mtimecmp;

	/* other sim state */
	uint32_t insn;
	int trace;
	uint64_t pc_next;
	bool is_exception; /* whether an exception is triggered */
};

struct mem_ctx {
	char *ram; /* read/write ram */
	uint64_t ram_phys_base;
	uint64_t ram_phys_size;
};

void asim(struct sim_ctx *sim, struct mem_ctx *mem);

int mem_ctx_init(struct mem_ctx *mem);

uint32_t mem_insn_read(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr);
uint64_t mem_read64(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr);
uint32_t mem_read32(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr);
uint16_t mem_read16(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr);
uint8_t mem_read8(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr);
void mem_write64(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr, uint64_t data);
void mem_write32(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr, uint32_t data);
void mem_write16(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr, uint16_t data);
void mem_write8(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr, uint8_t data);

/* all rv64gc_zifencei_zicsr instructions */
#define __riscv_xlen 64
#define DECLARE_INSN(fun, match, mask) void sim_##fun(struct sim_ctx *sim, struct mem_ctx *mem);

#include "encoding.out.h"
#undef DECLARE_INSN

/* instruction field access macros */
#define INSN_FIELD(NAME, VAL) ((VAL & INSN_FIELD_##NAME) >> INSN_FIELD_OFFSET_##NAME)
#define RV_X(x, s, n) (((x) >> (s)) & ((1 << (n)) - 1))

/* sign extend form any bit. Note that bits position start counting from one
 * (and not zero) */
#define SEXT(VAL, SHIFT)                                                                       \
	((((uint64_t)(VAL) & (((uint64_t)1 << (SHIFT)) - 1)) ^ ((uint64_t)1 << ((SHIFT)-1))) - \
	    ((uint64_t)1 << ((SHIFT)-1)))

#define CSR_FIELD_READ(CSR, FIELD) ((CSR >> __builtin_ctzll(FIELD)) & FIELD)
#define CSR_FIELD_WRITE(CSR, FIELD, VALUE) \
	((CSR & ~(FIELD)) | ((VALUE << __builtin_ctzll(FIELD)) & FIELD))

#endif /* AEHNELN_H */
