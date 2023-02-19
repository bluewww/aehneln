/* SPDX-License-Identifier: MIT */
#ifndef AEHNELN_H
#define AEHNELN_H

#include <stdbool.h>
#include <stdint.h>

#define CORE0_HARTID 0

#define MEM_RAM_BASE 0x80000000
#define MEM_TOHOST 0x80001000

struct elf {
	char *bytes;
	uint64_t size;
};

#define AEHNELN_TRACE_INSN (1 << 0)
#define AEHNELN_TRACE_MEM (1 << 1)
#define AEHNELN_TRACE_ILLEGAL (1 << 2)
#define AEHNELN_TRACE_UNKNOWN_CSR (1 << 3)

struct sim_ctx {
	/* machine state */
	uint64_t pc;
	uint64_t regs[32];

	int priv;

	/* m-mode csrs */
	uint64_t mtvec;
	uint64_t mstatus;
	uint64_t misa;
	uint64_t mimpid;
	uint64_t marchid;
	uint64_t mvendorid;
	uint64_t mscratch;
	uint64_t medeleg;
	uint64_t mideleg;
	uint64_t mip;
	uint64_t mie;
	uint64_t mepc;
	uint64_t mcause;
	uint64_t mtval;
	uint64_t mtime;
	uint64_t mtimecmp;

	/* s-mode csrs */
	uint64_t stvec;
	/* uint64_t sstatus; */ /* sstatus is a restricted view of mstatus */
	uint64_t sip;
	uint64_t sie;
	uint64_t sepc;
	uint64_t sscratch;
	uint64_t scause;
	uint64_t stval;
	uint64_t satp;

	/* u-mode csrs */
	uint64_t cycle;

	/* other sim state */
	uint32_t insn;
	int trace;
	uint64_t pc_next;
	bool is_exception;	/* whether an exception is triggered */
	uint64_t generic_cause; /* generic cause. Holds exception cause before
				 * delegation logic causes it to be written to mcause or
				 * scause */
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

/* access masks */
#define MCAUSE_MASK 0x80000000000000ff
#define SCAUSE_MASK 0x80000000000000ff
/* WMASK = writes should not update these fields
 * RMASK = reads should zero these fields */
#define MSTATUS_WMASK (MSTATUS_UXL | MSTATUS_SXL)
#define MSTATUS_RMASK (0)
/* note that sstatus is just a restricted view of mstatus */
#define SSTATUS_READONLY (MSTATUS_SXL | MSTATUS_UXL)
#define SSTATUS_INVISIBLE                                                                    \
	(MSTATUS_MBE | MSTATUS_SBE | MSTATUS_TSR | MSTATUS_TW | MSTATUS_TVM | MSTATUS_MPRV | \
	    MSTATUS_MPP | MSTATUS_MPIE | MSTATUS_MIE)
#define SSTATUS_WMASK (SSTATUS_READONLY | SSTATUS_INVISIBLE)
#define SSTATUS_RMASK (SSTATUS_INVISIBLE)

/* misa */
#define MISA_MXL_32 1ull
#define MISA_MXL_64 2ull
#define MISA_MXL_128 3ull

#define MISA_A 0  /* Atomic extension */
#define MISA_B 1  /* Tentatively reserved for Bit-Manipulation extension */
#define MISA_C 2  /* Compressed extension */
#define MISA_D 3  /* Double-precision floating-point extension */
#define MISA_E 4  /* RV32E base ISA */
#define MISA_F 5  /* Single-precision floating-point extension */
#define MISA_G 6  /* Reserved */
#define MISA_H 7  /* Hypervisor extension */
#define MISA_I 8  /* RV32I/64I/128I base ISA */
#define MISA_J 9  /* Tentatively reserved for Dynamically Translated Languages extension */
#define MISA_K 10 /* Reserved */
#define MISA_L 11 /* Reserved */
#define MISA_M 12 /* Integer Multiply/Divide extension */
#define MISA_N 13 /* Tentatively reserved for User-Level Interrupts extension */
#define MISA_O 14 /* Reserved */
#define MISA_P 15 /* Tentatively reserved for Packed-SIMD extension */
#define MISA_Q 16 /* Quad-precision floating-point extension */
#define MISA_R 17 /* Reserved */
#define MISA_S 18 /* Supervisor mode implemented */
#define MISA_T 19 /* Reserved */
#define MISA_U 20 /* User mode implemented */
#define MISA_V 21 /* Tentatively reserved for Vector extension */
#define MISA_W 22 /* Reserved */
#define MISA_X 23 /* Non-standard extensions present */
#define MISA_Y 24 /* Reserved */
#define MISA_Z 25 /* Reserved */

/* instruction field access macros */
#define INSN_FIELD(NAME, VAL) ((VAL & INSN_FIELD_##NAME) >> INSN_FIELD_OFFSET_##NAME)
#define RV_X(x, s, n) (((x) >> (s)) & ((1 << (n)) - 1))

/* Bit manipulation */
/* sign extend form any bit. Note that bits position start counting from one
 * (and not zero) */
#define SEXT(VAL, SHIFT)                                                                       \
	((((uint64_t)(VAL) & (((uint64_t)1 << (SHIFT)) - 1)) ^ ((uint64_t)1 << ((SHIFT)-1))) - \
	    ((uint64_t)1 << ((SHIFT)-1)))
#define BIT(VAL) (1ull << VAL)

/* TODO: we should rather update the encoding.h.out with offset constants than
 * doing this hack */
#define OFFSET(FIELD) (__builtin_ctzll(FIELD))

/* CSR manipulation */
#define CSR_FIELD_READ(CSR, FIELD) ((CSR & FIELD) >> __builtin_ctzll(FIELD))
#define CSR_FIELD_WRITE(CSR, FIELD, VALUE) \
	((CSR & ~(FIELD)) | ((VALUE << __builtin_ctzll(FIELD)) & FIELD))

#endif /* AEHNELN_H */
