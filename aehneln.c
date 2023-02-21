/* SPDX-License-Identifier: MIT */
#include <sys/mman.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
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
	/* helps debugging */
	ram = memset(ram, 0xf0, size);

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

static void
exception(struct sim_ctx *sim, uint64_t cause)
{
	sim->is_exception = true;
	sim->generic_cause = cause;
}

static int
cause_from_access(enum access_type access_type, enum fault_type fault_type)
{
	switch (access_type) {
	case ACC_W:
		return fault_type == PAGEFAULT ? CAUSE_STORE_PAGE_FAULT : CAUSE_STORE_ACCESS;
	case ACC_R:
		return fault_type == PAGEFAULT ? CAUSE_LOAD_PAGE_FAULT : CAUSE_LOAD_ACCESS;
	case ACC_X:
		return fault_type == PAGEFAULT ? CAUSE_FETCH_PAGE_FAULT : CAUSE_FETCH_ACCESS;
	default:
		exit(EXIT_FAILURE);
	}
}

static int
pte_access_from_access(enum access_type access_type)
{
	switch (access_type) {
	case ACC_W:
		return PTE_W;
	case ACC_R:
		return PTE_R;
	case ACC_X:
		return PTE_X;
	default:
		exit(EXIT_FAILURE);
	}
}

static uint64_t
ptwalk_sv39(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr, enum access_type type)
{
	/* translation off */
	if (CSR_FIELD_READ(sim->satp, SATP64_MODE) == SATP_MODE_OFF)
		return vaddr;

	assert(CSR_FIELD_READ(sim->satp, SATP64_MODE) == SATP_MODE_SV39);

	/* only works in S or U mode (effective) */
	if (sim->priv == PRV_M && CSR_FIELD_READ(sim->mstatus, MSTATUS_MPRV) == 0)
		return vaddr;

	if (CSR_FIELD_READ(sim->mstatus, MSTATUS_MPP) == PRV_M &&
	    CSR_FIELD_READ(sim->mstatus, MSTATUS_MPRV) == 1)
		return vaddr;

	if (type == ACC_X && CSR_FIELD_READ(sim->mstatus, MSTATUS_MPRV) == 1)
		return vaddr;

	/* At this point we should either be in
	 * MPRV=0 and prv=S/U or
	 * MPRV=1 and prv=M/S/U and mpp=S/U and type=r/w
	 */

	/* walk table according to privilege spec 4.3.2 */
	uint64_t ppn = CSR_FIELD_READ(sim->satp, SATP64_PPN);
	uint64_t pt = ppn * AEHNELN_PAGESIZE;
	int level = AEHNELN_LEVELS - 1;

	for (;;) {
		uint64_t pte = mem_read64(sim, mem, pt + SV39_VPN(vaddr, level) * AEHNELN_PTESIZE);
		if (sim->is_exception) {
			/* re-raise exception */
			exception(sim, cause_from_access(type, ACCESS));
			return pte;
		}

		if (REG_FIELD_READ(pte, PTE_V) == 0 ||
		    (REG_FIELD_READ(pte, PTE_R) == 0 && REG_FIELD_READ(pte, PTE_W) == 1) ||
		    (REG_FIELD_READ(pte, PTE_RSVD))) {
			exception(sim, cause_from_access(type, PAGEFAULT));
			return 0xdeadbee1;
		}

		if (REG_FIELD_READ(pte, PTE_R) == 1 || REG_FIELD_READ(pte, PTE_X) == 1) {
			/* leaf page table */
			/* check privilege mode. We consider mprv since it is also affected by SUM
			 */
			int effective_priv = CSR_FIELD_READ(sim->mstatus, MSTATUS_MPRV) ?
			    (int)CSR_FIELD_READ(sim->mstatus, MSTATUS_MPP) :
			    sim->priv;

			switch (effective_priv) {
			case PRV_U:
				if (REG_FIELD_READ(pte, PTE_U) == 0) {
					exception(sim, cause_from_access(type, PAGEFAULT));
					return 0xdeadbee4;
				}
				break;
			case PRV_S:
				/* supervisor can't access usermode pages when SUM is clear */
				if (REG_FIELD_READ(pte, PTE_U) == 1 &&
				    CSR_FIELD_READ(sim->mstatus, MSTATUS_SUM) == 0) {
					exception(sim, cause_from_access(type, PAGEFAULT));
					return 0xdeadbee4;
				}
				/* supervisor maybe never execute usermode pages */
				if (REG_FIELD_READ(pte, PTE_U) == 1 && type == ACC_X) {
					exception(sim, cause_from_access(type, PAGEFAULT));
					return 0xdeadbee4;
				}
				break;
			case PRV_M:
				/* handled below */
				break;
			}

			/* check rwx permissions */
			int pte_rw = REG_FIELD_READ(pte, pte_access_from_access(ACC_R)) ||
			    REG_FIELD_READ(pte, pte_access_from_access(ACC_X));

			if (effective_priv == PRV_M && type == ACC_R &&
			    CSR_FIELD_READ(sim->mstatus, MSTATUS_MXR) == 1 && !pte_rw) {
				/* MXR privilege spec 3.1.6.3 */
				exception(sim, cause_from_access(type, PAGEFAULT));
				return 0xdeadbee4;
			} else if (!REG_FIELD_READ(pte, pte_access_from_access(type))) {
				/* regular rwx check */
				exception(sim, cause_from_access(type, PAGEFAULT));
				return 0xdeadbee4;
			}

			/* check for misaligned superpage (level > 0) */
			for (int i = 0; i < level; i++) {
				if (SV39_PPN(pte, i) != 0) {
					exception(sim, cause_from_access(type, PAGEFAULT));
					return 0xdeadbee4;
				}
			}

			/* dirty and accessed check */
			if (REG_FIELD_READ(pte, PTE_A) == 0 ||
			    (type == ACC_W && REG_FIELD_READ(pte, PTE_D) == 0)) {
				exception(sim, cause_from_access(type, PAGEFAULT));
				return 0xdeadbee5;
			}

			/* At this point the translation is successfull */
			uint64_t paddr = 0;

			/* physical offset part */
			for (int i = AEHNELN_LEVELS - 1; i >= level; i--) {
				paddr <<= SV39_PPN_SHIFT;
				paddr |= SV39_PPN(pte, i);
			}

			/* virtual offset part (level > 0 we have a superpage) */
			for (int i = level - 1; i >= 0; i--) {
				paddr <<= SV39_VPN_SIZE;
				paddr |= SV39_VPN(vaddr, i);
			}

			paddr <<= AEHNELN_PAGEOFFSET;
			paddr |= vaddr & GENMASK(AEHNELN_PAGEOFFSET);

			return paddr;
		} else {
			/* go to next level */
			level = level - 1;
			if (level < 0) {
				exception(sim, cause_from_access(type, PAGEFAULT));
				return 0xdeadbee2;
			}

			ppn = SV39_FULL_PPN(pte);
			pt = ppn * AEHNELN_PAGESIZE;
		}
	}

	assert(0);
}

uint32_t
mem_insn_vread(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_X);
	if (sim->is_exception)
		return 0xdeadbeef;

	return mem_insn_read(sim, mem, paddr);
}

uint64_t
mem_vread64(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_R);
	if (sim->is_exception)
		return 0xdeadbeefdeadbeef;

	return mem_read64(sim, mem, paddr);
}

uint32_t
mem_vread32(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_R);
	if (sim->is_exception)
		return 0xdeadbeef;

	return mem_read32(sim, mem, paddr);
}

uint16_t
mem_vread16(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_R);
	if (sim->is_exception)
		return 0xdead;

	return mem_read16(sim, mem, paddr);
}

uint8_t
mem_vread8(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_R);
	if (sim->is_exception)
		return 0x0;

	return mem_read8(sim, mem, paddr);
}

void
mem_vwrite64(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr, uint64_t data)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_W);
	if (sim->is_exception)
		return;

	return mem_write64(sim, mem, paddr, data);
}

void
mem_vwrite32(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr, uint32_t data)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_W);
	if (sim->is_exception)
		return;

	return mem_write32(sim, mem, paddr, data);
}

void
mem_vwrite16(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr, uint16_t data)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_W);
	if (sim->is_exception)
		return;

	return mem_write16(sim, mem, paddr, data);
}

void
mem_vwrite8(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr, uint8_t data)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_W);
	if (sim->is_exception)
		return;

	return mem_write8(sim, mem, paddr, data);
}

uint32_t
mem_insn_read(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr)
{
	/* TODO: I/O devices */
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal read at 0x%016" PRIx64 "\n", addr);
		exception(sim, CAUSE_FETCH_ACCESS);
		return 0xdeadbeef;
	}
	uint32_t data;
	memcpy(&data, &mem->ram[addr - mem->ram_phys_base], 4);

	/* if (sim->trace & AEHNELN_TRACE_MEM) */
	/* 	fprintf(stdout, "%s: 0x%016" PRIx64 " -> 0x%08" PRIx32 "\n", __func__, addr, data);
	 */

	return data;
}

uint64_t
mem_read64(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr)
{
	/* TODO: I/O devices */
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal read at 0x%016" PRIx64 "\n", addr);
		exception(sim, CAUSE_LOAD_ACCESS);
		return 0xdeadbeef;
	}

	uint64_t data;
	memcpy(&data, &mem->ram[addr - mem->ram_phys_base], 8);

	if (sim->trace & AEHNELN_TRACE_MEM)
		fprintf(stdout, "%s: 0x%016" PRIx64 " -> 0x%016" PRIx64 "\n", __func__, addr, data);

	return data;
}

uint32_t
mem_read32(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr)
{
	/* TODO: I/O devices */
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal read at 0x%016" PRIx64 "\n", addr);
		exception(sim, CAUSE_LOAD_ACCESS);
		return 0xdeadbeef;
	}
	uint32_t data;
	memcpy(&data, &mem->ram[addr - mem->ram_phys_base], 4);

	if (sim->trace & AEHNELN_TRACE_MEM)
		fprintf(stdout, "%s: 0x%016" PRIx64 " -> 0x%08" PRIx32 "\n", __func__, addr, data);

	return data;
}

uint16_t
mem_read16(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr)
{
	/* TODO: I/O devices */
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal read at 0x%016" PRIx64 "\n", addr);
		exception(sim, CAUSE_LOAD_ACCESS);
		return 0xbeef;
	}
	uint16_t data;
	memcpy(&data, &mem->ram[addr - mem->ram_phys_base], 2);

	if (sim->trace & AEHNELN_TRACE_MEM)
		fprintf(stdout, "%s: 0x%016" PRIx64 " -> 0x%04" PRIx16 "\n", __func__, addr, data);

	return data;
}

uint8_t
mem_read8(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr)
{
	/* TODO: I/O devices */
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal read at 0x%016" PRIx64 "\n", addr);
		exception(sim, CAUSE_LOAD_ACCESS);
		return 0xff;
	}
	uint8_t data;
	memcpy(&data, &mem->ram[addr - mem->ram_phys_base], 1);

	if (sim->trace & AEHNELN_TRACE_MEM)
		fprintf(stdout, "%s: 0x%016" PRIx64 " -> 0x%02" PRIx8 "\n", __func__, addr, data);

	return data;
}

void
mem_write64(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr, uint64_t data)
{
	/* TODO: I/O devices */
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal write to 0x%016" PRIx64 " with 0x%016" PRIx64 "\n",
			    addr, data);
		exception(sim, CAUSE_STORE_ACCESS);
		return;
	}
	if (addr == MEM_TOHOST) {
		fprintf(stderr, "tohost: exit with %ld\n", data);
		exit(data == 1 ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	memcpy(&mem->ram[addr - mem->ram_phys_base], &data, 8);

	if (sim->trace & AEHNELN_TRACE_MEM)
		fprintf(stdout, "%s: 0x%016" PRIx64 " <- 0x%016" PRIx64 "\n", __func__, addr, data);
}

void
mem_write32(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr, uint32_t data)
{
	/* TODO: I/O devices */
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal write to 0x%016" PRIx64 " with 0x%08" PRIx32 "\n",
			    addr, data);
		exception(sim, CAUSE_STORE_ACCESS);
		return;
	}

	if (addr == MEM_TOHOST) {
		fprintf(stderr, "tohost: exit with %d\n", data);
		exit(data == 1 ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	memcpy(&mem->ram[addr - mem->ram_phys_base], &data, 4);

	if (sim->trace & AEHNELN_TRACE_MEM)
		fprintf(stdout, "%s: 0x%016" PRIx64 " <- 0x%08" PRIx32 "\n", __func__, addr, data);
}

void
mem_write16(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr, uint16_t data)
{
	/* TODO: I/O devices */
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal write to 0x%016" PRIx64 " with 0x%04" PRIx16 "\n",
			    addr, data);
		exception(sim, CAUSE_STORE_ACCESS);
		return;
	}

	if (addr == MEM_TOHOST) {
		fprintf(stderr, "tohost: exit with %d\n", data);
		exit(data == 1 ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	memcpy(&mem->ram[addr - mem->ram_phys_base], &data, 2);

	if (sim->trace & AEHNELN_TRACE_MEM)
		fprintf(stdout, "%s: 0x%016" PRIx64 " <- 0x%04" PRIx16 "\n", __func__, addr, data);
}

void
mem_write8(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr, uint8_t data)
{
	/* TODO: I/O devices */
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal write to 0x%016" PRIx64 " with 0x%02" PRIx8 "\n",
			    addr, data);
		exception(sim, CAUSE_STORE_ACCESS);
		return;
	}

	if (addr == MEM_TOHOST) {
		fprintf(stderr, "tohost: exit with %d\n", data);
		exit(data == 1 ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	memcpy(&mem->ram[addr - mem->ram_phys_base], &data, 1);

	if (sim->trace & AEHNELN_TRACE_MEM)
		fprintf(stdout, "%s: 0x%016" PRIx64 " <- 0x%02" PRIx8 "\n", __func__, addr, data);
}

void
printf_machine_state(struct sim_ctx *sim)
{
	printf("--------machine state-----------------\n");
	printf(" pc=0x%016" PRIx64 " ins=0x%08" PRIx32 "\n", sim->pc, sim->insn);
	printf(" x0=0x%016" PRIx64 "  ra=0x%016" PRIx64 "\n", sim->regs[0], sim->regs[1]);
	printf(" sp=0x%016" PRIx64 "  gp=0x%016" PRIx64 "\n", sim->regs[2], sim->regs[3]);
	printf(" tp=0x%016" PRIx64 "  t0=0x%016" PRIx64 "\n", sim->regs[4], sim->regs[5]);
	printf(" t1=0x%016" PRIx64 "  t2=0x%016" PRIx64 "\n", sim->regs[6], sim->regs[7]);
	printf(" s0=0x%016" PRIx64 "  s1=0x%016" PRIx64 "\n", sim->regs[8], sim->regs[9]);
	printf(" a0=0x%016" PRIx64 "  a1=0x%016" PRIx64 "\n", sim->regs[10], sim->regs[11]);
	printf(" a2=0x%016" PRIx64 "  a3=0x%016" PRIx64 "\n", sim->regs[12], sim->regs[13]);
	printf(" a4=0x%016" PRIx64 "  a5=0x%016" PRIx64 "\n", sim->regs[14], sim->regs[15]);
	printf(" a6=0x%016" PRIx64 "  a7=0x%016" PRIx64 "\n", sim->regs[16], sim->regs[17]);
	printf(" s2=0x%016" PRIx64 "  s3=0x%016" PRIx64 "\n", sim->regs[18], sim->regs[19]);
	printf(" s4=0x%016" PRIx64 "  s5=0x%016" PRIx64 "\n", sim->regs[20], sim->regs[21]);
	printf(" s6=0x%016" PRIx64 "  s7=0x%016" PRIx64 "\n", sim->regs[22], sim->regs[23]);
	printf(" s8=0x%016" PRIx64 "  s9=0x%016" PRIx64 "\n", sim->regs[24], sim->regs[25]);
	printf("s10=0x%016" PRIx64 " s11=0x%016" PRIx64 "\n", sim->regs[26], sim->regs[27]);
	printf(" t3=0x%016" PRIx64 "  t4=0x%016" PRIx64 "\n", sim->regs[28], sim->regs[29]);
	printf(" t5=0x%016" PRIx64 "  t6=0x%016" PRIx64 "\n", sim->regs[30], sim->regs[31]);
	printf("prv=%d\n", sim->priv);
	printf("------------------------------------\n");
}

#define SIM_UNIMPLEMENTED()                                                               \
	(void)mem;                                                                        \
	fprintf(stderr, "%s(): unimplemented insn=0x%08" PRIx32 " pc=0x%016" PRIx64 "\n", \
	    __func__, sim->insn, sim->pc);                                                \
	exit(EXIT_FAILURE);

#define FIELD(NAME) INSN_FIELD(NAME, sim->insn)
#define GET_REG(NAME) (NAME ? sim->regs[NAME] : 0)
#define REG(NAME) (sim->regs[NAME])

#define U_ITYPE_IMM(x) RV_X(x, 20, 12)
#define ITYPE_IMM(x) SEXT(RV_X(x, 20, 12), 12)
#define STYPE_IMM(x) SEXT(RV_X(x, 7, 5) | (RV_X(x, 25, 7) << 5), 12)
#define BTYPE_IMM(x)                                                                \
	SEXT((RV_X(x, 8, 4) << 1) | (RV_X(x, 25, 6) << 5) | (RV_X(x, 7, 1) << 11) | \
		(RV_X(x, 31, 1) << 12),                                             \
	    13)
#define UTYPE_IMM(x) SEXT(RV_X(x, 12, 20) << 12, 32)
#define JTYPE_IMM(x)                                                                    \
	SEXT((RV_X(x, 21, 10) << 1) | (RV_X(x, 20, 1) << 11) | (RV_X(x, 12, 8) << 12) | \
		(RV_X(x, 31, 1) << 20),                                                 \
	    21)

void
sim_add(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) + GET_REG(FIELD(RS2));
}
void
sim_addi(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn);
}
void
sim_addiw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn);
	REG(FIELD(RD)) = SEXT(GET_REG(FIELD(RD)), 32);
}
void
sim_addw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) + GET_REG(FIELD(RS2));
	REG(FIELD(RD)) = SEXT(GET_REG(FIELD(RD)), 32);
}
void
sim_amoadd_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_amoand_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_amomax_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_amomaxu_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_amomin_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_amominu_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_amoor_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_amoswap_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_amoxor_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_and(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) & GET_REG(FIELD(RS2));
}
void
sim_andi(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) & ITYPE_IMM(sim->insn);
}
void
sim_auipc(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = UTYPE_IMM(sim->insn) + sim->pc;
}
void
sim_beq(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	if (GET_REG(FIELD(RS1)) == GET_REG(FIELD(RS2)))
		sim->pc_next = sim->pc + BTYPE_IMM(sim->insn);
}
void
sim_bge(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	if ((int64_t)GET_REG(FIELD(RS1)) >= (int64_t)GET_REG(FIELD(RS2)))
		sim->pc_next = sim->pc + BTYPE_IMM(sim->insn);
}
void
sim_bgeu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	if (GET_REG(FIELD(RS1)) >= GET_REG(FIELD(RS2)))
		sim->pc_next = sim->pc + BTYPE_IMM(sim->insn);
}
void
sim_blt(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	if ((int64_t)GET_REG(FIELD(RS1)) < (int64_t)GET_REG(FIELD(RS2)))
		sim->pc_next = sim->pc + BTYPE_IMM(sim->insn);
}
void
sim_bltu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	if (GET_REG(FIELD(RS1)) < GET_REG(FIELD(RS2)))
		sim->pc_next = sim->pc + BTYPE_IMM(sim->insn);
}
void
sim_bne(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	if (GET_REG(FIELD(RS1)) != GET_REG(FIELD(RS2)))
		sim->pc_next = sim->pc + BTYPE_IMM(sim->insn);
}
void
sim_c_addiw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_c_addw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_c_ld(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_c_ldsp(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_c_sd(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_c_sdsp(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_c_slli(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_c_srai(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_c_srli(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_c_subw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) - GET_REG(FIELD(RS2));
	REG(FIELD(RD)) = SEXT(GET_REG(FIELD(RD)), 32);
}

#define CSR_PRIV_LVL(csr) RV_X(csr, 8, 2)
#define CSR_READONLY(csr) (RV_X(csr, 10, 2) == 3)

/* write VALUE to VAR preserving bits indicated by MASK (making them read-only) */
#define WRITE_PRESERVE_BITS(VAR, MASK, VALUE) (((VAR) & (MASK)) | ((VALUE) & (~MASK)))
/* read VALUE VAR zeroing bits indicated by MASK (making them "invisible") */
#define READ_ZEROD_BITS(VAR, MASK) ((VAR) & (~MASK))

static void
csrrc_generic(struct sim_ctx *sim, int csr_val, uint64_t csr_arg)
{

	switch (csr_val) {
		/* machine mode */
	case CSR_MHARTID:
		REG(FIELD(RD)) = CORE0_HARTID;
		break;
	case CSR_MSTATUS:
		REG(FIELD(RD)) = sim->mstatus;
		sim->mstatus = WRITE_PRESERVE_BITS(sim->mstatus, MSTATUS_WMASK,
		    sim->mstatus & ~csr_arg);
		break;
	case CSR_MISA:
		REG(FIELD(RD)) = sim->misa;
		break;
	case CSR_MIMPID:
		REG(FIELD(RD)) = sim->mimpid;
		break;
	case CSR_MARCHID:
		REG(FIELD(RD)) = sim->marchid;
		break;
	case CSR_MVENDORID:
		REG(FIELD(RD)) = sim->mvendorid;
		break;
	case CSR_MSCRATCH:
		REG(FIELD(RD)) = sim->mscratch;
		sim->mscratch &= ~csr_arg;
		break;
	case CSR_MEDELEG:
		/* bit 11 is read-only zero */
		REG(FIELD(RD)) = sim->medeleg;
		sim->medeleg &= ~csr_arg;
		sim->medeleg &= ~CAUSE_MACHINE_ECALL;
		break;
	case CSR_MIDELEG:
		REG(FIELD(RD)) = sim->mideleg;
		sim->mideleg &= ~csr_arg;
		break;
	case CSR_MIE:
		REG(FIELD(RD)) = sim->mie;
		sim->mie &= ~csr_arg;
		break;
	case CSR_MIP:
		REG(FIELD(RD)) = sim->mip;
		sim->mip &= ~csr_arg;
		break;
	case CSR_MTVEC:
		REG(FIELD(RD)) = sim->mtvec & ~3;
		sim->mtvec &= ~csr_arg;
		break;
	case CSR_MEPC:
		REG(FIELD(RD)) = sim->mepc;
		sim->mepc &= ~csr_arg;
		sim->mepc &= ~1;
		break;
	case CSR_MCAUSE:
		REG(FIELD(RD)) = sim->mcause;
		sim->mcause &= ~csr_arg;
		sim->mcause &= MCAUSE_MASK;
		break;
		/* supervisor mode */
	case CSR_SATP:
		REG(FIELD(RD)) = sim->satp;
		sim->satp &= ~csr_arg;
		break;
	case CSR_SSTATUS:
		REG(FIELD(RD)) = READ_ZEROD_BITS(sim->mstatus, SSTATUS_RMASK);
		sim->mstatus = WRITE_PRESERVE_BITS(sim->mstatus, SSTATUS_WMASK,
		    sim->mstatus & ~csr_arg);
		break;
	case CSR_SIE:
		REG(FIELD(RD)) = sim->sie;
		sim->sie &= ~csr_arg;
		break;
	case CSR_SIP:
		REG(FIELD(RD)) = sim->sip;
		sim->sip &= ~csr_arg;
		break;
	case CSR_STVEC:
		REG(FIELD(RD)) = sim->stvec & ~3;
		sim->stvec &= ~csr_arg;
		break;
	case CSR_SEPC:
		REG(FIELD(RD)) = sim->sepc;
		sim->sepc &= ~csr_arg;
		sim->sepc &= ~1;
		break;
	case CSR_SCAUSE:
		REG(FIELD(RD)) = sim->scause;
		sim->scause &= ~csr_arg;
		sim->scause &= SCAUSE_MASK;
		break;
	case CSR_SSCRATCH:
		REG(FIELD(RD)) = sim->sscratch;
		sim->sscratch &= ~csr_arg;
		break;
		/* user mode */
	case CSR_CYCLE:
		REG(FIELD(RD)) = sim->cycle;
		break;
	default:
		if (sim->trace & AEHNELN_TRACE_UNKNOWN_CSR)
			fprintf(stderr, "unknown csr 0x%03" PRIx32 "\n", U_ITYPE_IMM(sim->insn));
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION);
		break;
	}
}

void
sim_csrrc(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	int csr_val = U_ITYPE_IMM(sim->insn);
	uint64_t csr_arg = GET_REG(FIELD(RS1));

	/* we don't have enough privileges or we write to a read-only csr */
	if (!(sim->priv >= CSR_PRIV_LVL(csr_val)) || (FIELD(RS1) != 0 && CSR_READONLY(csr_val))) {
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION);
		return;
	}

	csrrc_generic(sim, csr_val, csr_arg);
}

void
sim_csrrci(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	int csr_val = U_ITYPE_IMM(sim->insn);
	uint64_t csr_arg = FIELD(RS1);

	/* we don't have enough privileges or we write to a read-only csr */
	if (!(sim->priv >= CSR_PRIV_LVL(csr_val)) || (FIELD(RS1) != 0 && CSR_READONLY(csr_val))) {
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION);
		return;
	}

	csrrc_generic(sim, csr_val, csr_arg);
}

static void
csrrs_generic(struct sim_ctx *sim, int csr_val, uint64_t csr_arg)
{

	switch (csr_val) {
		/* machine mode */
	case CSR_MHARTID:
		REG(FIELD(RD)) = CORE0_HARTID;
		break;
	case CSR_MSTATUS:
		REG(FIELD(RD)) = sim->mstatus;
		sim->mstatus = WRITE_PRESERVE_BITS(sim->mstatus, MSTATUS_WMASK,
		    sim->mstatus | csr_arg);
		break;
	case CSR_MISA:
		REG(FIELD(RD)) = sim->misa;
		break;
	case CSR_MIMPID:
		REG(FIELD(RD)) = sim->mimpid;
		break;
	case CSR_MARCHID:
		REG(FIELD(RD)) = sim->marchid;
		break;
	case CSR_MVENDORID:
		REG(FIELD(RD)) = sim->mvendorid;
		break;
	case CSR_MSCRATCH:
		REG(FIELD(RD)) = sim->mscratch;
		sim->mscratch |= csr_arg;
		break;
	case CSR_MEDELEG:
		REG(FIELD(RD)) = sim->medeleg;
		sim->medeleg |= csr_arg;
		sim->medeleg &= ~CAUSE_MACHINE_ECALL;
		break;
	case CSR_MIDELEG:
		REG(FIELD(RD)) = sim->mideleg;
		sim->mideleg |= csr_arg;
		break;
	case CSR_MIE:
		REG(FIELD(RD)) = sim->mie;
		sim->mie |= csr_arg;
		break;
	case CSR_MIP:
		REG(FIELD(RD)) = sim->mip;
		sim->mip |= csr_arg;
		break;
	case CSR_MTVEC:
		REG(FIELD(RD)) = sim->mtvec & ~3;
		sim->mtvec |= csr_arg;
		break;
	case CSR_MEPC:
		REG(FIELD(RD)) = sim->mepc;
		sim->mepc |= csr_arg;
		sim->mepc &= ~1;
		break;
	case CSR_MCAUSE:
		REG(FIELD(RD)) = sim->mcause;
		sim->mcause |= csr_arg;
		sim->mcause &= MCAUSE_MASK;
		break;
		/* supervisor mode */
	case CSR_SATP:
		REG(FIELD(RD)) = sim->satp;
		sim->satp |= csr_arg;
		break;
	case CSR_SSTATUS:
		REG(FIELD(RD)) = READ_ZEROD_BITS(sim->mstatus, SSTATUS_RMASK);
		sim->mstatus = WRITE_PRESERVE_BITS(sim->mstatus, SSTATUS_WMASK,
		    sim->mstatus | csr_arg);
		break;
	case CSR_SIE:
		REG(FIELD(RD)) = sim->sie;
		sim->sie |= csr_arg;
		break;
	case CSR_SIP:
		REG(FIELD(RD)) = sim->sip;
		sim->sip |= csr_arg;
		break;
	case CSR_STVEC:
		REG(FIELD(RD)) = sim->stvec & ~3;
		sim->stvec |= csr_arg;
		break;
	case CSR_SEPC:
		REG(FIELD(RD)) = sim->sepc;
		sim->sepc |= csr_arg;
		sim->sepc &= ~1;
		break;
	case CSR_SCAUSE:
		REG(FIELD(RD)) = sim->scause;
		sim->scause |= csr_arg;
		sim->scause &= SCAUSE_MASK;
		break;
	case CSR_SSCRATCH:
		REG(FIELD(RD)) = sim->sscratch;
		sim->sscratch |= csr_arg;
		break;
		/* user mode */
	case CSR_CYCLE:
		REG(FIELD(RD)) = sim->cycle;
		break;
	default:
		if (sim->trace & AEHNELN_TRACE_UNKNOWN_CSR)
			fprintf(stderr, "unknown csr 0x%03" PRIx32 "\n", U_ITYPE_IMM(sim->insn));
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION);
		break;
	}
}

void
sim_csrrs(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	int csr_val = U_ITYPE_IMM(sim->insn);
	uint64_t csr_arg = GET_REG(FIELD(RS1));

	/* we don't have enough privileges or we write to a read-only csr*/
	if (!(sim->priv >= CSR_PRIV_LVL(csr_val)) || (FIELD(RS1) != 0 && CSR_READONLY(csr_val))) {
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION);
		return;
	}

	csrrs_generic(sim, csr_val, csr_arg);
}
void
sim_csrrsi(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	int csr_val = U_ITYPE_IMM(sim->insn);
	uint64_t csr_arg = FIELD(RS1);

	/* we don't have enough privileges or we write to a read-only csr */
	if (!(sim->priv >= CSR_PRIV_LVL(csr_val)) || (FIELD(RS1) != 0 && CSR_READONLY(csr_val))) {
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION);
		return;
	}

	csrrs_generic(sim, csr_val, csr_arg);
}

static void
csrrw_generic(struct sim_ctx *sim, int csr_val, uint64_t csr_arg)
{
	switch (csr_val) {
		/* machine mode */
	case CSR_MHARTID:
		REG(FIELD(RD)) = CORE0_HARTID;
		break;
	case CSR_MSTATUS:
		REG(FIELD(RD)) = sim->mstatus;
		sim->mstatus = WRITE_PRESERVE_BITS(sim->mstatus, MSTATUS_WMASK, csr_arg);
		break;
	case CSR_MISA:
		REG(FIELD(RD)) = sim->misa;
		break;
	case CSR_MIMPID:
		REG(FIELD(RD)) = sim->mimpid;
		break;
	case CSR_MARCHID:
		REG(FIELD(RD)) = sim->marchid;
		break;
	case CSR_MVENDORID:
		REG(FIELD(RD)) = sim->mvendorid;
		break;
	case CSR_MSCRATCH:
		REG(FIELD(RD)) = sim->mscratch;
		sim->mscratch = csr_arg;
		break;
	case CSR_MEDELEG:
		REG(FIELD(RD)) = sim->medeleg;
		sim->medeleg = csr_arg;
		sim->medeleg &= ~CAUSE_MACHINE_ECALL;
		break;
	case CSR_MIDELEG:
		REG(FIELD(RD)) = sim->mideleg;
		sim->mideleg = csr_arg;
		break;
	case CSR_MIE:
		REG(FIELD(RD)) = sim->mie;
		sim->mie = csr_arg;
		break;
	case CSR_MIP:
		REG(FIELD(RD)) = sim->mip;
		sim->mip = csr_arg;
		break;
	case CSR_MTVEC:
		REG(FIELD(RD)) = sim->mtvec & ~3;
		sim->mtvec = csr_arg;
		break;
	case CSR_MEPC:
		REG(FIELD(RD)) = sim->mepc;
		sim->mepc = csr_arg;
		sim->mepc &= ~1;
		break;
	case CSR_MCAUSE:
		REG(FIELD(RD)) = sim->mcause;
		sim->mcause = csr_arg;
		sim->mcause &= MCAUSE_MASK;
		break;
		/* supervisor mode */
	case CSR_SATP:
		REG(FIELD(RD)) = sim->satp;
		sim->satp = csr_arg;
		break;
	case CSR_SSTATUS:
		REG(FIELD(RD)) = READ_ZEROD_BITS(sim->mstatus, SSTATUS_RMASK);
		sim->mstatus = WRITE_PRESERVE_BITS(sim->mstatus, SSTATUS_WMASK, csr_arg);
		break;
	case CSR_SIE:
		REG(FIELD(RD)) = sim->sie;
		sim->sie = csr_arg;
		break;
	case CSR_SIP:
		REG(FIELD(RD)) = sim->sip;
		sim->sip = csr_arg;
		break;
	case CSR_STVEC:
		REG(FIELD(RD)) = sim->stvec & ~3;
		sim->stvec = csr_arg;
		break;
	case CSR_SEPC:
		REG(FIELD(RD)) = sim->sepc;
		sim->sepc = csr_arg;
		sim->sepc &= ~1;
		break;
	case CSR_SCAUSE:
		REG(FIELD(RD)) = sim->scause;
		sim->scause = csr_arg;
		sim->scause &= SCAUSE_MASK;
		break;
	case CSR_SSCRATCH:
		REG(FIELD(RD)) = sim->sscratch;
		sim->sscratch = csr_arg;
		break;
		/* user mode */
	case CSR_CYCLE:
		REG(FIELD(RD)) = sim->cycle;
		break;
	default:
		if (sim->trace & AEHNELN_TRACE_UNKNOWN_CSR)
			fprintf(stderr, "unknown csr 0x%03" PRIx32 "\n", U_ITYPE_IMM(sim->insn));
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION);
		break;
	}
}

void
sim_csrrw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	int csr_val = U_ITYPE_IMM(sim->insn);
	uint64_t csr_arg = GET_REG(FIELD(RS1));

	/* we don't have enough privileges or we write to a read-only csr */
	if (!(sim->priv >= CSR_PRIV_LVL(csr_val)) || CSR_READONLY(csr_val)) {
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION);
		return;
	}

	csrrw_generic(sim, csr_val, csr_arg);
}

void
sim_csrrwi(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	int csr_val = U_ITYPE_IMM(sim->insn);
	uint64_t csr_arg = FIELD(RS1);

	/* we don't have enough privileges or we write to a read-only csr */
	if (!(sim->priv >= CSR_PRIV_LVL(csr_val)) || CSR_READONLY(csr_val)) {
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION);
		return;
	}

	csrrw_generic(sim, csr_val, csr_arg);
}
void
sim_divuw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_divw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_dret(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}

void
sim_ebreak(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	exception(sim, CAUSE_BREAKPOINT);
}
void
sim_ecall(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	/* transition to machine mode */
	if (sim->priv == PRV_M)
		exception(sim, CAUSE_MACHINE_ECALL);
	else if (sim->priv == PRV_S)
		exception(sim, CAUSE_SUPERVISOR_ECALL);
	else if (sim->priv == PRV_U)
		exception(sim, CAUSE_USER_ECALL);
}

void
sim_fcvt_d_l(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_fcvt_d_lu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_fcvt_l_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_fcvt_l_s(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_fcvt_lu_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_fcvt_lu_s(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_fcvt_s_l(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_fcvt_s_lu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_fence(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)sim;
	(void)mem;
	/* nop */
}
void
sim_fence_i(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)sim;
	(void)mem;
	/* nop */
}
void
sim_fmv_d_x(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_fmv_x_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_jal(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = sim->pc + 4;
	sim->pc_next = sim->pc + JTYPE_IMM(sim->insn);
}
void
sim_jalr(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = sim->pc + 4;
	sim->pc_next = GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn);
	sim->pc_next &= ~1;
}
void
sim_lb(struct sim_ctx *sim, struct mem_ctx *mem)
{
	uint64_t val = SEXT(mem_vread16(sim, mem, GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn)), 8);
	if (!(sim->is_exception && sim->generic_cause == CAUSE_LOAD_ACCESS))
		REG(FIELD(RD)) = val;
}
void
sim_lbu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	uint64_t val = mem_vread8(sim, mem, GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn));
	if (!(sim->is_exception && sim->generic_cause == CAUSE_LOAD_ACCESS))
		REG(FIELD(RD)) = val;
}
void
sim_ld(struct sim_ctx *sim, struct mem_ctx *mem)
{
	uint64_t val = mem_vread64(sim, mem, GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn));
	if (!(sim->is_exception && sim->generic_cause == CAUSE_LOAD_ACCESS))
		REG(FIELD(RD)) = val;
}
void
sim_lh(struct sim_ctx *sim, struct mem_ctx *mem)
{
	uint64_t val = SEXT(mem_vread16(sim, mem, GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn)), 16);
	if (!(sim->is_exception && sim->generic_cause == CAUSE_LOAD_ACCESS))
		REG(FIELD(RD)) = val;
}
void
sim_lhu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	uint64_t val = mem_vread16(sim, mem, GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn));
	if (!(sim->is_exception && sim->generic_cause == CAUSE_LOAD_ACCESS))
		REG(FIELD(RD)) = val;
}

void
sim_lr_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_lui(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = UTYPE_IMM(sim->insn);
	REG(FIELD(RD)) = SEXT(GET_REG(FIELD(RD)), 32);
}
void
sim_lw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	uint64_t val = SEXT(mem_vread32(sim, mem, GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn)), 32);
	if (!(sim->is_exception && sim->generic_cause == CAUSE_LOAD_ACCESS))
		REG(FIELD(RD)) = val;
}
void
sim_lwu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	uint64_t val = mem_vread32(sim, mem, GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn));
	if (!(sim->is_exception && sim->generic_cause == CAUSE_LOAD_ACCESS))
		REG(FIELD(RD)) = val;
}
void
sim_mret(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	/* mret works only in m-mode */
	if (!(sim->priv >= PRV_M)) {
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION);
		return;
	}
	/* Privilege mode updates according to privileged spec 3.3.2
	 * y = mpp
	 * mie = mpie
	 * priv = y
	 * mpie = 1
	 * mpp = u mode
	 * if mpp != m then mprv=0
	 */

	int mpp = CSR_FIELD_READ(sim->mstatus, MSTATUS_MPP);
	int mpie = CSR_FIELD_READ(sim->mstatus, MSTATUS_MPIE);
	sim->priv = mpp;
	sim->mstatus = CSR_FIELD_WRITE(sim->mstatus, MSTATUS_MIE, mpie);
	sim->mstatus = CSR_FIELD_WRITE(sim->mstatus, MSTATUS_MPIE, 1);
	sim->mstatus = CSR_FIELD_WRITE(sim->mstatus, MSTATUS_MPP, PRV_U);
	if (mpp != PRV_M)
		sim->mstatus = CSR_FIELD_WRITE(sim->mstatus, MSTATUS_MPRV, 0);
	/* now return */
	sim->pc_next = sim->mepc;
}

void
sim_mulw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_or(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) | GET_REG(FIELD(RS2));
}
void
sim_ori(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) | ITYPE_IMM(sim->insn);
}
void
sim_pause(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)sim;
	(void)mem;
	/* nop */
}
void
sim_remuw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_remw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_sb(struct sim_ctx *sim, struct mem_ctx *mem)
{
	mem_vwrite8(sim, mem, GET_REG(FIELD(RS1)) + STYPE_IMM(sim->insn),
	    (uint8_t)GET_REG(FIELD(RS2)));
}
void
sim_sc_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_sd(struct sim_ctx *sim, struct mem_ctx *mem)
{
	mem_vwrite64(sim, mem, GET_REG(FIELD(RS1)) + STYPE_IMM(sim->insn),
	    (uint64_t)GET_REG(FIELD(RS2)));
}
void
sim_sfence_vma(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)sim;
	(void)mem;
	/* since we walk the full page table on each access our sfence is just a
	 * nop (there is no translation cache) */
}
void
sim_sh(struct sim_ctx *sim, struct mem_ctx *mem)
{
	mem_vwrite16(sim, mem, GET_REG(FIELD(RS1)) + STYPE_IMM(sim->insn),
	    (uint16_t)GET_REG(FIELD(RS2)));
}
void
sim_sll(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) << (GET_REG(FIELD(RS2)) & 0x3f);
}
void
sim_slli(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) << FIELD(SHAMTD);
}
void
sim_slliw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) << FIELD(SHAMTW);
	REG(FIELD(RD)) = SEXT(GET_REG(FIELD(RD)), 32);
}
void
sim_sllw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) << (GET_REG(FIELD(RS2)) & 0x1f);
	REG(FIELD(RD)) = SEXT(GET_REG(FIELD(RD)), 32);
}
void
sim_slt(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = ((int64_t)GET_REG(FIELD(RS1))) < ((int64_t)GET_REG(FIELD(RS2)));
}
void
sim_slti(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = ((int64_t)GET_REG(FIELD(RS1))) < ((int64_t)ITYPE_IMM(sim->insn));
}
void
sim_sltiu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) < ITYPE_IMM(sim->insn);
}
void
sim_sltu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) < GET_REG(FIELD(RS2));
}
void
sim_sra(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = ((int64_t)GET_REG(FIELD(RS1))) >> (GET_REG(FIELD(RS2)) & 0x3f);
}
void
sim_srai(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	/* c compiler needs to do artihmetic shift on signed types*/
	REG(FIELD(RD)) = ((int64_t)GET_REG(FIELD(RS1))) >> FIELD(SHAMTD);
}
void
sim_sraiw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	/* c compiler needs to do artihmetic shift on signed types*/
	REG(FIELD(RD)) = ((int32_t)GET_REG(FIELD(RS1))) >> FIELD(SHAMTW);
	REG(FIELD(RD)) = SEXT(GET_REG(FIELD(RD)), 32);
}
void
sim_sraw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = ((int32_t)GET_REG(FIELD(RS1))) >> (GET_REG(FIELD(RS2)) & 0x1f);
	REG(FIELD(RD)) = SEXT(GET_REG(FIELD(RD)), 32);
}
void
sim_sret(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	/* sret works in m-mode and s-mode. privileged-spec 3.3.2 and 3.1.6.1 */
	if (!(sim->priv >= PRV_S) || CSR_FIELD_READ(sim->mstatus, MSTATUS_TSR)) {
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION);
		return;
	}
	/* Privilege mode updates according to privileged spec 3.3.2
	 * y = spp
	 * sie = spie
	 * priv = y
	 * spie = 1
	 * spp = u mode
	 * if spp != m then mprv=0
	 */

	int spp = CSR_FIELD_READ(sim->mstatus, MSTATUS_SPP);
	int spie = CSR_FIELD_READ(sim->mstatus, MSTATUS_SPIE);
	sim->priv = spp;
	sim->mstatus = CSR_FIELD_WRITE(sim->mstatus, MSTATUS_SIE, spie);
	sim->mstatus = CSR_FIELD_WRITE(sim->mstatus, MSTATUS_SPIE, 1);
	sim->mstatus = CSR_FIELD_WRITE(sim->mstatus, MSTATUS_SPP, PRV_U);
	if (spp != PRV_M)
		sim->mstatus = CSR_FIELD_WRITE(sim->mstatus, MSTATUS_MPRV, 0);
	/* now return */
	sim->pc_next = sim->sepc;
}
void
sim_srl(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) >> (GET_REG(FIELD(RS2)) & 0x3f);
}
void
sim_srli(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) >> FIELD(SHAMTD);
}
void
sim_srliw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = ((uint32_t)GET_REG(FIELD(RS1))) >> FIELD(SHAMTW);
	REG(FIELD(RD)) = SEXT(GET_REG(FIELD(RD)), 32);
}
void
sim_srlw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = ((uint32_t)GET_REG(FIELD(RS1))) >> (GET_REG(FIELD(RS2)) & 0x1f);
	REG(FIELD(RD)) = SEXT(GET_REG(FIELD(RD)), 32);
}
void
sim_sub(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) - GET_REG(FIELD(RS2));
}
void
sim_subw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_sw(struct sim_ctx *sim, struct mem_ctx *mem)
{
	mem_vwrite32(sim, mem, GET_REG(FIELD(RS1)) + STYPE_IMM(sim->insn),
	    (uint32_t)GET_REG(FIELD(RS2)));
}
void
sim_wfi(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)sim;
	(void)mem;
	/* nop */
}
void
sim_xor(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) ^ GET_REG(FIELD(RS2));
}
void
sim_xori(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) ^ ITYPE_IMM(sim->insn);
}

#undef FIELD
#undef REG

void
asim(struct sim_ctx *sim, struct mem_ctx *mem)
{
	assert(sim);
	assert(mem);

	for (;;) {
		uint32_t insn = mem_insn_vread(sim, mem, sim->pc);
		if (sim->trace & AEHNELN_TRACE_INSN)
			printf("priv=%d pc=0x%016" PRIx64 " insn=0x%08" PRIx32 "\n", sim->priv,
			    sim->pc, insn);
#define __riscv_xlen 64
#define DECLARE_INSN(fun, match, mask)   \
	else if ((insn & mask) == match) \
	{                                \
		sim_##fun(sim, mem);     \
	}

		/* store current pc and insn */
		sim->pc = sim->pc;
		sim->insn = insn;

		/* next natural pc. Overwritten by branches, jumps and compressed insns */
		sim->pc_next = sim->pc + 4;

		/* get the first branch going */
		if (sim->is_exception) {
			/* don't decode insn fetch exceptions */
		}
		/* TODO: inefficient decoding */
#include "encoding.out.h"
		else {
			fprintf(stderr,
			    "oops illegal instruction pc=0x%016" PRIx64 " insn=0x%08" PRIx32 "\n",
			    sim->pc, insn);
			exit(EXIT_FAILURE);
		}
#undef DECLARE_INSN

		/* update cycle counters */
		sim->cycle += 1;

		/* update pc according to machine state (normal, exception, interrupt) */
		if (sim->is_exception && sim->priv <= PRV_S &&
		    ((sim->medeleg >> sim->generic_cause) & 1)) {
			/* take exception in supervisor mode (riscv-privileged 3.1.8) */
			int sie = CSR_FIELD_READ(sim->mstatus, SSTATUS_SIE);
			/* save previous int state */
			sim->mstatus = CSR_FIELD_WRITE(sim->mstatus, SSTATUS_SPIE, sie);
			/* disable interrupts */
			sim->mstatus = CSR_FIELD_WRITE(sim->mstatus, SSTATUS_SIE, 0);
			/* save previous priv state */
			sim->mstatus = CSR_FIELD_WRITE(sim->mstatus, SSTATUS_SPP, sim->priv);
			/* go to supervisor mode */
			sim->priv = PRV_S;
			sim->sepc = sim->pc;
			sim->scause = sim->generic_cause;
			sim->is_exception = false;

			if ((sim->trace & AEHNELN_TRACE_ILLEGAL) &&
			    sim->generic_cause == CAUSE_ILLEGAL_INSTRUCTION) {
				fprintf(stderr,
				    "traced illegal instruction pc=0x%016" PRIx64
				    " insn=0x%08" PRIx32 " stvec=0x%08" PRIx64 "\n",
				    sim->pc, insn, sim->stvec);
			}
			if ((sim->stvec & 3) == 0) {
				/* direct mode */
				sim->pc = sim->stvec;
			} else {
				/* vectored mode */
				fprintf(stderr, "vectored mode not implemented");
				exit(EXIT_FAILURE);
			}

		} else if (sim->is_exception) {
			/* take exception in machine mode (riscv-privileged 3.1.6.1) */
			int mie = CSR_FIELD_READ(sim->mstatus, MSTATUS_MIE);
			/* save previous int state */
			sim->mstatus = CSR_FIELD_WRITE(sim->mstatus, MSTATUS_MPIE, mie);
			/* disable interrupts */
			sim->mstatus = CSR_FIELD_WRITE(sim->mstatus, MSTATUS_MIE, 0);
			/* save previous priv state */
			sim->mstatus = CSR_FIELD_WRITE(sim->mstatus, MSTATUS_MPP, sim->priv);
			/* go to machine mode */
			sim->priv = PRV_M;
			sim->mepc = sim->pc;
			sim->mcause = sim->generic_cause;
			sim->is_exception = false;

			if ((sim->trace & AEHNELN_TRACE_ILLEGAL) &&
			    sim->generic_cause == CAUSE_ILLEGAL_INSTRUCTION) {
				fprintf(stderr,
				    "traced illegal instruction pc=0x%016" PRIx64
				    " insn=0x%08" PRIx32 " mtvec=0x%08" PRIx64 "\n",
				    sim->pc, insn, sim->mtvec);
			}
			if ((sim->mtvec & 3) == 0) {
				/* direct mode */
				sim->pc = sim->mtvec;
			} else {
				/* vectored mode */
				fprintf(stderr, "vectored mode not implemented");
				exit(EXIT_FAILURE);
			}
		} else {
			sim->pc = sim->pc_next;
		}
	}
}

int
main(int argc, char *argv[])
{
	int c;
	int trace = false;

	while (1) {
		__attribute__((unused)) int this_option_optind = optind ? optind : 1;
		int option_index = 0;
		static struct option long_options[] = {
			{ "trace", no_argument, 0, 'd' },
			{ "help", no_argument, 0, 'h' },
		};

		c = getopt_long(argc, argv, "?h", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			break;

		case 'd':
			trace |= AEHNELN_TRACE_INSN;
			trace |= AEHNELN_TRACE_MEM;
			trace |= AEHNELN_TRACE_ILLEGAL;
			trace |= AEHNELN_TRACE_UNKNOWN_CSR;
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
		printf("opening %s ...\n", argv[optind]);
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

	/* load elf */
	struct elf elf = { 0 };
	map_binary(&elf, elf_name);

	int err;
	struct mem_ctx mem = { 0 };

	/* initialize physical memory */
	err = mem_ctx_init(&mem);
	if (err) {
		fprintf(stderr, "mem_ctx_init()\n");
		return EXIT_FAILURE;
	}

	err = mem_ctx_copy_elf(&mem, elf.bytes, MEM_RAM_BASE, elf.size);

	if (err) {
		fprintf(stderr, "mem_ctx_copy_elf()\n");
		return EXIT_FAILURE;
	}

	/* initialize and start sim */
	struct sim_ctx sim = { 0 };
	sim.regs[0] = 0;
	sim.trace = trace;
	sim.priv = PRV_M;
	sim.pc = MEM_RAM_BASE;

	/* we are a rv64 machine */
	sim.misa |= BIT(MISA_I);
	sim.misa |= BIT(MISA_M);
	sim.misa |= BIT(MISA_A);
	sim.misa |= (MISA_MXL_64 << 62);

	sim.mstatus |= (MISA_MXL_64 << OFFSET(MSTATUS_UXL));
	sim.mstatus |= (MISA_MXL_64 << OFFSET(MSTATUS_SXL));

	sim.mimpid = 1;
	sim.marchid = 1;
	sim.mvendorid = 0; /* non-commercial */

	asim(&sim, &mem);

	return EXIT_SUCCESS;
}
