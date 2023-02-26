/* SPDX-License-Identifier: MIT */
#include <sys/mman.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <getopt.h>
#include <inttypes.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aehneln.h"
#include "config.h"

#define aehneln_perror(msg)         \
	do {                        \
		perror(msg);        \
		exit(EXIT_FAILURE); \
	} while (0)

int debug = 0;

static void
aehneln_elf_error()
{
	(void)fprintf(stderr, "%s\n", elf_errmsg(elf_errno()));
	exit(EXIT_FAILURE);
}

static void
aehneln_error(const char *msg)
{
	(void)fprintf(stderr, "%s\n", msg);
	exit(EXIT_FAILURE);
}

void
print_usage(void)
{
	printf("Usage: " PACKAGE " RISCV-ELF\n");
}

__attribute__((unused)) void
hexdump(const void *data, size_t size)
{
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char *)data)[i]);
		if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char *)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

/* map binary file into host system memory */
static void
map_binary(struct bin *bin, char *name)
{
	struct stat sb = { 0 };
	off_t pa_offset = 0;
	char *addr = NULL;

	/* mmap bin file into memory */
	int fd = open(name, O_RDONLY);
	if (fd == -1)
		aehneln_perror("open");

	if (fstat(fd, &sb) == -1)
		aehneln_perror("fstat");

	addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, pa_offset);
	if (addr == MAP_FAILED)
		aehneln_perror("mmap");

	close(fd);
	bin->bytes = addr;
	bin->size = sb.st_size;
}

void
load_bin(struct mem_ctx *mem, char *name)
{
	int err;
	struct bin bin = { 0 };

	map_binary(&bin, name);

	err = mem_ctx_copy_bin(mem, bin.bytes, MEM_RAM_BASE, bin.size);
	if (err)
		aehneln_error("mem_ctx_copy_bin\n");
}

void
load_elf(struct mem_ctx *mem, char *name)
{
	Elf64_Shdr *shdr;
	Elf64_Ehdr *ehdr;
	Elf *elf;
	Elf_Scn *scn;
	Elf_Data *data;
	unsigned int cnt;
	int fd;

	if ((fd = open(name, O_RDONLY)) == -1)
		aehneln_perror("open");

	if (elf_version(EV_CURRENT) == EV_NONE)
		aehneln_elf_error();

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		aehneln_elf_error();

	/* find loadable segments and load them into mem */
	size_t n;
	Elf64_Phdr *phdr;
	if (elf_getphdrnum(elf, &n) != 0)
		aehneln_elf_error();

	if ((phdr = elf64_getphdr(elf)) == NULL)
		aehneln_elf_error();

	for (size_t i = 0; i < n; i++) {
		if (debug & AEHNELN_DEBUG_ELF) {
			printf("PHDR %ld (%p):\n", i, &phdr[i]);
			printf("p_type   = %d\n", phdr[i].p_type);
			printf("p_offset = 0x%lx\n", phdr[i].p_offset);
			printf("p_vaddr  = 0x%lx\n", phdr[i].p_vaddr);
			printf("p_paddr  = 0x%lx\n", phdr[i].p_paddr);
			printf("p_filesz = 0x%lx\n", phdr[i].p_filesz);
			printf("p_memsz  = 0x%lx\n", phdr[i].p_memsz);
			printf("p_flags  = 0x%x [", phdr[i].p_flags);
			if (phdr[i].p_flags & PF_R)
				printf("r");
			if (phdr[i].p_flags & PF_W)
				printf("w");
			if (phdr[i].p_flags & PF_X)
				printf("x");
			printf("]\n");
			printf("p_align  = 0x%lx\n", phdr[i].p_align);
		}

		size_t elf_bytes;
		char *raw;
		if ((raw = elf_rawfile(elf, &elf_bytes)) == NULL)
			aehneln_elf_error();

		if (phdr[i].p_offset + phdr[i].p_filesz >= elf_bytes)
			aehneln_error("phdr out of range");

		if (phdr[i].p_type == PT_LOAD) {
			int ret = mem_ctx_copy_bin(mem, raw + phdr[i].p_offset, phdr[i].p_paddr,
			    phdr[i].p_filesz);
			if (ret != 0)
				aehneln_error("mem_ctx_copy_bin");

			if (debug & AEHNELN_DEBUG_ELF)
				hexdump(raw + phdr[i].p_offset, phdr[i].p_filesz);

			/* zero fill trailing bytes */
			if (phdr[i].p_filesz < phdr[i].p_memsz)
				mem_ctx_set(mem, 0, phdr[i].p_paddr + phdr[i].p_filesz,
				    phdr[i].p_memsz - phdr[i].p_filesz);
		}
	}

	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		aehneln_elf_error();

	if ((ehdr = elf64_getehdr(elf)) == NULL)
		aehneln_elf_error();

	if (((scn = elf_getscn(elf, ehdr->e_shstrndx)) == NULL))
		aehneln_elf_error();

	if (((data = elf_getdata(scn, NULL)) == NULL))
		aehneln_elf_error();

	/* traverse input filename, printing each section */
	for (cnt = 1, scn = NULL; (scn = elf_nextscn(elf, scn)); cnt++) {
		if ((shdr = elf64_getshdr(scn)) == NULL)
			aehneln_elf_error();

		if (debug & AEHNELN_DEBUG_ELF)
			(void)printf("[%d]	  %s\n", cnt, (char *)data->d_buf + shdr->sh_name);
	}

	elf_end(elf);

	close(fd);
}

int
mem_ctx_init(struct mem_ctx *mem, int c)
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
	/* TODO: some tests fail if uninitialized memory doesn't return 0. This
	 * is because we don't have the bss section initialized if we use c !=
	 * 0. Implement a proper elf loader. */
	ram = memset(ram, c, size);

	mem->ram = ram;
	mem->ram_phys_base = base;
	mem->ram_phys_size = size;

	return 0;
}

int
mem_ctx_copy_bin(struct mem_ctx *mem, char *bin, uint64_t base, uint64_t size)
{
	assert(mem);
	assert(bin);

	if (base < mem->ram_phys_base)
		return 1;
	if (base + size >= mem->ram_phys_base + mem->ram_phys_size)
		return 1;

	memcpy(mem->ram + (base - mem->ram_phys_base), bin, size);

	return 0;
}

int
mem_ctx_set(struct mem_ctx *mem, int c, uint64_t base, uint64_t size)
{
	assert(mem);

	if (base < mem->ram_phys_base)
		return 1;
	if (base + size >= mem->ram_phys_base + mem->ram_phys_size)
		return 1;

	memset(mem->ram + (base - mem->ram_phys_base), c, size);

	return 0;
}

static void
exception(struct sim_ctx *sim, uint64_t cause, uint64_t tval)
{
	sim->is_exception = true;
	sim->generic_cause = cause;
	sim->generic_tval = tval;
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

	if (sim->trace & AEHNELN_TRACE_TRANSLATION)
		printf("%s: start translation of va=0x%016" PRIx64 " type=%d\n", __func__, vaddr,
		    type);

	for (;;) {
		uint64_t pte = mem_read64(sim, mem, pt + SV39_VPN(vaddr, level) * AEHNELN_PTESIZE);
		if (sim->trace & AEHNELN_TRACE_TRANSLATION)
			printf("%s: reading 0x%016" PRIx64 " -> pte=0x%016" PRIx64 " at level=%d\n",
			    __func__, pt + SV39_VPN(vaddr, level) * AEHNELN_PTESIZE, pte, level);
		if (sim->is_exception) {
			/* re-raise exception */
			exception(sim, cause_from_access(type, ACCESS), vaddr);
			return pte;
		}

		if (REG_FIELD_READ(pte, PTE_V) == 0 ||
		    (REG_FIELD_READ(pte, PTE_R) == 0 && REG_FIELD_READ(pte, PTE_W) == 1) ||
		    (REG_FIELD_READ(pte, PTE_RSVD))) {
			exception(sim, cause_from_access(type, PAGEFAULT), vaddr);
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
					exception(sim, cause_from_access(type, PAGEFAULT), vaddr);
					return 0xdeadbee4;
				}
				break;
			case PRV_S:
				/* supervisor can't access usermode pages when SUM is clear */
				if (REG_FIELD_READ(pte, PTE_U) == 1 &&
				    CSR_FIELD_READ(sim->mstatus, MSTATUS_SUM) == 0) {
					exception(sim, cause_from_access(type, PAGEFAULT), vaddr);
					return 0xdeadbee4;
				}
				/* supervisor maybe never execute usermode pages */
				if (REG_FIELD_READ(pte, PTE_U) == 1 && type == ACC_X) {
					exception(sim, cause_from_access(type, PAGEFAULT), vaddr);
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
				exception(sim, cause_from_access(type, PAGEFAULT), vaddr);
				return 0xdeadbee4;
			} else if (!REG_FIELD_READ(pte, pte_access_from_access(type))) {
				/* regular rwx check */
				exception(sim, cause_from_access(type, PAGEFAULT), vaddr);
				return 0xdeadbee4;
			}

			/* check for misaligned superpage (level > 0) */
			for (int i = 0; i < level; i++) {
				if (SV39_PPN(pte, i) != 0) {
					exception(sim, cause_from_access(type, PAGEFAULT), vaddr);
					return 0xdeadbee4;
				}
			}

			/* dirty and accessed check */
			if (REG_FIELD_READ(pte, PTE_A) == 0 ||
			    (type == ACC_W && REG_FIELD_READ(pte, PTE_D) == 0)) {
				exception(sim, cause_from_access(type, PAGEFAULT), vaddr);
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

			if (sim->trace & AEHNELN_TRACE_TRANSLATION)
				printf("%s: return va=0x%016" PRIx64 " -> pa=0x%016" PRIx64 "\n",
				    __func__, vaddr, paddr);

			return paddr;
		} else {
			/* go to next level */
			level = level - 1;
			if (level < 0) {
				exception(sim, cause_from_access(type, PAGEFAULT), vaddr);
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

	uint32_t data = mem_insn_read(sim, mem, paddr);
	if (sim->bus_exception) {
		sim->bus_exception = false;
		exception(sim, CAUSE_FETCH_ACCESS, vaddr);
	}

	return data;
}

uint64_t
mem_vread64(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_R);
	if (sim->is_exception)
		return 0xdeadbeefdeadbeef;

	uint64_t data = mem_read64(sim, mem, paddr);
	if (sim->bus_exception) {
		sim->bus_exception = false;
		exception(sim, CAUSE_LOAD_ACCESS, vaddr);
	}

	return data;
}

uint32_t
mem_vread32(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_R);
	if (sim->is_exception)
		return 0xdeadbeef;

	uint32_t data = mem_read32(sim, mem, paddr);
	if (sim->bus_exception) {
		sim->bus_exception = false;
		exception(sim, CAUSE_LOAD_ACCESS, vaddr);
	}

	return data;
}

uint16_t
mem_vread16(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_R);
	if (sim->is_exception)
		return 0xdead;

	uint16_t data = mem_read16(sim, mem, paddr);
	if (sim->bus_exception) {
		sim->bus_exception = false;
		exception(sim, CAUSE_LOAD_ACCESS, vaddr);
	}

	return data;
}

uint8_t
mem_vread8(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_R);
	if (sim->is_exception)
		return 0x0;

	uint8_t data = mem_read8(sim, mem, paddr);
	if (sim->bus_exception) {
		sim->bus_exception = false;
		exception(sim, CAUSE_LOAD_ACCESS, vaddr);
	}

	return data;
}

void
mem_vwrite64(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr, uint64_t data)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_W);
	if (sim->is_exception)
		return;

	mem_write64(sim, mem, paddr, data);
	if (sim->bus_exception) {
		sim->bus_exception = false;
		exception(sim, CAUSE_STORE_ACCESS, vaddr);
	}
}

void
mem_vwrite32(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr, uint32_t data)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_W);
	if (sim->is_exception)
		return;

	mem_write32(sim, mem, paddr, data);
	if (sim->bus_exception) {
		sim->bus_exception = false;
		exception(sim, CAUSE_STORE_ACCESS, vaddr);
	}
}

void
mem_vwrite16(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr, uint16_t data)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_W);
	if (sim->is_exception)
		return;

	mem_write16(sim, mem, paddr, data);
	if (sim->bus_exception) {
		sim->bus_exception = false;
		exception(sim, CAUSE_STORE_ACCESS, vaddr);
	}
}

void
mem_vwrite8(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t vaddr, uint8_t data)
{
	uint64_t paddr = ptwalk_sv39(sim, mem, vaddr, ACC_W);
	if (sim->is_exception)
		return;

	mem_write8(sim, mem, paddr, data);
	if (sim->bus_exception) {
		sim->bus_exception = false;
		exception(sim, CAUSE_STORE_ACCESS, vaddr);
	}
}

uint32_t
mem_insn_read(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr)
{
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal read at 0x%016" PRIx64 "\n", addr);
		sim->bus_exception = true;
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
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal read at 0x%016" PRIx64 "\n", addr);
		sim->bus_exception = true;
		return 0xdeadbeef;
	}

	uint64_t data;
	memcpy(&data, &mem->ram[addr - mem->ram_phys_base], 8);

	/* if (sim->trace & AEHNELN_TRACE_MEM) */
	/* 	fprintf(stdout, "%s: 0x%016" PRIx64 " -> 0x%016" PRIx64 "\n", __func__, addr, data);
	 */

	return data;
}

uint32_t
mem_read32(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr)
{
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal read at 0x%016" PRIx64 "\n", addr);
		sim->bus_exception = true;
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
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal read at 0x%016" PRIx64 "\n", addr);
		sim->bus_exception = true;
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
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal read at 0x%016" PRIx64 "\n", addr);
		sim->bus_exception = true;
		return 0xff;
	}
	uint8_t data;
	memcpy(&data, &mem->ram[addr - mem->ram_phys_base], 1);

	if (sim->trace & AEHNELN_TRACE_MEM)
		fprintf(stdout, "%s: 0x%016" PRIx64 " -> 0x%02" PRIx8 "\n", __func__, addr, data);

	return data;
}

/* sifive tohost protocol according to vm.c */
static void
decode_tohost(uint64_t data)
{
	/* cputchar */
	if ((data >> 8) == (0x0101000000000000 >> 8)) {
		putchar(data & 0xff);
	} else {
		fprintf(stderr, "tohost: exit with 0x%lx\n", data);
		/* just exit */
		exit(data == 1 ? EXIT_SUCCESS : EXIT_FAILURE);
	}
}

void
mem_write64(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr, uint64_t data)
{
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal write to 0x%016" PRIx64 " with 0x%016" PRIx64 "\n",
			    addr, data);
		sim->bus_exception = true;
		return;
	}

	if (addr == MEM_TOHOST) {
		decode_tohost(data);
		return;
	}

	memcpy(&mem->ram[addr - mem->ram_phys_base], &data, 8);

	if (sim->trace & AEHNELN_TRACE_MEM)
		fprintf(stdout, "%s: 0x%016" PRIx64 " <- 0x%016" PRIx64 "\n", __func__, addr, data);
}

void
mem_write32(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr, uint32_t data)
{
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal write to 0x%016" PRIx64 " with 0x%08" PRIx32 "\n",
			    addr, data);
		sim->bus_exception = true;
		return;
	}

	if (addr == MEM_TOHOST) {
		decode_tohost(data);
		return;
	}

	memcpy(&mem->ram[addr - mem->ram_phys_base], &data, 4);

	if (sim->trace & AEHNELN_TRACE_MEM)
		fprintf(stdout, "%s: 0x%016" PRIx64 " <- 0x%08" PRIx32 "\n", __func__, addr, data);
}

void
mem_write16(struct sim_ctx *sim, struct mem_ctx *mem, uint64_t addr, uint16_t data)
{
	if (addr < mem->ram_phys_base || addr >= mem->ram_phys_base + mem->ram_phys_size) {
		if (sim->trace & AEHNELN_TRACE_MEM)
			fprintf(stderr, "illegal write to 0x%016" PRIx64 " with 0x%04" PRIx16 "\n",
			    addr, data);
		sim->bus_exception = true;
		return;
	}

	if (addr == MEM_TOHOST) {
		decode_tohost(data);
		return;
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
		sim->bus_exception = true;
		return;
	}

	if (addr == MEM_TOHOST) {
		decode_tohost(data);
		return;
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
	REG(FIELD(RD)) = mem_vread64(sim, mem, GET_REG(FIELD(RS1)));
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite64(sim, mem, GET_REG(FIELD(RS1)), GET_REG(FIELD(RD)) + GET_REG(FIELD(RS2)));
}
void
sim_amoadd_w(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = SEXT(mem_vread32(sim, mem, GET_REG(FIELD(RS1))), 32);
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite32(sim, mem, GET_REG(FIELD(RS1)), GET_REG(FIELD(RD)) + GET_REG(FIELD(RS2)));
}

void
sim_amoand_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = mem_vread64(sim, mem, GET_REG(FIELD(RS1)));
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite64(sim, mem, GET_REG(FIELD(RS1)), GET_REG(FIELD(RD)) & GET_REG(FIELD(RS2)));
}
void
sim_amoand_w(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = SEXT(mem_vread32(sim, mem, GET_REG(FIELD(RS1))), 32);
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite32(sim, mem, GET_REG(FIELD(RS1)), GET_REG(FIELD(RD)) & GET_REG(FIELD(RS2)));
}
void
sim_amomax_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = mem_vread64(sim, mem, GET_REG(FIELD(RS1)));
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite64(sim, mem, GET_REG(FIELD(RS1)),
	    MAX((int64_t)GET_REG(FIELD(RS2)), (int64_t)GET_REG(FIELD(RD))));
}
void
sim_amomax_w(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = SEXT(mem_vread32(sim, mem, GET_REG(FIELD(RS1))), 32);
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite32(sim, mem, GET_REG(FIELD(RS1)),
	    MAX((int64_t)GET_REG(FIELD(RS2)), (int64_t)GET_REG(FIELD(RD))));
}
void
sim_amomaxu_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = mem_vread64(sim, mem, GET_REG(FIELD(RS1)));
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite64(sim, mem, GET_REG(FIELD(RS1)), MAX(GET_REG(FIELD(RS2)), GET_REG(FIELD(RD))));
}
void
sim_amomaxu_w(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = SEXT(mem_vread32(sim, mem, GET_REG(FIELD(RS1))), 32);
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite32(sim, mem, GET_REG(FIELD(RS1)), MAX(GET_REG(FIELD(RS2)), GET_REG(FIELD(RD))));
}
void
sim_amomin_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = mem_vread64(sim, mem, GET_REG(FIELD(RS1)));
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite64(sim, mem, GET_REG(FIELD(RS1)),
	    MIN((int64_t)GET_REG(FIELD(RS2)), (int64_t)GET_REG(FIELD(RD))));
}
void
sim_amomin_w(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = SEXT(mem_vread32(sim, mem, GET_REG(FIELD(RS1))), 32);
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite32(sim, mem, GET_REG(FIELD(RS1)),
	    MIN((int64_t)GET_REG(FIELD(RS2)), (int64_t)GET_REG(FIELD(RD))));
}
void
sim_amominu_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = mem_vread64(sim, mem, GET_REG(FIELD(RS1)));
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite64(sim, mem, GET_REG(FIELD(RS1)), MIN(GET_REG(FIELD(RS2)), GET_REG(FIELD(RD))));
}
void
sim_amominu_w(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = SEXT(mem_vread32(sim, mem, GET_REG(FIELD(RS1))), 32);
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite32(sim, mem, GET_REG(FIELD(RS1)), MIN(GET_REG(FIELD(RS2)), GET_REG(FIELD(RD))));
}
void
sim_amoor_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = mem_vread64(sim, mem, GET_REG(FIELD(RS1)));
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite64(sim, mem, GET_REG(FIELD(RS1)), GET_REG(FIELD(RD)) | GET_REG(FIELD(RS2)));
}
void
sim_amoor_w(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = SEXT(mem_vread32(sim, mem, GET_REG(FIELD(RS1))), 32);
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite32(sim, mem, GET_REG(FIELD(RS1)), GET_REG(FIELD(RD)) | GET_REG(FIELD(RS2)));
}
void
sim_amoswap_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = mem_vread64(sim, mem, GET_REG(FIELD(RS1)));
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite64(sim, mem, GET_REG(FIELD(RS1)), GET_REG(FIELD(RS2)));
}
void
sim_amoswap_w(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = SEXT(mem_vread32(sim, mem, GET_REG(FIELD(RS1))), 32);
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite32(sim, mem, GET_REG(FIELD(RS1)), GET_REG(FIELD(RS2)));
}
void
sim_amoxor_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = mem_vread64(sim, mem, GET_REG(FIELD(RS1)));
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite64(sim, mem, GET_REG(FIELD(RS1)), GET_REG(FIELD(RD)) ^ GET_REG(FIELD(RS2)));
}
void
sim_amoxor_w(struct sim_ctx *sim, struct mem_ctx *mem)
{
	REG(FIELD(RD)) = SEXT(mem_vread32(sim, mem, GET_REG(FIELD(RS1))), 32);
	if (sim->is_exception) {
		/* AMOs only generate store page-fault exceptions (privileged
		 * spec 4.3.1). Rewrite them. */
		if (sim->generic_cause == CAUSE_LOAD_PAGE_FAULT)
			sim->generic_cause = CAUSE_STORE_PAGE_FAULT;
		return;
	}

	mem_vwrite32(sim, mem, GET_REG(FIELD(RS1)), GET_REG(FIELD(RD)) ^ GET_REG(FIELD(RS2)));
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
	case CSR_MTVAL:
		REG(FIELD(RD)) = sim->mtval;
		sim->mtval &= ~csr_arg;
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
	case CSR_STVAL:
		REG(FIELD(RD)) = sim->stval;
		sim->stval &= ~csr_arg;
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
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION, sim->insn);
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
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION, sim->insn);
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
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION, sim->insn);
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
	case CSR_MTVAL:
		REG(FIELD(RD)) = sim->mtval;
		sim->mtval |= csr_arg;
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
	case CSR_STVAL:
		REG(FIELD(RD)) = sim->stval;
		sim->stval |= csr_arg;
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
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION, sim->insn);
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
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION, sim->insn);
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
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION, sim->insn);
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
	case CSR_MTVAL:
		REG(FIELD(RD)) = sim->mtval;
		sim->mtval = csr_arg;
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
	case CSR_STVAL:
		REG(FIELD(RD)) = sim->stval;
		sim->stval = csr_arg;
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
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION, sim->insn);
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
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION, sim->insn);
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
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION, sim->insn);
		return;
	}

	csrrw_generic(sim, csr_val, csr_arg);
}
void
sim_div(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_divu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
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
	exception(sim, CAUSE_BREAKPOINT, sim->pc);
}
void
sim_ecall(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	/* transition to machine mode */
	if (sim->priv == PRV_M)
		exception(sim, CAUSE_MACHINE_ECALL, 0);
	else if (sim->priv == PRV_S)
		exception(sim, CAUSE_SUPERVISOR_ECALL, 0);
	else if (sim->priv == PRV_U)
		exception(sim, CAUSE_USER_ECALL, 0);
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
	if (!sim->is_exception)
		REG(FIELD(RD)) = val;
}
void
sim_lbu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	uint64_t val = mem_vread8(sim, mem, GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn));
	if (!sim->is_exception)
		REG(FIELD(RD)) = val;
}
void
sim_ld(struct sim_ctx *sim, struct mem_ctx *mem)
{
	uint64_t val = mem_vread64(sim, mem, GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn));
	if (!sim->is_exception)
		REG(FIELD(RD)) = val;
}
void
sim_lh(struct sim_ctx *sim, struct mem_ctx *mem)
{
	uint64_t val = SEXT(mem_vread16(sim, mem, GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn)), 16);
	if (!sim->is_exception)
		REG(FIELD(RD)) = val;
}
void
sim_lhu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	uint64_t val = mem_vread16(sim, mem, GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn));
	if (!sim->is_exception)
		REG(FIELD(RD)) = val;
}
void
sim_lr_d(struct sim_ctx *sim, struct mem_ctx *mem)
{
	if (GET_REG(FIELD(RS1)) & 7) {
		exception(sim, CAUSE_MISALIGNED_LOAD, GET_REG(FIELD(RS1)));
		return;
	}

	uint64_t val = mem_vread64(sim, mem, GET_REG(FIELD(RS1)));
	if (!sim->is_exception) {
		REG(FIELD(RD)) = val;
		sim->reserved = true;
		sim->reserved_addr = GET_REG(FIELD(RS1));
	}
}
void
sim_lr_w(struct sim_ctx *sim, struct mem_ctx *mem)
{
	if (GET_REG(FIELD(RS1)) & 3) {
		exception(sim, CAUSE_MISALIGNED_LOAD, GET_REG(FIELD(RS1)));
		return;
	}

	uint64_t val = SEXT(mem_vread32(sim, mem, GET_REG(FIELD(RS1))), 32);
	if (!sim->is_exception) {
		REG(FIELD(RD)) = val;
		sim->reserved = true;
		sim->reserved_addr = GET_REG(FIELD(RS1));
	}
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
	if (!sim->is_exception)
		REG(FIELD(RD)) = val;
}
void
sim_lwu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	uint64_t val = mem_vread32(sim, mem, GET_REG(FIELD(RS1)) + ITYPE_IMM(sim->insn));
	if (!sim->is_exception)
		REG(FIELD(RD)) = val;
}
void
sim_mret(struct sim_ctx *sim, struct mem_ctx *mem)
{
	(void)mem;
	/* mret works only in m-mode */
	if (!(sim->priv >= PRV_M)) {
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION, sim->insn);
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
sim_mul(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_mulh(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_mulhsu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_mulhu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
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
sim_rem(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
}
void
sim_remu(struct sim_ctx *sim, struct mem_ctx *mem)
{
	SIM_UNIMPLEMENTED();
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
	if (GET_REG(FIELD(RS1)) & 7) {
		exception(sim, CAUSE_MISALIGNED_STORE, GET_REG(FIELD(RS1)));
		return;
	}

	/* TODO: For implementations with both page-based virtual memory and the
	 * “A” standard extension, the LR/SC reservation set must lie completely within a
	 * single base page (i.e., a naturally aligned 4 KiB region). (privileged spec 4.3.1)*/
	if (sim->reserved_addr == GET_REG(FIELD(RS1))) {
		mem_vwrite64(sim, mem, GET_REG(FIELD(RS1)), (uint64_t)GET_REG(FIELD(RS2)));
		REG(FIELD(RD)) = 0;
	} else {
		REG(FIELD(RD)) = 1;
	}

	/* no matter what invalidate reservations */
	sim->reserved = false;
	sim->reserved_addr = 0;
}
void
sim_sc_w(struct sim_ctx *sim, struct mem_ctx *mem)
{
	if (GET_REG(FIELD(RS1)) & 3) {
		exception(sim, CAUSE_MISALIGNED_STORE, GET_REG(FIELD(RS1)));
		return;
	}

	if (sim->reserved_addr == GET_REG(FIELD(RS1))) {
		mem_vwrite32(sim, mem, GET_REG(FIELD(RS1)), (uint32_t)GET_REG(FIELD(RS2)));
		REG(FIELD(RD)) = 0;
	} else {
		REG(FIELD(RD)) = 1;
	}

	/* no matter what invalidate reservations */
	sim->reserved = false;
	sim->reserved_addr = 0;
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
		exception(sim, CAUSE_ILLEGAL_INSTRUCTION, sim->insn);
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
	(void)mem;
	REG(FIELD(RD)) = GET_REG(FIELD(RS1)) - GET_REG(FIELD(RS2));
	REG(FIELD(RD)) = SEXT(GET_REG(FIELD(RD)), 32);
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
			printf("%s: priv=%d pc=0x%016" PRIx64 " insn=0x%08" PRIx32 "\n", __func__,
			    sim->priv, sim->pc, insn);
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

			if (sim->trace & AEHNELN_TRACE_ILLEGAL)
				fprintf(stderr,
				    "oops illegal instruction pc=0x%016" PRIx64 " insn=0x%08" PRIx32
				    "\n",
				    sim->pc, insn);
			exception(sim, CAUSE_ILLEGAL_INSTRUCTION, sim->insn);
		}
#undef DECLARE_INSN

		/* update cycle counters */
		sim->cycle += 1;

		/* update pc according to machine state (normal, exception, interrupt) */
		if (sim->is_exception && sim->priv <= PRV_S &&
		    ((sim->medeleg >> sim->generic_cause) & 1)) {
			if (sim->trace & AEHNELN_TRACE_EXCEPTIONS)
				printf("exception to supervisor mode: %ld tval: 0x%016" PRIx64 "\n",
				    sim->generic_cause, sim->generic_tval);
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
			sim->stval = sim->generic_tval;
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
			if (sim->trace & AEHNELN_TRACE_EXCEPTIONS)
				printf("exception to machine mode: %ld\n", sim->generic_cause);
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
			sim->mtval = sim->generic_tval;
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
	bool poison = false;
	bool raw_binary = false;

	while (1) {
		__attribute__((unused)) int this_option_optind = optind ? optind : 1;
		int option_index = 0;
		static struct option long_options[] = {
			{ "poison-mem", no_argument, 0, 'p' },
			{ "raw", no_argument, 0, 'r' },
			{ "trace", no_argument, 0, 't' },
			{ "trace-vm", no_argument, 0, 'k' },
			{ "debug", no_argument, 0, 'd' },
			{ "help", no_argument, 0, 'h' },
		};

		c = getopt_long(argc, argv, "?h", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			break;

		case 'p':
			poison = true;
			break;

		case 'r':
			raw_binary = true;
			break;

		case 'd':
			debug |= AEHNELN_DEBUG_ELF;
			break;

		case 't':
			trace |= AEHNELN_TRACE_INSN;
			trace |= AEHNELN_TRACE_MEM;
			trace |= AEHNELN_TRACE_ILLEGAL;
			trace |= AEHNELN_TRACE_UNKNOWN_CSR;
			trace |= AEHNELN_TRACE_EXCEPTIONS;
			break;

		case 'k':
			trace |= AEHNELN_TRACE_TRANSLATION;
			break;

		case 'h':
		case '?':
			print_usage();
			return EXIT_SUCCESS;

		default:
			printf("?? getopt returned character code 0%o ??\n", c);
		}
	}

	char *name = NULL;
	if (argc - optind == 1) {
		printf("opening %s ...\n", argv[optind]);
		name = argv[optind];
	} else if (argc - optind >= 1) {
		fprintf(stderr, "too many arguments\n");
		print_usage();
		return EXIT_FAILURE;
	} else {
		fprintf(stderr, "missing RISCV-ELF\n");
		print_usage();
		return EXIT_FAILURE;
	}

	struct mem_ctx mem = { 0 };
	int err;

	/* initialize physical memory */
	err = mem_ctx_init(&mem, poison ? 0xde : 0x00);
	if (err) {
		fprintf(stderr, "mem_ctx_init()\n");
		return EXIT_FAILURE;
	}

	/* load raw bin or elf */
	if (raw_binary)
		load_bin(&mem, name);
	else
		load_elf(&mem, name);

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
