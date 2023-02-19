# SPDX-License-Identifier: MIT
dist_doc_DATA = README.md
bin_PROGRAMS = aehneln
aehneln_SOURCES = aehneln.c
AM_CFLAGS = -std=gnu11 -Wall -Wextra

tests/bin/%.bin: tests/riscv/target/share/riscv-tests/isa/%
	riscv64-elf-objcopy -O binary $^ $@

run-riscv-tests: riscv-tests
	for f in tests/bin/*.bin; do ./aehneln $$f; done

riscv-tests: tests/bin/rv64mi-p-access.bin \
tests/bin/rv64mi-p-breakpoint.bin \
tests/bin/rv64mi-p-csr.bin \
tests/bin/rv64mi-p-illegal.bin \
tests/bin/rv64mi-p-ld-misaligned.bin \
tests/bin/rv64mi-p-lh-misaligned.bin \
tests/bin/rv64mi-p-lw-misaligned.bin \
tests/bin/rv64mi-p-ma_addr.bin \
tests/bin/rv64mi-p-ma_fetch.bin \
tests/bin/rv64mi-p-mcsr.bin \
tests/bin/rv64mi-p-sbreak.bin \
tests/bin/rv64mi-p-scall.bin \
tests/bin/rv64mi-p-sd-misaligned.bin \
tests/bin/rv64mi-p-sh-misaligned.bin \
tests/bin/rv64mi-p-sw-misaligned.bin \
tests/bin/rv64mzicbo-p-zero.bin \
tests/bin/rv64si-p-csr.bin \
tests/bin/rv64si-p-dirty.bin \
tests/bin/rv64si-p-icache-alias.bin \
tests/bin/rv64si-p-ma_fetch.bin \
tests/bin/rv64si-p-sbreak.bin \
tests/bin/rv64si-p-scall.bin \
tests/bin/rv64si-p-wfi.bin \
tests/bin/rv64ssvnapot-p-napot.bin \
tests/bin/rv64ua-p-amoadd_d.bin \
tests/bin/rv64ua-p-amoadd_w.bin \
tests/bin/rv64ua-p-amoand_d.bin \
tests/bin/rv64ua-p-amoand_w.bin \
tests/bin/rv64ua-p-amomax_d.bin \
tests/bin/rv64ua-p-amomaxu_d.bin \
tests/bin/rv64ua-p-amomaxu_w.bin \
tests/bin/rv64ua-p-amomax_w.bin \
tests/bin/rv64ua-p-amomin_d.bin \
tests/bin/rv64ua-p-amominu_d.bin \
tests/bin/rv64ua-p-amominu_w.bin \
tests/bin/rv64ua-p-amomin_w.bin \
tests/bin/rv64ua-p-amoor_d.bin \
tests/bin/rv64ua-p-amoor_w.bin \
tests/bin/rv64ua-p-amoswap_d.bin \
tests/bin/rv64ua-p-amoswap_w.bin \
tests/bin/rv64ua-p-amoxor_d.bin \
tests/bin/rv64ua-p-amoxor_w.bin \
tests/bin/rv64ua-p-lrsc.bin \
tests/bin/rv64ua-v-amoadd_d.bin \
tests/bin/rv64ua-v-amoadd_w.bin \
tests/bin/rv64ua-v-amoand_d.bin \
tests/bin/rv64ua-v-amoand_w.bin \
tests/bin/rv64ua-v-amomax_d.bin \
tests/bin/rv64ua-v-amomaxu_d.bin \
tests/bin/rv64ua-v-amomaxu_w.bin \
tests/bin/rv64ua-v-amomax_w.bin \
tests/bin/rv64ua-v-amomin_d.bin \
tests/bin/rv64ua-v-amominu_d.bin \
tests/bin/rv64ua-v-amominu_w.bin \
tests/bin/rv64ua-v-amomin_w.bin \
tests/bin/rv64ua-v-amoor_d.bin \
tests/bin/rv64ua-v-amoor_w.bin \
tests/bin/rv64ua-v-amoswap_d.bin \
tests/bin/rv64ua-v-amoswap_w.bin \
tests/bin/rv64ua-v-amoxor_d.bin \
tests/bin/rv64ua-v-amoxor_w.bin \
tests/bin/rv64ua-v-lrsc.bin \
tests/bin/rv64uc-p-rvc.bin \
tests/bin/rv64uc-v-rvc.bin \
tests/bin/rv64ud-p-fadd.bin \
tests/bin/rv64ud-p-fclass.bin \
tests/bin/rv64ud-p-fcmp.bin \
tests/bin/rv64ud-p-fcvt.bin \
tests/bin/rv64ud-p-fcvt_w.bin \
tests/bin/rv64ud-p-fdiv.bin \
tests/bin/rv64ud-p-fmadd.bin \
tests/bin/rv64ud-p-fmin.bin \
tests/bin/rv64ud-p-ldst.bin \
tests/bin/rv64ud-p-move.bin \
tests/bin/rv64ud-p-recoding.bin \
tests/bin/rv64ud-p-structural.bin \
tests/bin/rv64ud-v-fadd.bin \
tests/bin/rv64ud-v-fclass.bin \
tests/bin/rv64ud-v-fcmp.bin \
tests/bin/rv64ud-v-fcvt.bin \
tests/bin/rv64ud-v-fcvt_w.bin \
tests/bin/rv64ud-v-fdiv.bin \
tests/bin/rv64ud-v-fmadd.bin \
tests/bin/rv64ud-v-fmin.bin \
tests/bin/rv64ud-v-ldst.bin \
tests/bin/rv64ud-v-move.bin \
tests/bin/rv64ud-v-recoding.bin \
tests/bin/rv64ud-v-structural.bin \
tests/bin/rv64uf-p-fadd.bin \
tests/bin/rv64uf-p-fclass.bin \
tests/bin/rv64uf-p-fcmp.bin \
tests/bin/rv64uf-p-fcvt.bin \
tests/bin/rv64uf-p-fcvt_w.bin \
tests/bin/rv64uf-p-fdiv.bin \
tests/bin/rv64uf-p-fmadd.bin \
tests/bin/rv64uf-p-fmin.bin \
tests/bin/rv64uf-p-ldst.bin \
tests/bin/rv64uf-p-move.bin \
tests/bin/rv64uf-p-recoding.bin \
tests/bin/rv64uf-v-fadd.bin \
tests/bin/rv64uf-v-fclass.bin \
tests/bin/rv64uf-v-fcmp.bin \
tests/bin/rv64uf-v-fcvt.bin \
tests/bin/rv64uf-v-fcvt_w.bin \
tests/bin/rv64uf-v-fdiv.bin \
tests/bin/rv64uf-v-fmadd.bin \
tests/bin/rv64uf-v-fmin.bin \
tests/bin/rv64uf-v-ldst.bin \
tests/bin/rv64uf-v-move.bin \
tests/bin/rv64uf-v-recoding.bin \
tests/bin/rv64ui-p-add.bin \
tests/bin/rv64ui-p-addi.bin \
tests/bin/rv64ui-p-addiw.bin \
tests/bin/rv64ui-p-addw.bin \
tests/bin/rv64ui-p-and.bin \
tests/bin/rv64ui-p-andi.bin \
tests/bin/rv64ui-p-auipc.bin \
tests/bin/rv64ui-p-beq.bin \
tests/bin/rv64ui-p-bge.bin \
tests/bin/rv64ui-p-bgeu.bin \
tests/bin/rv64ui-p-blt.bin \
tests/bin/rv64ui-p-bltu.bin \
tests/bin/rv64ui-p-bne.bin \
tests/bin/rv64ui-p-fence_i.bin \
tests/bin/rv64ui-p-jal.bin \
tests/bin/rv64ui-p-jalr.bin \
tests/bin/rv64ui-p-lb.bin \
tests/bin/rv64ui-p-lbu.bin \
tests/bin/rv64ui-p-ld.bin \
tests/bin/rv64ui-p-lh.bin \
tests/bin/rv64ui-p-lhu.bin \
tests/bin/rv64ui-p-lui.bin \
tests/bin/rv64ui-p-lw.bin \
tests/bin/rv64ui-p-lwu.bin \
tests/bin/rv64ui-p-ma_data.bin \
tests/bin/rv64ui-p-or.bin \
tests/bin/rv64ui-p-ori.bin \
tests/bin/rv64ui-p-sb.bin \
tests/bin/rv64ui-p-sd.bin \
tests/bin/rv64ui-p-sh.bin \
tests/bin/rv64ui-p-simple.bin \
tests/bin/rv64ui-p-sll.bin \
tests/bin/rv64ui-p-slli.bin \
tests/bin/rv64ui-p-slliw.bin \
tests/bin/rv64ui-p-sllw.bin \
tests/bin/rv64ui-p-slt.bin \
tests/bin/rv64ui-p-slti.bin \
tests/bin/rv64ui-p-sltiu.bin \
tests/bin/rv64ui-p-sltu.bin \
tests/bin/rv64ui-p-sra.bin \
tests/bin/rv64ui-p-srai.bin \
tests/bin/rv64ui-p-sraiw.bin \
tests/bin/rv64ui-p-sraw.bin \
tests/bin/rv64ui-p-srl.bin \
tests/bin/rv64ui-p-srli.bin \
tests/bin/rv64ui-p-srliw.bin \
tests/bin/rv64ui-p-srlw.bin \
tests/bin/rv64ui-p-sub.bin \
tests/bin/rv64ui-p-subw.bin \
tests/bin/rv64ui-p-sw.bin \
tests/bin/rv64ui-p-xor.bin \
tests/bin/rv64ui-p-xori.bin \
tests/bin/rv64ui-v-add.bin \
tests/bin/rv64ui-v-addi.bin \
tests/bin/rv64ui-v-addiw.bin \
tests/bin/rv64ui-v-addw.bin \
tests/bin/rv64ui-v-and.bin \
tests/bin/rv64ui-v-andi.bin \
tests/bin/rv64ui-v-auipc.bin \
tests/bin/rv64ui-v-beq.bin \
tests/bin/rv64ui-v-bge.bin \
tests/bin/rv64ui-v-bgeu.bin \
tests/bin/rv64ui-v-blt.bin \
tests/bin/rv64ui-v-bltu.bin \
tests/bin/rv64ui-v-bne.bin \
tests/bin/rv64ui-v-fence_i.bin \
tests/bin/rv64ui-v-jal.bin \
tests/bin/rv64ui-v-jalr.bin \
tests/bin/rv64ui-v-lb.bin \
tests/bin/rv64ui-v-lbu.bin \
tests/bin/rv64ui-v-ld.bin \
tests/bin/rv64ui-v-lh.bin \
tests/bin/rv64ui-v-lhu.bin \
tests/bin/rv64ui-v-lui.bin \
tests/bin/rv64ui-v-lw.bin \
tests/bin/rv64ui-v-lwu.bin \
tests/bin/rv64ui-v-ma_data.bin \
tests/bin/rv64ui-v-or.bin \
tests/bin/rv64ui-v-ori.bin \
tests/bin/rv64ui-v-sb.bin \
tests/bin/rv64ui-v-sd.bin \
tests/bin/rv64ui-v-sh.bin \
tests/bin/rv64ui-v-simple.bin \
tests/bin/rv64ui-v-sll.bin \
tests/bin/rv64ui-v-slli.bin \
tests/bin/rv64ui-v-slliw.bin \
tests/bin/rv64ui-v-sllw.bin \
tests/bin/rv64ui-v-slt.bin \
tests/bin/rv64ui-v-slti.bin \
tests/bin/rv64ui-v-sltiu.bin \
tests/bin/rv64ui-v-sltu.bin \
tests/bin/rv64ui-v-sra.bin \
tests/bin/rv64ui-v-srai.bin \
tests/bin/rv64ui-v-sraiw.bin \
tests/bin/rv64ui-v-sraw.bin \
tests/bin/rv64ui-v-srl.bin \
tests/bin/rv64ui-v-srli.bin \
tests/bin/rv64ui-v-srliw.bin \
tests/bin/rv64ui-v-srlw.bin \
tests/bin/rv64ui-v-sub.bin \
tests/bin/rv64ui-v-subw.bin \
tests/bin/rv64ui-v-sw.bin \
tests/bin/rv64ui-v-xor.bin \
tests/bin/rv64ui-v-xori.bin \
tests/bin/rv64um-p-div.bin \
tests/bin/rv64um-p-divu.bin \
tests/bin/rv64um-p-divuw.bin \
tests/bin/rv64um-p-divw.bin \
tests/bin/rv64um-p-mul.bin \
tests/bin/rv64um-p-mulh.bin \
tests/bin/rv64um-p-mulhsu.bin \
tests/bin/rv64um-p-mulhu.bin \
tests/bin/rv64um-p-mulw.bin \
tests/bin/rv64um-p-rem.bin \
tests/bin/rv64um-p-remu.bin \
tests/bin/rv64um-p-remuw.bin \
tests/bin/rv64um-p-remw.bin \
tests/bin/rv64um-v-div.bin \
tests/bin/rv64um-v-divu.bin \
tests/bin/rv64um-v-divuw.bin \
tests/bin/rv64um-v-divw.bin \
tests/bin/rv64um-v-mul.bin \
tests/bin/rv64um-v-mulh.bin \
tests/bin/rv64um-v-mulhsu.bin \
tests/bin/rv64um-v-mulhu.bin \
tests/bin/rv64um-v-mulw.bin \
tests/bin/rv64um-v-rem.bin \
tests/bin/rv64um-v-remu.bin \
tests/bin/rv64um-v-remuw.bin \
tests/bin/rv64um-v-remw.bin \
tests/bin/rv64uzfh-p-fadd.bin \
tests/bin/rv64uzfh-p-fclass.bin \
tests/bin/rv64uzfh-p-fcmp.bin \
tests/bin/rv64uzfh-p-fcvt.bin \
tests/bin/rv64uzfh-p-fcvt_w.bin \
tests/bin/rv64uzfh-p-fdiv.bin \
tests/bin/rv64uzfh-p-fmadd.bin \
tests/bin/rv64uzfh-p-fmin.bin \
tests/bin/rv64uzfh-p-ldst.bin \
tests/bin/rv64uzfh-p-move.bin \
tests/bin/rv64uzfh-p-recoding.bin \
tests/bin/rv64uzfh-v-fadd.bin \
tests/bin/rv64uzfh-v-fclass.bin \
tests/bin/rv64uzfh-v-fcmp.bin \
tests/bin/rv64uzfh-v-fcvt.bin \
tests/bin/rv64uzfh-v-fcvt_w.bin \
tests/bin/rv64uzfh-v-fdiv.bin \
tests/bin/rv64uzfh-v-fmadd.bin \
tests/bin/rv64uzfh-v-fmin.bin \
tests/bin/rv64uzfh-v-ldst.bin \
tests/bin/rv64uzfh-v-move.bin \
tests/bin/rv64uzfh-v-recoding.bin

# tests/bin/rv32mi-p-breakpoint.bin \
# tests/bin/rv32mi-p-csr.bin \
# tests/bin/rv32mi-p-illegal.bin \
# tests/bin/rv32mi-p-lh-misaligned.bin \
# tests/bin/rv32mi-p-lw-misaligned.bin \
# tests/bin/rv32mi-p-ma_addr.bin \
# tests/bin/rv32mi-p-ma_fetch.bin \
# tests/bin/rv32mi-p-mcsr.bin \
# tests/bin/rv32mi-p-sbreak.bin \
# tests/bin/rv32mi-p-scall.bin \
# tests/bin/rv32mi-p-shamt.bin \
# tests/bin/rv32mi-p-sh-misaligned.bin \
# tests/bin/rv32mi-p-sw-misaligned.bin \
# tests/bin/rv32si-p-csr.bin \
# tests/bin/rv32si-p-dirty.bin \
# tests/bin/rv32si-p-ma_fetch.bin \
# tests/bin/rv32si-p-sbreak.bin \
# tests/bin/rv32si-p-scall.bin \
# tests/bin/rv32si-p-wfi.bin \
# tests/bin/rv32ua-p-amoadd_w.bin \
# tests/bin/rv32ua-p-amoand_w.bin \
# tests/bin/rv32ua-p-amomaxu_w.bin \
# tests/bin/rv32ua-p-amomax_w.bin \
# tests/bin/rv32ua-p-amominu_w.bin \
# tests/bin/rv32ua-p-amomin_w.bin \
# tests/bin/rv32ua-p-amoor_w.bin \
# tests/bin/rv32ua-p-amoswap_w.bin \
# tests/bin/rv32ua-p-amoxor_w.bin \
# tests/bin/rv32ua-p-lrsc.bin \
# tests/bin/rv32ua-v-amoadd_w.bin \
# tests/bin/rv32ua-v-amoand_w.bin \
# tests/bin/rv32ua-v-amomaxu_w.bin \
# tests/bin/rv32ua-v-amomax_w.bin \
# tests/bin/rv32ua-v-amominu_w.bin \
# tests/bin/rv32ua-v-amomin_w.bin \
# tests/bin/rv32ua-v-amoor_w.bin \
# tests/bin/rv32ua-v-amoswap_w.bin \
# tests/bin/rv32ua-v-amoxor_w.bin \
# tests/bin/rv32ua-v-lrsc.bin \
# tests/bin/rv32uc-p-rvc.bin \
# tests/bin/rv32uc-v-rvc.bin \
# tests/bin/rv32ud-p-fadd.bin \
# tests/bin/rv32ud-p-fclass.bin \
# tests/bin/rv32ud-p-fcmp.bin \
# tests/bin/rv32ud-p-fcvt.bin \
# tests/bin/rv32ud-p-fcvt_w.bin \
# tests/bin/rv32ud-p-fdiv.bin \
# tests/bin/rv32ud-p-fmadd.bin \
# tests/bin/rv32ud-p-fmin.bin \
# tests/bin/rv32ud-p-ldst.bin \
# tests/bin/rv32ud-p-recoding.bin \
# tests/bin/rv32ud-v-fadd.bin \
# tests/bin/rv32ud-v-fclass.bin \
# tests/bin/rv32ud-v-fcmp.bin \
# tests/bin/rv32ud-v-fcvt.bin \
# tests/bin/rv32ud-v-fcvt_w.bin \
# tests/bin/rv32ud-v-fdiv.bin \
# tests/bin/rv32ud-v-fmadd.bin \
# tests/bin/rv32ud-v-fmin.bin \
# tests/bin/rv32ud-v-ldst.bin \
# tests/bin/rv32ud-v-recoding.bin \
# tests/bin/rv32uf-p-fadd.bin \
# tests/bin/rv32uf-p-fclass.bin \
# tests/bin/rv32uf-p-fcmp.bin \
# tests/bin/rv32uf-p-fcvt.bin \
# tests/bin/rv32uf-p-fcvt_w.bin \
# tests/bin/rv32uf-p-fdiv.bin \
# tests/bin/rv32uf-p-fmadd.bin \
# tests/bin/rv32uf-p-fmin.bin \
# tests/bin/rv32uf-p-ldst.bin \
# tests/bin/rv32uf-p-move.bin \
# tests/bin/rv32uf-p-recoding.bin \
# tests/bin/rv32uf-v-fadd.bin \
# tests/bin/rv32uf-v-fclass.bin \
# tests/bin/rv32uf-v-fcmp.bin \
# tests/bin/rv32uf-v-fcvt.bin \
# tests/bin/rv32uf-v-fcvt_w.bin \
# tests/bin/rv32uf-v-fdiv.bin \
# tests/bin/rv32uf-v-fmadd.bin \
# tests/bin/rv32uf-v-fmin.bin \
# tests/bin/rv32uf-v-ldst.bin \
# tests/bin/rv32uf-v-move.bin \
# tests/bin/rv32uf-v-recoding.bin \
# tests/bin/rv32ui-p-add.bin \
# tests/bin/rv32ui-p-addi.bin \
# tests/bin/rv32ui-p-and.bin \
# tests/bin/rv32ui-p-andi.bin \
# tests/bin/rv32ui-p-auipc.bin \
# tests/bin/rv32ui-p-beq.bin \
# tests/bin/rv32ui-p-bge.bin \
# tests/bin/rv32ui-p-bgeu.bin \
# tests/bin/rv32ui-p-blt.bin \
# tests/bin/rv32ui-p-bltu.bin \
# tests/bin/rv32ui-p-bne.bin \
# tests/bin/rv32ui-p-fence_i.bin \
# tests/bin/rv32ui-p-jal.bin \
# tests/bin/rv32ui-p-jalr.bin \
# tests/bin/rv32ui-p-lb.bin \
# tests/bin/rv32ui-p-lbu.bin \
# tests/bin/rv32ui-p-lh.bin \
# tests/bin/rv32ui-p-lhu.bin \
# tests/bin/rv32ui-p-lui.bin \
# tests/bin/rv32ui-p-lw.bin \
# tests/bin/rv32ui-p-or.bin \
# tests/bin/rv32ui-p-ori.bin \
# tests/bin/rv32ui-p-sb.bin \
# tests/bin/rv32ui-p-sh.bin \
# tests/bin/rv32ui-p-simple.bin \
# tests/bin/rv32ui-p-sll.bin \
# tests/bin/rv32ui-p-slli.bin \
# tests/bin/rv32ui-p-slt.bin \
# tests/bin/rv32ui-p-slti.bin \
# tests/bin/rv32ui-p-sltiu.bin \
# tests/bin/rv32ui-p-sltu.bin \
# tests/bin/rv32ui-p-sra.bin \
# tests/bin/rv32ui-p-srai.bin \
# tests/bin/rv32ui-p-srl.bin \
# tests/bin/rv32ui-p-srli.bin \
# tests/bin/rv32ui-p-sub.bin \
# tests/bin/rv32ui-p-sw.bin \
# tests/bin/rv32ui-p-xor.bin \
# tests/bin/rv32ui-p-xori.bin \
# tests/bin/rv32ui-v-add.bin \
# tests/bin/rv32ui-v-addi.bin \
# tests/bin/rv32ui-v-and.bin \
# tests/bin/rv32ui-v-andi.bin \
# tests/bin/rv32ui-v-auipc.bin \
# tests/bin/rv32ui-v-beq.bin \
# tests/bin/rv32ui-v-bge.bin \
# tests/bin/rv32ui-v-bgeu.bin \
# tests/bin/rv32ui-v-blt.bin \
# tests/bin/rv32ui-v-bltu.bin \
# tests/bin/rv32ui-v-bne.bin \
# tests/bin/rv32ui-v-fence_i.bin \
# tests/bin/rv32ui-v-jal.bin \
# tests/bin/rv32ui-v-jalr.bin \
# tests/bin/rv32ui-v-lb.bin \
# tests/bin/rv32ui-v-lbu.bin \
# tests/bin/rv32ui-v-lh.bin \
# tests/bin/rv32ui-v-lhu.bin \
# tests/bin/rv32ui-v-lui.bin \
# tests/bin/rv32ui-v-lw.bin \
# tests/bin/rv32ui-v-or.bin \
# tests/bin/rv32ui-v-ori.bin \
# tests/bin/rv32ui-v-sb.bin \
# tests/bin/rv32ui-v-sh.bin \
# tests/bin/rv32ui-v-simple.bin \
# tests/bin/rv32ui-v-sll.bin \
# tests/bin/rv32ui-v-slli.bin \
# tests/bin/rv32ui-v-slt.bin \
# tests/bin/rv32ui-v-slti.bin \
# tests/bin/rv32ui-v-sltiu.bin \
# tests/bin/rv32ui-v-sltu.bin \
# tests/bin/rv32ui-v-sra.bin \
# tests/bin/rv32ui-v-srai.bin \
# tests/bin/rv32ui-v-srl.bin \
# tests/bin/rv32ui-v-srli.bin \
# tests/bin/rv32ui-v-sub.bin \
# tests/bin/rv32ui-v-sw.bin \
# tests/bin/rv32ui-v-xor.bin \
# tests/bin/rv32ui-v-xori.bin \
# tests/bin/rv32um-p-div.bin \
# tests/bin/rv32um-p-divu.bin \
# tests/bin/rv32um-p-mul.bin \
# tests/bin/rv32um-p-mulh.bin \
# tests/bin/rv32um-p-mulhsu.bin \
# tests/bin/rv32um-p-mulhu.bin \
# tests/bin/rv32um-p-rem.bin \
# tests/bin/rv32um-p-remu.bin \
# tests/bin/rv32um-v-div.bin \
# tests/bin/rv32um-v-divu.bin \
# tests/bin/rv32um-v-mul.bin \
# tests/bin/rv32um-v-mulh.bin \
# tests/bin/rv32um-v-mulhsu.bin \
# tests/bin/rv32um-v-mulhu.bin \
# tests/bin/rv32um-v-rem.bin \
# tests/bin/rv32um-v-remu.bin \
# tests/bin/rv32uzfh-p-fadd.bin \
# tests/bin/rv32uzfh-p-fclass.bin \
# tests/bin/rv32uzfh-p-fcmp.bin \
# tests/bin/rv32uzfh-p-fcvt.bin \
# tests/bin/rv32uzfh-p-fcvt_w.bin \
# tests/bin/rv32uzfh-p-fdiv.bin \
# tests/bin/rv32uzfh-p-fmadd.bin \
# tests/bin/rv32uzfh-p-fmin.bin \
# tests/bin/rv32uzfh-p-ldst.bin \
# tests/bin/rv32uzfh-p-move.bin \
# tests/bin/rv32uzfh-p-recoding.bin \
# tests/bin/rv32uzfh-v-fadd.bin \
# tests/bin/rv32uzfh-v-fclass.bin \
# tests/bin/rv32uzfh-v-fcmp.bin \
# tests/bin/rv32uzfh-v-fcvt.bin \
# tests/bin/rv32uzfh-v-fcvt_w.bin \
# tests/bin/rv32uzfh-v-fdiv.bin \
# tests/bin/rv32uzfh-v-fmadd.bin \
# tests/bin/rv32uzfh-v-fmin.bin \
# tests/bin/rv32uzfh-v-ldst.bin \
# tests/bin/rv32uzfh-v-move.bin \
# tests/bin/rv32uzfh-v-recoding.bin
