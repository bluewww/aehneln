# Aehneln
Simple RISC-V rv64ima simulator.

## Setup

```
./autogen.sh
./configure --prefix=$OPTIONAL_PREFIX
make
```

## Usage

```
$ ./aehneln --help
Usage: amaehneln RISCV-ELF
```

## Installing and Running Tests
Make sure you have `riscv64-unknown-elf-gcc` in your PATH (at least version `10.2.0`.

Install them by running

```
git submodule update --init --recursive
cd tests/riscv-tests
mkdir -p ../riscv/target
./configure --prefix=$(readlink -f ../riscv/target)
make
make install

```

Then you can execute them by calling

```
make run-riscv-tests
```

in the root folder of the project.

## Misc
Generating headers from riscv-opcodes

```
make EXTENSIONS=rv*_i rv64_m rv64_a rv64_f rv64_d rv64_c rv_zicsr rv_zifencei rv_s rv_system
```
