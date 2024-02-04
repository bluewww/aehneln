# Aehneln
Simple RISC-V rv64ima\_zicsr\_zifencei emulator.

The goal is run a minimal Linux distribution but we are still not there yet.

## Setup and Compile

```
./autogen.sh
./configure --prefix=$OPTIONAL_PREFIX
make
```

If you want to get started with a debug build you might want to use
```
./configure-debug
```

instead of plain `./configure`.

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
./configure --prefix=$(readlink -f ../riscv/target)
make
# or make RISCV_PREFIX=riscv64-elf-
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
make EXTENSIONS="rv*_i rv*_m rv*_a rv_zicsr rv_zifencei rv_s rv_system" everything
```
