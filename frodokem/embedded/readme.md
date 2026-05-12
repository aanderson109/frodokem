# TM4C1294/TM4C123G & FrodoKEM



## Toolchain

`arm-none-eabi-gcc` is the standard bare-metal GCC toolchain for ARM Cortex-M processors, and we use it here for this project.

- `arm` --> target instruction set architecture; TM4C1294 uses Cortex M4F core, which needs ARM instructions
- `none` --> operating system; no OS runs on the microcontroller, so we are bare metal.
- `eabi` --> embedded ABI; standard for embedded ARM targets. defines how function arguments get passed in registers, how the stack is laid out, how structs are aligned, etc... ARM microcontrollers speak EABI
- `gcc` --> compiler



### Build System

`make` provides a clean, layered way of automating the build process.


# References

(1) [GNU Linker](https://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_node/ld_toc.html)


