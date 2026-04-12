# FrodoKEM-1344-AES Makefile

# Targets:
#	make hello_tm4c123gh6pm -> builds hello_uart.c for TM4C123GH6PM


# Toolchain
CC = arm-none-eabi-gcc
OBJCOPY = arm-none-eabi-objcopy
SIZE = arm-none-eabi-size
HOST_CC = gcc

# Directories
ROOT = ../..
INCLUDE_DIR = $(ROOT)/include
SRC_DIR = $(ROOT)/src
TIVAWARE = tivaware

TM4C123GH6PM_DIR = tm4c123g
TEST_DIR = ../../test

BUILD_TM4C123GH6PM = $(TM4C123GH6PM_DIR)/build
BUILD_TEST = $(TEST_DIR)/build

DRIVERLIB_SRCS = \
	$(TIVAWARE)/driverlib/sysctl.c \
	$(TIVAWARE)/driverlib/gpio.c \
	$(TIVAWARE)/driverlib/uart.c \

# FrodoKEM Core Sources (TODO)


# Common Compiler Flags
COMMON_CFLAGS = \
	-Wall \
	-Wextra \
	-std=c99 \
	-O2 \
	-I$(INCLUDE_DIR)

# ARM Cross-compilation Flags
ARM_CFLAGS = \
	$(COMMON_CFLAGS) \
	-mcpu=cortex-m4 \
	-mthumb \
	-mfpu=fpv4-sp-d16 \
	-mfloat-abi=hard \
	-ffunction-sections \
	-fdata-sections \
	-Dgcc \
	-I$(TIVAWARE) \
	-I$(TIVAWARE)/inc \
	-I$(TIVAWARE)/driverlib

# Linker Flags
ARM_LDFLAGS = \
	-mthumb \
	-mcpu=cortex-m4 \
	-mfpu=fpv4-sp-d16 \
	-mfloat-abi=hard \
	-nostartfiles \
	-Wl,--gc-sections \
	-Wl,--print-gc-sections

# TivaWare Peripheral Drivers Library
DRIVERLIB_OBJS = $(patsubst $(TIVAWARE)/driverlib/%.c,\
				 $(BUILD_TM4C123GH6PM)/%.o,$(DRIVERLIB_SRCS))

# TM4C123GH6PM Target
LINKER_TM4C123GH6PM = $(TM4C123GH6PM_DIR)/tm4c123gh6pm.ld
STARTUP_TM4C123GH6PM = $(TM4C123GH6PM_DIR)/startup_gcc.c
MAIN_TM4C123GH6PM = $(TM4C123GH6PM_DIR)/main.c
HELLO_TM4C123GH6PM = $(TM4C123GH6PM_DIR)/test/hello_uart.c

CFLAGS_TM4C123GH6PM = $(ARM_CFLAGS) -DTARGET_TM4C123GH6PM
LDFLAGS_TM4C123GH6PM = \
	$(ARM_LDFLAGS) \
	-T$(LINKER_TM4C123GH6PM) \
	-Wl,-Map=$(BUILD_TM4C123GH6PM)/frodo1344.map

# Objects for Full Build (TODO)

# Objects for Hello World Build
OBJS_HELLO_TM4C123GH6PM = \
	$(BUILD_TM4C123GH6PM)/startup_gcc.o \
	$(BUILD_TM4C123GH6PM)/hello_uart.o \
	$(DRIVERLIB_OBJS)

# TM4C1294NCPDT Target (TODO)

# Host KAT Test Target (TODO)

# Build Targets
.PHONY: all hello_tm4c123gh6pm flash_tm4c123gh6pm size size-hello clean

# Hello World Tests
hello_tm4c123gh6pm: ${BUILD_TM4C123GH6PM}/hello_uart.elf
	@echo ""
	@$(SIZE) $<
	@echo ""
	@echo "Build OK: $<"
	@echo "Flash with: make flash_tm4c123gh6pm-hello"

# Full FrodoKEM Builds (TODO)

# Host KAT Test (TODO)

# Link: TM4C123GH6PM Hello World ELF
$(BUILD_TM4C123GH6PM)/hello_uart.elf: $(OBJS_HELLO_TM4C123GH6PM) | $(BUILD_TM4C123GH6PM)
	$(CC) $(LDFLAGS_TM4C123GH6PM) -o $@ $^
	$(OBJCOPY) -O binary $@ $(BUILD_TM4C123GH6PM)/hello_uart.bin

# Link: TM4C123GH6PM FrodoKEM ELF (TODO)

# Link: TM4C1294NCPDT Hello World ELF (TODO)

# Link: TM4C1294NCPDT FrodoKEM ELF (TODO)

# Compile: TivaWare Peripheral Drivers
$(BUILD_TM4C123GH6PM)/%.o: $(TIVAWARE)/driverlib/%.c | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -c -o $@ $<

# Compile: TM4C123GH6PM Startup
$(BUILD_TM4C123GH6PM)/startup_gcc.o: $(STARTUP_TM4C123GH6PM) | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -c -o $@ $<

# Compile: TM4C123GH6PM Main (TODO)

# Compile: TM4C123GH6PM Hello UART
$(BUILD_TM4C123GH6PM)/hello_uart.o: $(HELLO_TM4C123GH6PM) | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -c -o $@ $<

# Compile: TM4C123GH6PM FrodoKEM Core Sources (TODO)

# Compile: TM4C1294NCPDT Startup (TODO)

# Compile: TM4C1294NCPDT Main (TODO)

# Compile: TM4C1294NCPDT Hello UART (TODO)

# Compile: TM4C1294NCPDT FrodoKEM Core Sources (TODO)

# Compile: Host KAT Test (TODO)

# Flash Targets via OpenOCD
# Note: ti_ek-tm4c123gxl.cfg fails with OpenOCD 0.12.0 due to stellaris
# flash driver snytax change; use deprecated ek-tm4c123gxl.cfg instead
OPENOCD_CFG_TM4C123GH6PM = /opt/homebrew/opt/open-ocd/share/openocd/scripts/board/ek-tm4c123gxl.cfg

flash_tm4c123gh6pm-hello: $(BUILD_TM4C123GH6PM)/hello_uart.elf
	openocd -f $(OPENOCD_CFG_TM4C123GH6PM) \
		-c "program $< verify reset exit"

# Size Report
size-hello: $(BUILD_TM4C123GH6PM)/hello_uart.elf
	$(SIZE) -A $<

size: $(BUILD_TM4C123GH6PM)/frodo1344.elf
	$(SIZE) -A $<

# Build Directories
$(BUILD_TM4C123GH6PM):
	mkdir -p $@

# Clean
clean:
	rm -rf $(BUILD_TM4C123GH6PM)
	@echo "Clean complete"