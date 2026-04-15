# FrodoKEM-1344-AES Makefile
#
# Builds FrodoKEM-1344-AES for embedded targets and manages flashing
# via OpenOCD.
#
# Targets:
#	hello_tm4c123gh6pm		  ->  UART hello world for TM4C123GH6PM
#	flash_tm4c123gh6pm-hello  ->  Flash hello world via OpenOCD
#	size-hello				  ->  Print section sizes for hello world build
#	size					  ->  Print section sizes for FrodoKEM build
#	clean					  ->  Remove all build artifacts
#
# TODO Targets:
#	frodo_tm4c123gh6pm		->  FrodoKEM KAT runner for TM4C123GH6PM
#	frodo_tm4c1294ncpdt		->  FrodoKEM KAT runner for TM4C1294NCPDT
#	hello_tm4c1294ncpdt		->  UART hello world for TM4C1294NCPDT
#	flash_tm4c1294ncpdt		->  Flash TM4C1294NCPDT via OpenOCD
#
# Target Platforms Specs:
#	TM4C123GH6PM	->  Cortex-M4; 256KB flash; 32KB SRAM; no hardware AES
#	TM4C1294NCPDT	->  Cortex-M4F; 1MB flash; 256KB SRAM; hardware AES (maybe)
#
# Other Notes:
#	ti_ek-tm4c123gxl.cfg fails with OpenOCD due to Stellaris flash issue
#	Use deprecated ek-tm4c123gxl.cfg instead

# ------------------------------------
# TOOLCHAIN
# ------------------------------------
CC 		= arm-none-eabi-gcc
OBJCOPY = arm-none-eabi-objcopy
SIZE 	= arm-none-eabi-size

# ------------------------------------
# DIRECTORIES
# ------------------------------------
ROOT 				= ..
INCLUDE_DIR 		= $(ROOT)/include
SRC_DIR 			= $(ROOT)/src
TIVAWARE 			= tivaware
TM4C123GH6PM_DIR 	= tm4c123g
BUILD_TM4C123GH6PM 	= $(TM4C123GH6PM_DIR)/build
TEST_DIR = ../test

# ------------------------------------
# TIVAWARE PERIPHERAL DRIVER SOURCES
# ------------------------------------
DRIVERLIB_SRCS = \
	$(TIVAWARE)/driverlib/sysctl.c \
	$(TIVAWARE)/driverlib/gpio.c \
	$(TIVAWARE)/driverlib/uart.c \
	$(TIVAWARE)/driverlib/systick.c
	# add more as needed

DRIVERLIB_OBJS = $(patsubst $(TIVAWARE)/driverlib/%.c, \
				 $(BUILD_TM4C123GH6PM)/%.o, $(DRIVERLIB_SRCS))

# ------------------------------------
# FRODOKEM CORE SOURCES
# ------------------------------------

# FrodoKEM core sources for TM4C123G
FRODO_SRCS = \
    $(SRC_DIR)/kem.c     \
    $(SRC_DIR)/matrix.c  \
    $(SRC_DIR)/sample.c  \
    $(SRC_DIR)/encode.c  \
    $(SRC_DIR)/pack.c    \
    $(SRC_DIR)/gen_A.c   \
    $(SRC_DIR)/util.c

FRODO_OBJS = $(patsubst $(SRC_DIR)/%.c, \
             $(BUILD_TM4C123GH6PM)/%.o, $(FRODO_SRCS))

# HAL sources for TM4C123G
HAL_SRCS = \
    $(TM4C123GH6PM_DIR)/hal_rng.c     \
    $(TM4C123GH6PM_DIR)/hal_aes.c     \
    $(TM4C123GH6PM_DIR)/hal_shake.c

HAL_OBJS = $(patsubst $(TM4C123GH6PM_DIR)/%.c, \
           $(BUILD_TM4C123GH6PM)/%.o, $(HAL_SRCS))


# Objects for full FrodoKEM build
OBJS_FRODO_TM4C123GH6PM = \
    $(BUILD_TM4C123GH6PM)/startup_gcc.o \
    $(BUILD_TM4C123GH6PM)/main.o        \
    $(FRODO_OBJS)                        \
    $(HAL_OBJS)                          \
    $(BUILD_TM4C123GH6PM)/aes.o         \
    $(BUILD_TM4C123GH6PM)/fips202.o     \
    $(DRIVERLIB_OBJS)


# ------------------------------------
# COMPILER FLAGS
# ------------------------------------
COMMON_CFLAGS = \
	-Wall		\
	-Wextra		\
	-std=c99	\
	-O2			\
	-I$(INCLUDE_DIR)

# ARM Cortex-M4F Cross-compilation Flags
ARM_CFLAGS = \
	$(COMMON_CFLAGS)	 \
	-mcpu=cortex-m4		 \
	-mthumb				 \
	-mfpu=fpv4-sp-d16	 \
	-mfloat-abi=hard	 \
	-ffunction-sections  \
	-fdata-sections		 \
	-Dgcc				 \
	-I$(TIVAWARE)		 \
	-I$(TIVAWARE)/inc	 \
	-I$(TIVAWARE)/driverlib

# TM4C123GH6PM-specific Flags
CFLAGS_TM4C123GH6PM = $(ARM_CFLAGS) -DTARGET_TM4C123GH6PM

# ------------------------------------
# LINKER FLAGS
# ------------------------------------
ARM_LDFLAGS = \
	-mthumb			  \
	-mcpu=cortex-m4   \
	-mfpu=fpv4-sp-d16 \
	-mfloat-abi=hard  \
	-nostartfiles 	  \
	-Wl,--gc-sections \
	-Wl,--print-gc-sections

# TM4C123GH6PM Linker Script & Map File
LINKER_TM4C123GH6PM  = $(TM4C123GH6PM_DIR)/tm4c123gh6pm.ld
LDFLAGS_TM4C123GH6PM = \
	$(ARM_LDFLAGS) 			 \
	-T$(LINKER_TM4C123GH6PM) \
	-Wl,-Map=$(BUILD_TM4C123GH6PM)/frodo1344.map

# ------------------------------------
# SOURCE FILES
# ------------------------------------
STARTUP_TM4C123GH6PM = $(TM4C123GH6PM_DIR)/startup_gcc.c
HELLO_TM4C123GH6PM 	 = $(TM4C123GH6PM_DIR)/test/hello_uart.c

# Objects for Hello World Build
OBJS_HELLO_TM4C123GH6PM = \
	$(BUILD_TM4C123GH6PM)/startup_gcc.o	 \
	$(BUILD_TM4C123GH6PM)/hello_uart.o	 \
	$(DRIVERLIB_OBJS)

# ------------------------------------
# OPENOCD FLASH CONFIGURATION
# ------------------------------------
OPENOCD_CFG_TM4C123GH6PM = \
	/opt/homebrew/opt/open-ocd/share/openocd/scripts/board/ek-tm4c123gxl.cfg

# ------------------------------------
# BUILD TARGETS
# ------------------------------------
.PHONY: all hello_tm4c123gh6pm flash_tm4c123gh6pm size size-hello clean \
		frodo_tm4c123gh6pm

all: hello_tm4c123gh6pm

# FrodoKEM build target
frodo_tm4c123gh6pm: $(BUILD_TM4C123GH6PM)/frodo1344.elf
	@echo ""
	@$(SIZE) $
	@echo ""
	@echo "Build OK: $<"
	@echo "Flash with: make flash_tm4c123gh6pm"

# Hello World Build for TM4C123GH6PM
hello_tm4c123gh6pm: ${BUILD_TM4C123GH6PM}/hello_uart.elf
	@echo ""
	@$(SIZE) $<
	@echo ""
	@echo "Build OK: $<"
	@echo "Flash with: make flash_tm4c123gh6pm-hello"

# TODO: frodo_tm4c123gh6pm target
# TODO: hello_tm4c1294ncpdt target
# TODO: frodo_tm4c1294ncpdt target

# ------------------------------------
# LINK RULES
# ------------------------------------

# Link FrodoKEM ELF
$(BUILD_TM4C123GH6PM)/frodo1344.elf: \
		$(OBJS_FRODO_TM4C123GH6PM) | $(BUILD_TM4C123GH6PM)
	$(CC) $(LDFLAGS_TM4C123GH6PM) -o $@ $^
	$(OBJCOPY) -O binary $@ $(BUILD_TM4C123GH6PM)/frodo1344.bin


# TM4C123GH6PM Hello World ELF + binary
$(BUILD_TM4C123GH6PM)/hello_uart.elf: $(OBJS_HELLO_TM4C123GH6PM) | $(BUILD_TM4C123GH6PM)
	$(CC) $(LDFLAGS_TM4C123GH6PM) -o $@ $^
	$(OBJCOPY) -O binary $@ $(BUILD_TM4C123GH6PM)/hello_uart.bin

# TODO: TM4C123GH6PM FrodoKEM ELF
# TODO: TM4C1294NCPDT Hello World ELF
# TODO: TM4C1294NCPDT FrodoKEM ELF

# ------------------------------------
# COMPILE RULES
# ------------------------------------

# TivaWare Peripheral Drivers
$(BUILD_TM4C123GH6PM)/%.o: $(TIVAWARE)/driverlib/%.c | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -c -o $@ $<

# TM4C123GH6PM Startup
$(BUILD_TM4C123GH6PM)/startup_gcc.o: $(STARTUP_TM4C123GH6PM) | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -c -o $@ $<

# TM4C123GH6PM Hello UART
$(BUILD_TM4C123GH6PM)/hello_uart.o: $(HELLO_TM4C123GH6PM) | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -c -o $@ $<

# Compile FrodoKEM core sources for TM4C123G
$(BUILD_TM4C123GH6PM)/%.o: $(SRC_DIR)/%.c | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -c -o $@ $<


# Compile HAL sources
$(BUILD_TM4C123GH6PM)/hal_rng.o: $(TM4C123GH6PM_DIR)/hal_rng.c \
        | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -DFRODO_RNG_FIXED -c -o $@ $<

$(BUILD_TM4C123GH6PM)/hal_aes.o: $(TM4C123GH6PM_DIR)/hal_aes.c \
		$(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -c -o $@ $<

$(BUILD_TM4C123GH6PM)/hal_shake.o: $(TM4C123GH6PM_DIR)/hal_shake.c \
        | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -c -o $@ $<

# Compile main.c
$(BUILD_TM4C123GH6PM)/main.o: $(TM4C123GH6PM_DIR)/main.c \
        | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -c -o $@ $<

$(BUILD_TM4C123GH6PM)/aes.o: $(TEST_DIR)/aes.c | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -c -o $@ $<

$(BUILD_TM4C123GH6PM)/fips202.o: $(TEST_DIR)/fips202.c | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -c -o $@ $<

# pack.o
$(BUILD_TM4C123GH6PM)/pack.o: $(SRC_DIR)/pack.c | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -DFRODO_TARGET -c -o $@ $<

# sample.o
$(BUILD_TM4C123GH6PM)/sample.o: $(SRC_DIR)/sample.c | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -DFRODO_TARGET -c -o $@ $<

# encode.o
$(BUILD_TM4C123GH6PM)/encode.o: $(SRC_DIR)/encode.c | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -DFRODO_TARGET -c -o $@ $<

# matrix.o
$(BUILD_TM4C123GH6PM)/matrix.o: $(SRC_DIR)/matrix.c | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -DFRODO_TARGET -c -o $@ $<

# gen_A.o
$(BUILD_TM4C123GH6PM)/gen_A.o: $(SRC_DIR)/gen_A.c | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -DFRODO_TARGET -c -o $@ $<

# kem.o
$(BUILD_TM4C123GH6PM)/kem.o: $(SRC_DIR)/kem.c | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -DFRODO_TARGET -c -o $@ $<

# util.o
$(BUILD_TM4C123GH6PM)/util.o: $(SRC_DIR)/util.c | $(BUILD_TM4C123GH6PM)
	$(CC) $(CFLAGS_TM4C123GH6PM) -DFRODO_TARGET -c -o $@ $<


# TODO: TM4C123GH6PM FrodoKEM Core Sources
# TODO: TM4C1294NCPDT Startup
# TODO: TM4C1294NCPDT Hello UART
# TODO: TM4C1294NCPDT FrodoKEM Core Sources

# ------------------------------------
# FLASH VIA OPENOCD
# ------------------------------------
flash_tm4c123gh6pm-hello: $(BUILD_TM4C123GH6PM)/hello_uart.elf
	openocd -f $(OPENOCD_CFG_TM4C123GH6PM) \
		-c "program $< verify reset exit"

# Flash FrodoKEM
flash_tm4c123gh6pm: $(BUILD_TM4C123GH6PM)/frodo1344.elf
	openocd -f $(OPENOCD_CFG_TM4C123GH6PM) \
		-c "program $< verify reset exit"


# ------------------------------------
# SIZE REPORTS
# ------------------------------------
size-hello: $(BUILD_TM4C123GH6PM)/hello_uart.elf
	$(SIZE) -A $<

size: $(BUILD_TM4C123GH6PM)/frodo1344.elf
	$(SIZE) -A $<

# ------------------------------------
# BUILD DIRECTORIES
# ------------------------------------
$(BUILD_TM4C123GH6PM):
	mkdir -p $@

# ------------------------------------
# CLEAN
# ------------------------------------
clean:
	rm -rf $(BUILD_TM4C123GH6PM)
	@echo "Clean complete"