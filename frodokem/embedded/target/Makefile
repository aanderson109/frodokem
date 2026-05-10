# --------------------------------------------------------------------------------
# FrodoKEM-1344-AES Makefile
#
# Handles all build targets: host, host-kat, and embedded platforms.
# Select target with TARGET variable (default: tm4c123g)
#
# Usage:
#	make TARGET=tm4c123g		-> build embedded FrodoKEM (default)
#	make TARGET=tm4c123g size	-> size report from object files
#	make TARGET=tm4c123g report	-> detailed per-module size report
#	make TARGET=tm4c123g flash	-> flash via OpenOCD
#	make TARGET=host test		-> build and run unit tests
#	make TARGET=host-kat kat	-> build and run NIST KAT verification
#	make format					-> clang-format all source files
#	make TARGET=<target> clean	-> remove build artifacts
#	make clean-all				-> remove all build artifacts
#
# Platform Specifications:
#	TM4C123GH6PM  -> Cortex-M4; 256KB flash; 32KB SRAM; no hardware AES
#	TM4C1294NCPDT -> Cortex-M4F; 1MB flash; 256KB SRAM; hardware AES
#
# Notes:
#	- KAT build links against OpenSSL for NIST AES-256 CTR DRBG
#	- OpenSSL path assumes Homebrew install on macOS
#	- ti_ek-tm4c123gxl.cfg fails with OpenOCD -> use deprecated ek-tm4c123gxl.cfg
# --------------------------------------------------------------------------------

TARGET ?= tm4c123g

# --------------------------------------------------------------------------------
# DIRECTORIES
# --------------------------------------------------------------------------------
ROOT 		= ..
INCLUDE_DIR = $(ROOT)/include
SRC_DIR 	= $(ROOT)/src
HAL_DIR 	= $(ROOT)/hal
TEST_DIR 	= $(ROOT)/test
BUILD_DIR 	= $(TARGET)/build

# --------------------------------------------------------------------------------
# TOOLCHAIN & FLAGS BY TARGET
# --------------------------------------------------------------------------------
ifeq ($(TARGET), host)
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -I$(INCLUDE_DIR) -DAES128=1
LDFLAGS = 
HAL_PLATFORM_DIR = $(HAL_DIR)/host

else ifeq ($(TARGET), host-kat)
CC = gcc
OPENSSL_INC = /opt/homebrew/opt/openssl/include
OPENSSL_LIB = /opt/homebrew/opt/openssl/lib
CFLAGS = -Wall -Wextra -std=c99 -O2	-I$(INCLUDE_DIR) -I$(OPENSSL_INC) -I$(TEST_DIR)/rng -DAES128=1
LDFLAGS = -L$(OPENSSL_LIB) -lssl -lcrypto
HAL_PLATFORM_DIR = $(HAL_DIR)/host

else ifeq ($(TARGET), tm4c123g)
CC = arm-none-eabi-gcc
OBJCOPY = arm-none-eabi-objcopy
SIZE = arm-none-eabi-size
VENDOR = vendor/tivaware
CFLAGS = \
    -Wall -Wextra -std=c99 -O2	\
	-I$(INCLUDE_DIR)			\
	-mcpu=cortex-m4				\
	-mthumb						\
	-mfpu=fpv4-sp-d16			\
	-mfloat-abi=hard			\
	-ffunction-sections			\
	-fdata-sections				\
	-Dgcc						\
	-I$(VENDOR)					\
	-I$(VENDOR)/inc				\
	-I$(VENDOR)/driverlib		\
	-DTARGET_TM4C123GH6PM		\
	-DFRODO_TARGET				\
	-DFRODO_RNG_FIXED
LDFLAGS = \
	-mthumb						\
	-mcpu=cortex-m4				\
	-mfpu=fpv4-sp-d16			\
	-mfloat-abi=hard			\
	-nostartfiles				\
	-Wl,--gc-sections			\
	-Ttm4c123g/tm4c123gh6pm.ld	\
	-Wl,-Map=$(BUILD_DIR)/frodo1344.map
HAL_PLATFORM_DIR = $(HAL_DIR)/tm4c123g

else
	$(error Unknown TARGET: $(TARGET). Valid targets: host, host-kat, tm4c123g)
endif

# --------------------------------------------------------------------------------
# COMMON SOURCES
# --------------------------------------------------------------------------------
FRODO_SRCS = \
	$(SRC_DIR)/kem.c	\
	$(SRC_DIR)/matrix.c \
	$(SRC_DIR)/sample.c \
	$(SRC_DIR)/encode.c \
	$(SRC_DIR)/pack.c	\
	$(SRC_DIR)/gen_A.c	\
	$(SRC_DIR)/util.c

HAL_PLATFORM_SRCS = \
	$(HAL_PLATFORM_DIR)/hal_aes.c	\
	$(HAL_PLATFORM_DIR)/hal_shake.c \
	$(HAL_PLATFORM_DIR)/hal_rng.c

HAL_COMMON_SRCS = \
	$(HAL_DIR)/common/aes.c \
	$(HAL_DIR)/common/fips202.c

# KAT build swaps hal_rng for rng_drbg
ifeq ($(TARGET), host-kat)
HAL_PLATFORM_SRCS := $(filter-out	\
    $(HAL_PLATFORM_DIR)/hal_rng.c,	\
    $(HAL_PLATFORM_SRCS))
KAT_RNG_SRC = $(TEST_DIR)/rng/rng_drbg.c
endif

# --------------------------------------------------------------------------------
# OBJECT FILES BY TARGET
# --------------------------------------------------------------------------------
FRODO_OBJS		  = $(patsubst $(SRC_DIR)/%.c,			$(BUILD_DIR)/%.o, $(FRODO_SRCS))
HAL_PLATFORM_OBJS = $(patsubst $(HAL_PLATFORM_DIR)/%.c, $(BUILD_DIR)/%.o, $(HAL_PLATFORM_SRCS))
HAL_COMMON_OBJS	  = $(patsubst $(HAL_DIR)/common/%.c,	$(BUILD_DIR)/%.o, $(HAL_COMMON_SRCS))
COMMON_OBJS 	  = $(FRODO_OBJS) $(HAL_PLATFORM_OBJS) $(HAL_COMMON_OBJS)

ifeq ($(TARGET), host)
MAIN_OBJ = $(BUILD_DIR)/main.o
ALL_OBJS = $(MAIN_OBJ) $(COMMON_OBJS)

else ifeq ($(TARGET), host-kat)
KAT_RNG_OBJ = $(BUILD_DIR)/rng_drbg.o
MAIN_OBJ = $(BUILD_DIR)/kat_kem.o
ALL_OBJS = $(MAIN_OBJ) $(KAT_RNG_OBJ) $(COMMON_OBJS)

else ifeq ($(TARGET), tm4c123g)
DRIVERLIB_SRCS = \
	$(VENDOR)/driverlib/sysctl.c \
	$(VENDOR)/driverlib/gpio.c	 \
	$(VENDOR)/driverlib/uart.c	 \
	$(VENDOR)/driverlib/systick.c
DRIVERLIB_OBJS = $(patsubst $(VENDOR)/driverlib/%.c, \
                 $(BUILD_DIR)/%.o, $(DRIVERLIB_SRCS))
ALL_OBJS = \
    $(BUILD_DIR)/startup_gcc.o \
    $(BUILD_DIR)/main.o		   \
    $(BUILD_DIR)/syscalls.o	   \
    $(COMMON_OBJS)			   \
    $(DRIVERLIB_OBJS)
endif

# --------------------------------------------------------------------------------
# MAIN SOURCE SELECTION
# --------------------------------------------------------------------------------
ifeq ($(TARGET), tm4c123g)
MAIN_SRC = tm4c123g/main.c
else ifeq ($(TARGET), host)
MAIN_SRC = host/main.c
endif

# --------------------------------------------------------------------------------
# DEFAULT GOAL
# --------------------------------------------------------------------------------
ifeq ($(TARGET), tm4c123g)
DEFAULT_GOAL = $(BUILD_DIR)/frodo1344.elf
else ifeq ($(TARGET), host)
DEFAULT_GOAL = $(BUILD_DIR)/frodo_host
else ifeq ($(TARGET), host-kat)
DEFAULT_GOAL = $(BUILD_DIR)/kat_kem
endif

# --------------------------------------------------------------------------------
# PHONY TARGETS
# --------------------------------------------------------------------------------
.PHONY: all test kat flash size report format clean clean-all

all: $(DEFAULT_GOAL)

# --------------------------------------------------------------------------------
# BUILD & RUN TARGETS
# --------------------------------------------------------------------------------

# Unit Tests (host only)
test: $(BUILD_DIR)/unit_tests
	$(BUILD_DIR)/unit_tests
	@echo ""
	@echo "All tests passed."

$(BUILD_DIR)/unit_tests: \
		$(BUILD_DIR)/unit_tests.o \
		$(COMMON_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^

# KAT Verification (host-kat only)
kat: $(BUILD_DIR)/kat_kem
	$(BUILD_DIR)/kat_kem

$(BUILD_DIR)/kat_kem: $(ALL_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Embedded ELF
$(BUILD_DIR)/frodo1344.elf: $(ALL_OBJS) | $(BUILD_DIR)
	$(CC) $(LDFLAGS) -o $@ $^
	$(OBJCOPY) -O binary $@ $(BUILD_DIR)/frodo1344.bin

# Host Image
$(BUILD_DIR)/frodo_host: $(ALL_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Flash
flash: $(BUILD_DIR)/frodo1344.elf
	openocd -f /opt/homebrew/opt/open-ocd/share/openocd/scripts/board/ek-tm4c123gxl.cfg \
		-c "program $< verify reset exit"

# --------------------------------------------------------------------------------
# SIZE
# --------------------------------------------------------------------------------
size: $(BUILD_DIR)/frodo1344.elf
	$(SIZE) -A $<

report:
	@bash tools/size_report.sh TARGET=$(TARGET)

# --------------------------------------------------------------------------------
# COMPILE RULES
# --------------------------------------------------------------------------------

# FrodoKEM core
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# HAL Platform
$(BUILD_DIR)/%.o: $(HAL_PLATFORM_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# HAL Common
$(BUILD_DIR)/%.o: $(HAL_DIR)/common/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# TivaWare driverlib
$(BUILD_DIR)/%.o: $(VENDOR)/driverlib/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# TM4C123G Board Files
$(BUILD_DIR)/startup_gcc.o: tm4c123g/startup_gcc.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/syscalls.o: tm4c123g/syscalls.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/main.o: $(MAIN_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Test Harness
$(BUILD_DIR)/unit_tests.o: $(TEST_DIR)/unit_tests.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/kat_kem.o: $(TEST_DIR)/kat_kem.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Wno-deprecated-declarations -c -o $@ $<

$(BUILD_DIR)/rng_drbg.o: $(TEST_DIR)/rng/rng_drbg.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Wno-deprecated-declarations -c -o $@ $<

# --------------------------------------------------------------------------------
# FORMAT
# --------------------------------------------------------------------------------
format:
	find $(SRC_DIR) $(INCLUDE_DIR) $(HAL_DIR) \( -name "*.c" -o -name "*.h" \) | \
		xargs clang-format -i
	@echo "Formatting complete"

# --------------------------------------------------------------------------------
# BUILD DIRECTORY
# --------------------------------------------------------------------------------
$(BUILD_DIR):
	mkdir -p $@

# --------------------------------------------------------------------------------
# CLEAN
# --------------------------------------------------------------------------------
clean:
	rm -rf $(BUILD_DIR)
	@echo "Clean: $(BUILD_DIR) removed"

clean-all:
	rm -rf host/build host-kat/build tm4c123g/build
	@echo "Clean: all build directories removed"