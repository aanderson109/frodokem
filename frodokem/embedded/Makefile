# ---------------------------------------------------------------------
# FrodoKEM-1344-AES Host Test Makefile
#
# Targets:
# 	make test		->  build and run all unit/functionality tests (~31 tests)
#	make kat		->  run NIST KAT verification (100/100, ~26 seconds on M4 Max)
#	make format	    ->  clang-format all source files
#	make clean		->  remove build artifacts
#
# Notes:
#	+ KAT build links against OpenSSL for NIST AES-256 CTR DRBG
#
#	+ util_kat.o is compiled with -DFRODO_KAT_TEST to suppress the
#	  /dev/urandom randombytes in favor of rng_drbg.c
#
#	+ OpenSSL path assumes Homebrew install on macOS
# ---------------------------------------------------------------------

# -------------------------------------------
# TOOLCHAIN
# -------------------------------------------
CC = gcc

# -------------------------------------------
# DIRECTORIES
# -------------------------------------------
SRC_DIR 	= ../src
INCLUDE_DIR = ../include
BUILD_DIR	= build
OPENSSL_INC = /opt/homebrew/opt/openssl/include
OPENSSL_LIB = /opt/homebrew/opt/openssl/lib

# -------------------------------------------
# COMPILER FLAGS
# -------------------------------------------
CFLAGS = \
	-Wall 			 \
	-Wextra 		 \
	-std=c99 		 \
	-O2 			 \
	-I$(INCLUDE_DIR) \
	-DAES128=1

# -------------------------------------------
# BUILD TARGETS
# -------------------------------------------
.PHONY: all test kat format clean

all: test

# Run tests (approx. 31 across all modules)
test: $(BUILD_DIR)/unit_tests
	$(BUILD_DIR)/unit_tests
	@echo ""
	@echo "All tests passed."

# Run NIST KAT verification
kat: $(BUILD_DIR)/kat_kem
	$(BUILD_DIR)/kat_kem

# clang-format all source + header files
format: 
	find $(SRC_DIR) $(INCLUDE_DIR) -name "*.c" -o -name "*.h" | \
		xargs clang-format -i
	@echo "Formatting complete"

# -------------------------------------------
# COMMON OBJECT FILES
# -------------------------------------------
COMMON_OBJS = \
	$(BUILD_DIR)/pack.o 			\
	$(BUILD_DIR)/sample.o			\
	$(BUILD_DIR)/encode.o			\
	$(BUILD_DIR)/matrix.o			\
	$(BUILD_DIR)/gen_A.o			\
	$(BUILD_DIR)/kem.o				\
	$(BUILD_DIR)/hal_aes_soft.o 	\
	$(BUILD_DIR)/hal_shake_soft.o 	\
	$(BUILD_DIR)/aes.o 				\
	$(BUILD_DIR)/fips202.o

# -------------------------------------------
# LINK RULES
# -------------------------------------------

# Unit test binary
$(BUILD_DIR)/unit_tests: \
		$(BUILD_DIR)/unit_tests.o \
		$(BUILD_DIR)/util.o		\
		$(COMMON_OBJS)			\
		| $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^

# KAT verification binary
$(BUILD_DIR)/kat_kem: \
		$(BUILD_DIR)/kat_kem.o	\
		$(BUILD_DIR)/rng_drbg.o \
		$(BUILD_DIR)/util_kat.o \
		$(COMMON_OBJS)			\
		| $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(OPENSSL_INC) -o $@ $^ -L$(OPENSSL_LIB) -lssl -lcrypto

# -------------------------------------------
# COMPILE RULES (FROODKEM CORE)
# -------------------------------------------

# pack.o
$(BUILD_DIR)/pack.o: $(SRC_DIR)/pack.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# sample.o
$(BUILD_DIR)/sample.o: $(SRC_DIR)/sample.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# encode.o
$(BUILD_DIR)/encode.o: $(SRC_DIR)/encode.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# matrix.o
$(BUILD_DIR)/matrix.o: $(SRC_DIR)/matrix.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# gen_A.o
$(BUILD_DIR)/gen_A.o: $(SRC_DIR)/gen_A.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# kem.o
$(BUILD_DIR)/kem.o: $(SRC_DIR)/kem.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# util.o
$(BUILD_DIR)/util.o: $(SRC_DIR)/util.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# util_kat.o
# KAT build compiles util.c without randombytes
$(BUILD_DIR)/util_kat.o: $(SRC_DIR)/util.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DFRODO_KAT_TEST -c -o $@ $<

# -------------------------------------------
# COMPILE RULES (HARDWARE ABSTRACTION LAYER)
# -------------------------------------------

# hal_aes_soft.o
$(BUILD_DIR)/hal_aes_soft.o: hal_aes_soft.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# hal_shake_soft.o
$(BUILD_DIR)/hal_shake_soft.o: hal_shake_soft.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# aes.o
$(BUILD_DIR)/aes.o: aes.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# fips202.o
$(BUILD_DIR)/fips202.o: fips202.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# rng_drbg.o -> NIST AES-256 CTR DRBG via OpenSSL
# KAT build gets randombytes from rng_drbg.c
$(BUILD_DIR)/rng_drbg.o: rng/rng_drbg.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(OPENSSL_INC) -Wno-deprecated-declarations -c -o $@ $<

# -------------------------------------------
# COMPILE RULES (TEST HARNESS)
# -------------------------------------------

# unit_tests.o
$(BUILD_DIR)/unit_tests.o: unit_tests.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# kat_kem.o -> includes OpenSSL headers + DRBG
$(BUILD_DIR)/kat_kem.o: kat_kem.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(OPENSSL_INC) -Irng -DFRODO_KAT_TEST -c -o $@ $<

# -------------------------------------------
# BUILD DIRECTORY
# -------------------------------------------
$(BUILD_DIR):
	mkdir -p $@

# -------------------------------------------
# CLEAN
# -------------------------------------------
clean:
	rm -rf $(BUILD_DIR)
	@echo "Clean complete"