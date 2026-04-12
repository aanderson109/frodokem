# FrodoKEM-1344-AES Test Makefile
#
# Targets:
# 	make test: build and run all teests
#	make pack: build and runpck/unpack test
#	make clean: remove build artifacts

# Toolchain
CC = gcc

# Directories
SRC_DIR = ../src
INCLUDE_DIR = ../include
BUILD_DIR = build
OPENSSL_INC = /opt/homebrew/opt/openssl/include
OPENSSL_LIB = /opt/homebrew/opt/openssl/lib

# Compiler flags
CFLAGS = \
	-Wall \
	-Wextra \
	-std=c99 \
	-O2 \
	-I$(INCLUDE_DIR) \
	-DAES128=1

# Build Targets
.PHONY: all test pack clean kat

all: test

test: pack
	@echo ""
	@echo "All tests passed."

# Pack/Unpack Roundtrip Test
pack: $(BUILD_DIR)/kat_test
	$(BUILD_DIR)/kat_test

$(BUILD_DIR)/kat_test: \
	$(BUILD_DIR)/kat_test.o \
	$(BUILD_DIR)/pack.o \
	$(BUILD_DIR)/sample.o \
	$(BUILD_DIR)/encode.o \
	$(BUILD_DIR)/matrix.o \
	$(BUILD_DIR)/gen_A.o \
	$(BUILD_DIR)/kem.o \
	$(BUILD_DIR)/util.o \
	$(BUILD_DIR)/hal_aes_soft.o \
	$(BUILD_DIR)/hal_shake_soft.o \
	$(BUILD_DIR)/aes.o \
	$(BUILD_DIR)/fips202.o
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/hal_shake_soft.o: hal_shake_soft.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/kat_test.o: kat_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/pack.o: $(SRC_DIR)/pack.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/sample.o: $(SRC_DIR)/sample.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/encode.o: $(SRC_DIR)/encode.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/matrix.o: $(SRC_DIR)/matrix.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/gen_A.o: $(SRC_DIR)/gen_A.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/kem.o: $(SRC_DIR)/kem.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/hal_aes_soft.o: hal_aes_soft.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/aes.o: aes.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/util.o: $(SRC_DIR)/util.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/fips202.o: fips202.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

kat: $(BUILD_DIR)/kat_kem
	$(BUILD_DIR)/kat_kem

$(BUILD_DIR)/kat_kem: \
	$(BUILD_DIR)/kat_kem.o \
	$(BUILD_DIR)/rng_drbg.o \
	$(BUILD_DIR)/pack.o \
	$(BUILD_DIR)/sample.o \
	$(BUILD_DIR)/encode.o \
	$(BUILD_DIR)/matrix.o \
	$(BUILD_DIR)/gen_A.o \
	$(BUILD_DIR)/kem.o \
	$(BUILD_DIR)/util_kat.o \
	$(BUILD_DIR)/hal_aes_soft.o \
	$(BUILD_DIR)/hal_shake_soft.o \
	$(BUILD_DIR)/aes.o \
	$(BUILD_DIR)/fips202.o
	$(CC) $(CFLAGS) -I$(OPENSSL_INC) -o $@ $^ -L$(OPENSSL_LIB) -lssl -lcrypto

$(BUILD_DIR)/kat_kem.o: kat_kem.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(OPENSSL_INC) -Irng -DFRODO_KAT_TEST -c -o $@ $<

$(BUILD_DIR)/rng_drbg.o: rng/rng_drbg.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(OPENSSL_INC) -Wno-deprecated-declarations -c -o $@ $<

$(BUILD_DIR)/util_kat.o: $(SRC_DIR)/util.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DFRODO_KAT_TEST -c -o $@ $<

# Build directory
$(BUILD_DIR):
	mkdir -p $@

# Clean
clean:
	rm -rf $(BUILD_DIR)
	@echo "Clean complete"