#!/bin/bash
# =============================================================================
# size_report.sh -- FrodoKEM-1344-AES ARM Cortex-M4F Size Characterization
#
# Runs arm-none-eabi-size on all FrodoKEM object files compiled for
# TM4C123GH6PM and produces a summary report for report_2.
#
# Usage:
#   cd target/
#   bash size_report.sh
#
# Output:
#   tm4c123g/build/size_report.txt
# =============================================================================

# Parse TARGET argument
for arg in "$@"; do
    case $arg in
        TARGET=*) TARGET="${arg#TARGET=}" ;;
    esac
done

# Default to tm4c123g if not specified
TARGET=${TARGET:-tm4c123g}

# Set paths based on TARGET
BUILD=${TARGET}/build
OUT=${BUILD}/size_report.txt

# Set size tool based on target
if [ "$TARGET" = "tm4c123g" ]; then
    SIZE=arm-none-eabi-size
else
    SIZE=size
fi

#BUILD=tm4c123g/build
#OUT=$BUILD/size_report.txt
#SIZE=arm-none-eabi-size

echo "FrodoKEM-1344-AES ARM Cortex-M4F Size Report" > $OUT
echo "Generated: $(date)"                           >> $OUT
echo "Compiler:  $($SIZE --version | head -1)"      >> $OUT
echo "Target:    TM4C123GH6PM (Cortex-M4F)"        >> $OUT
echo "Flags:     -mcpu=cortex-m4 -mthumb -O2"      >> $OUT
echo ""                                             >> $OUT
echo "=============================================" >> $OUT

# -----------------------------------------------------------------------------
# Per-module breakdown
# -----------------------------------------------------------------------------
echo ""                                             >> $OUT
echo "--- Per-module breakdown ---"                 >> $OUT
echo ""                                             >> $OUT

MODULES=(
    "kem.o      KeyGen/Encaps/Decaps"
    "matrix.o   Matrix arithmetic"
    "sample.o   CDF error sampling"
    "encode.o   Encode/Decode"
    "pack.o     Pack/Unpack"
    "gen_A.o    Public matrix A generation"
    "util.o     ct_verify/ct_select/SHAKE256"
    "aes.o      tiny-AES (HAL dependency)"
    "fips202.o  fips202 SHAKE256 (HAL dependency)"
    "hal_aes.o  AES HAL"
    "hal_shake.o SHAKE HAL"
    "hal_rng.o  RNG HAL"
    "main.o     Board init and KEM runner"
    "startup_gcc.o Reset handler and vector table"
    "syscalls.o Newlib bare-metal syscall stubs"
)

TOTAL_TEXT=0
TOTAL_BSS=0
TOTAL_DATA=0

for entry in "${MODULES[@]}"; do
    OBJ=$(echo $entry | awk '{print $1}')
    DESC=$(echo $entry | cut -d' ' -f2-)
    PATH_OBJ=$BUILD/$OBJ

    if [ ! -f "$PATH_OBJ" ]; then
        echo "  [MISSING] $OBJ" >> $OUT
        continue
    fi

    echo "--- $OBJ ($DESC) ---"               >> $OUT
    $SIZE -A $PATH_OBJ                        >> $OUT

    # Extract .text and .bss for totals
    TEXT=$($SIZE -A $PATH_OBJ | awk '/^\.text/{sum+=$2} END{print sum+0}')
    BSS=$($SIZE -A $PATH_OBJ  | awk '/^\.bss/{sum+=$2} END{print sum+0}')
    DATA=$($SIZE -A $PATH_OBJ | awk '/^\.data/{sum+=$2} END{print sum+0}')

    TEXT=${TEXT:-0}
    BSS=${BSS:-0}
    DATA=${DATA:-0}

    TOTAL_TEXT=$((TOTAL_TEXT + TEXT))
    TOTAL_BSS=$((TOTAL_BSS + BSS))
    TOTAL_DATA=$((TOTAL_DATA + DATA))

    echo "" >> $OUT
done

# -----------------------------------------------------------------------------
# Summary table
# -----------------------------------------------------------------------------
echo "=============================================" >> $OUT
echo ""                                             >> $OUT
echo "--- Summary ---"                              >> $OUT
echo ""                                             >> $OUT
printf "%-30s %10s %10s %10s\n" \
    "Section" "Bytes" "KiB" "%" >> $OUT
printf "%-30s %10s %10s %10s\n" \
    "-------" "-----" "---" "-" >> $OUT

TM4C123G_FLASH=262144   # 256K
TM4C123G_SRAM=32768     # 32K
TM4C1294_FLASH=1048576  # 1M
TM4C1294_SRAM=262144    # 256K

TEXT_KIB=$(echo "scale=1; $TOTAL_TEXT / 1024" | bc)
BSS_KIB=$(echo  "scale=1; $TOTAL_BSS  / 1024" | bc)
DATA_KIB=$(echo "scale=1; $TOTAL_DATA / 1024" | bc)

TEXT_PCT_123G=$(echo "scale=1; $TOTAL_TEXT * 100 / $TM4C123G_FLASH" | bc)
BSS_PCT_123G=$(echo  "scale=1; $TOTAL_BSS  * 100 / $TM4C123G_SRAM"  | bc)
TEXT_PCT_1294=$(echo "scale=1; $TOTAL_TEXT * 100 / $TM4C1294_FLASH" | bc)
BSS_PCT_1294=$(echo  "scale=1; $TOTAL_BSS  * 100 / $TM4C1294_SRAM"  | bc)

printf "%-30s %10d %10s\n" \
    ".text (flash / code)"  $TOTAL_TEXT  "${TEXT_KIB}K" >> $OUT
printf "%-30s %10d %10s\n" \
    ".bss  (SRAM / static)" $TOTAL_BSS   "${BSS_KIB}K"  >> $OUT
printf "%-30s %10d %10s\n" \
    ".data (SRAM / init)"   $TOTAL_DATA  "${DATA_KIB}K" >> $OUT

echo ""                                                     >> $OUT
echo "--- Platform viability ---"                           >> $OUT
echo ""                                                     >> $OUT
printf "%-20s %8s %8s %10s %10s\n" \
    "Board" "Flash" "SRAM" ".text fit?" ".bss fit?" >> $OUT
printf "%-20s %8s %8s %10s %10s\n" \
    "-----" "-----" "----" "----------" "----------" >> $OUT

# TM4C123G
if [ $TOTAL_TEXT -le $TM4C123G_FLASH ]; then
    TEXT_FIT_123G="YES (${TEXT_PCT_123G}%)"
else
    TEXT_FIT_123G="NO"
fi
if [ $TOTAL_BSS -le $TM4C123G_SRAM ]; then
    BSS_FIT_123G="YES (${BSS_PCT_123G}%)"
else
    OVERFLOW_123G=$(( TOTAL_BSS - TM4C123G_SRAM ))
    BSS_FIT_123G="NO (+${OVERFLOW_123G}B)"
fi

printf "%-20s %8s %8s %10s %10s\n" \
    "TM4C123GH6PM" "256K" "32K" \
    "$TEXT_FIT_123G" "$BSS_FIT_123G" >> $OUT

# TM4C1294
if [ $TOTAL_TEXT -le $TM4C1294_FLASH ]; then
    TEXT_FIT_1294="YES (${TEXT_PCT_1294}%)"
else
    TEXT_FIT_1294="NO"
fi
if [ $TOTAL_BSS -le $TM4C1294_SRAM ]; then
    BSS_FIT_1294="YES (${BSS_PCT_1294}%)"
else
    BSS_FIT_1294="NO"
fi

printf "%-20s %8s %8s %10s %10s\n" \
    "TM4C1294NCPDT" "1M" "256K" \
    "$TEXT_FIT_1294" "$BSS_FIT_1294" >> $OUT

echo ""                                      >> $OUT
echo "=============================================" >> $OUT

# -----------------------------------------------------------------------------
# Print to terminal as well
# -----------------------------------------------------------------------------
cat $OUT
echo ""
echo "Report saved to: $OUT"