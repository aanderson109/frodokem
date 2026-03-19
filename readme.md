# FrodoKEM Optimization Project

## FrodoKEM-1344-AES Cryptol Specification

A Cryptol specification of FrodoKEM-1344-AES, verified against the official NIST Known Answer Test (KAT) provided by the FrodoKEM design team's GitHub. This specification serves as a golden reference model for a future C implementation targeting the Texas Instruments TM4C1294 microcontroller.

## Development Team

| Team Member | Organization |
| ----------- | ------------ |
| Alex Anderson | Virginia Tech |
| Max Nordberg | Virginia Tech |
| Aemiliana Cruz | Virginia Tech |

## Project Structure

- `frodokem/cryptol/frodokem.cry` is the Cryptol specification of FrodoKEM-1344-AES
- `frodokem/cryptol/tests/kat_test.py` is a KAT test harness using the Cryptol Python API
- `frodokem/cryptol/tests/kat/` contains the NIST KAT files for FrodoKEM-1344
- `frodokem/cryptol/cryptol-specs/` contains Galois, Inc. cryptol-specs submodule
- `frodokem/optimized/` contains the future C implementation (TBD) optimized for the target platform

## Dependencies

- [Cryptol](https://cryptol.net) >= 3.0
- [cryptol-specs](https://github.com/GaloisInc/cryptol-specs) --> included as submodule
- Python >= 3.10 with `cryptol` package for KAT testing (+ `bitstring` and `cryptography`)

## Running the KAT Test
```bash
cd frodokem/cryptol/tests
python3 kat_test.py
```

Expected output:
```text
aandrs [tests] % python3 kat_test.py
A[0][0] with KAT Seed_A: BV(16, 0x87fa)
B[0][0] from KAT pk: BV(16, 0xa00f)
Decaps took: 3193.0 seconds
Expected ss: 376955161273fc667f3feae5ec98681820dbd759971bb0a2d2bec4510f557e83
Got ss:      376955161273fc667f3feae5ec98681820dbd759971bb0a2d2bec4510f557e83
Match:       True
Shared secrets matched!
```


## References

- [FrodoKEM Preliminary Specification Proposal (2025)](https://frodokem.org/files/FrodoKEM_standard_proposal_20250929.pdf)
- [FrodoKEM Specification - Third Round, NIST PQC Competition (2020)](https://frodokem.org/files/FrodoKEM-specification-20200930.pdf)
- [FrodoKEM General Website](https://frodokem.org)
- [FrodoKEM GitHub](https://github.com/microsoft/PQCrypto-LWEKE/tree/master)
- [Galois cryptol-specs](https://github.com/GaloisInc/cryptol-specs)
- [Cryptol Style Guide](https://github.com/weaversa/cryptol-course/blob/master/cryptol-style.md)
- [Microsoft Research - FrodoKEM](https://www.microsoft.com/en-us/research/blog/frodokem-a-conservative-quantum-safe-cryptographic-algorithm/)


