# FrodoKEM Notation

Due to the complexity associated with cryptography and its implementation, this document provides a reference for understanding the mathematics and underlying structure of FrodoKEM. It has three sections:

- **Parameters:** Values chosen specifically for the construction of FrodoKEM along with their constraints and the algorithms that rely on them.
- **Definitions:** These are invariant conditioins that articulate the relationships between the parameters. They include compliance tests that are used to ensure the reference model doesn't have an issue at the base layer.
- **Conventions:** Symbols, operators, and other notation-specific items that need a common meaning for those looking to understand the algorithms. Python equivalents are provided as well.


## Parameters
*Reference:* [Section 2.2](https://frodokem.org/files/FrodoKEM-specification-20200930.pdf)


| Symbol | Definition | Constraint | Used In |
| ------ | ---------- | ---------- | ------- |
| $\chi$ | Probability distribution on $\mathbb{Z}$ | N/A | TODO |
| $q$ | Integer modulus | $q = 2^D$ | TODO |
| $n$ | TODO | $n \equiv 0 \pmod{8}$ | TODO |
| $\bar{m}, \bar{n}$ | Integer matrix dimensions | N/A (fixed per parameter set) | TODO |
| $B$ | Bits encoded per matrix entry | $B \leq D$ | TODO |
| $D$ | TODO | $D \leq 16$ | TODO |
| $\ell$ | Length of bit strings that are encoded as $\bar{m} \times \bar{n}$ matrices | $\ell = B \cdot \bar{m} \cdot \bar{n}$ | TODO |
| $\mathrm{len}_{\mathrm{seed}_{\mathbf{A}}}$ | Bit length of seeds used for pseudorandom matrix generation | N/A (fixed per parameter set) | TODO |
| $\mathrm{len}_{\mathrm{seed}_{\mathbf{SE}}}$ | Bit length of seeds used for pseudorandom bit generation for error sampling | N/A (fixed per parameter set) | TODO |


## Definitions

| Definition | Description | Test |
| ---------- | ----------- | ---- |
| $q = 2^D$ | TODO | TODO: link to test |
| $B \leq D$ | TODO | TODO: link to test |
| $\ell = B \cdot \bar{m} \cdot \bar{n}$ | TODO | TODO: link to test |
| $2^B \leq q$ | TODO | TODO |
| $\mathrm{dc}(\mathrm{ec}(k)) = k$ | Decode is the inverse of encode | TODO |
| $\mathrm{ec}(k) := k \cdot \frac{q}{2^B}$ | Encode a B-bit integer into $\mathbb{Z}_q$ | TODO
| $\mathrm{dc}(c) := \lfloor c \cdot \frac{2^B}{q} \rfloor \mod 2^B$ | Decode $\mathbb{Z}_q element to a B-bit integer | TODO |



## Conventions

| Symbol | Meaning | Python |
| ------ | ------- | ------ |
| $\leftarrow$ | assignment | `x = a` |
| $\mathbb{Z}_q$ | integers mod $q$ | `x % params.q` |
| $\leftarrow_{\$}$ | sample uniformly at random | `secrets.randbelow(q)`|
| $\oplus$ | Exclusive OR (XOR) | `a ^ b` |
| $\lfloor x $rceil$ | round to nearest integer | TODO |
| $\mathbf{A}$ | matrix (bold uppercase) | `np.ndarray` |
| $\mathbf{a}$ | vector (bold lowercase) | `np.ndarray` |


# References

[1] https://frodokem.org/files/FrodoKEM-specification-20200930.pdf