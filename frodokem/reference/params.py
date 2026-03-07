# params.py
# FrodoKEM Parameter Sets
from dataclasses import dataclass, field
from typing import Literal

# Error distributions for each parameter set
_CDF_1344 = (18286, 14320, 6876, 2023, 364, 40, 2)
_CDF_976 = (11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1)
_CDF_640 = (9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1)


@dataclass
class FrodoParams:
    """
    FrodoKEM parameter set. All length fields are in bits.
    Reference: FrodoKEM Third Round Spec (2021), Table 4
    """
    D: int      # modulus exponent q = 2^D
    q: int      # modulus
    n: int      # dimension of secret matrix S
    mbar: int   # 
    nbar: int
    B: int
    ell: int = field(init=False)    # calculated
    length_seed_A: int
    length_Z: int
    length_mu: int
    length_seed_SE: int
    length_S: int
    length_k: int
    length_PKH: int
    length_SS: int
    length_CHI: int
    shake_variant: Literal[128, 256]
    sigma: float
    cdf_table: tuple[int, ...]

    def __post_init__(self):
        self.ell = self.B * self.mbar * self.nbar


# FrodoKEM-1344-AES -- NIST Security Category 5
FRODO_1344_AES = FrodoParams(
    D = 16,
    q = 65536,      # 2^16
    n = 1344,
    mbar = 8,
    nbar = 8,
    B = 4,
    length_seed_A = 128,
    length_Z = 128,
    length_mu = 256,
    length_seed_SE = 256,
    length_S = 256,
    length_k = 256,
    length_PKH = 256,
    length_SS = 256,
    length_CHI = 16,
    sigma = 1.4,
    cdf_table = _CDF_1344,
    shake_variant = 256
)


# FrodoKEM-976-AES -- NIST Security Category 3
FRODO_976_AES = FrodoParams(
    D = 16,
    q = 65536,      # 2^16
    n = 976,
    mbar = 8,
    nbar = 8,
    B = 3,
    length_seed_A = 128,
    length_Z = 128,
    length_mu = 192,
    length_seed_SE = 192,
    length_S = 192,
    length_k = 192,
    length_PKH = 192,
    length_SS = 192,
    length_CHI = 16,
    sigma = 2.3,
    cdf_table = _CDF_976,
    shake_variant = 256
)


# FrodoKEM-640-AES -- NIST Security Category 1
FRODO_640_AES = FrodoParams(
    D = 15,
    q = 32768,      # 2^16
    n = 640,
    mbar = 8,
    nbar = 8,
    B = 2,
    length_seed_A = 128,
    length_Z = 128,
    length_mu = 128,
    length_seed_SE = 128,
    length_S = 128,
    length_k = 128,
    length_PKH = 128,
    length_SS = 128,
    length_CHI = 16,
    sigma = 2.8,
    cdf_table = _CDF_640,
    shake_variant = 128
)