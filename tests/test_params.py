# tests/test_params.py
# Used to exercise the relationship between parameters
# and ensure everything is what it should be
from frodokem.reference.params import FRODO_1344_AES, FRODO_976_AES, FRODO_640_AES


# Expected input and output sizes (bytes) for FrodoKEM
_EXPECTED_SIZES = {
    "FRODO_1344": {"sk": 43088, "pk": 21520, "c": 21632, "ss": 32},
    "FRODO_976": {"sk": 31296, "pk": 15632, "c": 15744, "ss": 24},
    "FRODO_640": {"sk": 19888, "pk": 9616, "c": 9720, "ss": 16},
}

def test_q_equals_2_to_D():
    for params in [FRODO_1344_AES, FRODO_976_AES, FRODO_640_AES]:
        assert params.q == 2 ** params.D


def test_ell_equals_B_times_mbar_times_nbar():
    for params in [FRODO_1344_AES, FRODO_976_AES, FRODO_640_AES]:
        assert params.length_mu == params.B * params.mbar * params.nbar


def test_cdf_weights_sum_to_65536():
    """
    Full distribution should sum to 2^16
    """
    for params in [FRODO_1344_AES, FRODO_976_AES, FRODO_640_AES]:
        total = params.cdf_table[0] + 2 * sum(params.cdf_table[1:])
        assert total == 65536


def test_keygen_output_sizes_1344():
    pk, sk = frodo_keygen(FRODO_1344_AES)
    assert len(sk) == _EXPECTED_SIZES["FRODO_1344"]["sk"]
    assert len(pk) == _EXPECTED_SIZES["FRODO_1344"]["pk"]