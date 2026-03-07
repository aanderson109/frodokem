# encoding.py
# Contains the matrix encoding/decoding algorithms
from frodokem.reference.params import FrodoParams
from frodokem.reference.utils import ec, dc, bytes_to_bits


def frodo_encode(k_vector: bytes, params: FrodoParams) -> list[list[int]]:
    """Encodes bit strings of length `ell` as
    `mbar` by `nbar` matrices by applying the
    `ec()` function to B-bit substrings sequentially;
    fills the matrix row-by-row.

    Because each B-bit substring is treated as an
    integer and encoded with `ec()`, the B-bit values
    are placed by most significant bit correspnding to
    modulo `q`.

    Args:
        k (bytes): _description_
        params (FrodoParams): _description_

    Returns:
        np.ndarray: _description_
    """
    # Convert bytes to bits to work sequentially
    # Matches *Input:* in Algorithm 1 (Frodo.Encode)
    bits = bytes_to_bits(k_vector)

    # Initialize the matrix K as an mbar-by-nbar matrix in Z_q
    # Matches *Output:* in Algorithm 1 (Frodo.Encode)
    K_matrix = [[0]*params.nbar for _ in range(params.mbar)]

    for i in range(params.mbar):
        for j in range(params.nbar):
            for l in range(params.B):
                step = (i*params.nbar + j)*(params.B + l)
                k_value = k_vector[step] * 2**l
                encoded_k = ec(k_value, params)
                K_matrix[i][j] = encoded_k
    return K_matrix


def frodo_decode(K_matrix: list[list[int]], params: FrodoParams) -> list[int]:
    """Decodes mbar-by-nbar matrix into a bit string of length `ell`

    Args:
        K_matrix (list[list[int]]): `mbar`-by-`nbar` matrix
        params (FrodoParams): FrodoKEM parameter set being used

    Returns:
        int: Bit string of length `ell`
    """
    k_vector = 0*[params.ell]

    for i in range(params.mbar):
        for j in range(params.nbar):
            decoded_k = dc(K_matrix[i][j], params)
            for l in range(params.B):
                step = (i*params.nbar + j)*(params.B + l)
                k_vector[step] = (decoded_k >> l) & 1
    return k_vector

