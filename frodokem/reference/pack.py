# pack.py
# Includes Frodo.Pack, Frodo.Unpack
from frodokem.reference.params import FrodoParams
from frodokem.reference.utils import bytes_to_bits

def frodo_pack(C_matrix: list[list[int]], n1: int, n2: int, params: FrodoParams) -> list[int]:
    """Packs a matrix into a bit string by concatenating the D-bit matrix coefficients

    Args:
        C_matrix (list[list[int]]): Matrix to be packed
        params (params.FrodoParams): FrodoKEM parameter set

    Returns:
        bytes: Bit string vector
    """
    b_vector = [0] * (params.D * n1 * n2)
    for i in range(n1):
        for j in range(n2):
            for l in range(params.D):
                step = (i * n2 + j) * params.D + l
                b_vector[step] = (C_matrix[i][j] >> (params.D - 1 - l)) & 1
    return b_vector
    #raise NotImplementedError


def frodo_unpack(b_vector: bytes, n1:int, n2: int, params: FrodoParams) -> list[list[int]]:
    """Reverses the operation from Frodo.Pack

    Args:
        b_vector (bytes): _description_
        n1 (int): _description_
        n2 (int): _description_
        params (FrodoParams): FrodoKEM parameter set

    Raises:
        NotImplementedError: _description_

    Returns:
        list[list[int]]: _description_
    """
    bits = bytes_to_bits(b_vector)
    C_matrix = [[0] * n2 for _ in range(n1)]
    for i in range(n1):
        for j in range(n2):
            for l in range(params.D):
                step = (i * n2 + j) * params.D + l
                C_matrix[i][j] += bits[step] * (2 ** (params.D - 1 - l))
    return C_matrix

    #raise NotImplementedError