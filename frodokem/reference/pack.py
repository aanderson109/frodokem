# pack.py
# Includes Frodo.Pack, Frodo.Unpack
from frodokem.reference.params import FrodoParams

def frodo_pack(C_matrix: list[list[int]], n1: int, n2: int, params: FrodoParams) -> bytes:
    """Packs a matrix into a bit string by concatenating the D-bit matrix coefficients

    Args:
        C_matrix (list[list[int]]): Matrix to be packed
        params (params.FrodoParams): FrodoKEM parameter set

    Returns:
        bytes: Bit string vector
    """
    raise NotImplementedError


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
    raise NotImplementedError