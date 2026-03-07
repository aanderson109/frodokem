# utils.py
# Utility functions
from frodokem.reference.params import FrodoParams
import hashlib
import numpy as np

def get_shake(params: FrodoParams):
    if params.shake_variant == 128:
        return hashlib.shake_128
    return hashlib.shake_256


def dc(c: int, params: FrodoParams) -> int:
    """Decodes an element in Z_q to a B-bit integer

    Args:
        c (int): Z_q entry treated as an integer
        params (FrodoParams): Parameter set for FrodoKEM

    Returns:
        int: Decoded integer 
    """
    decoded_c = (c * (2 ** params.B) // params.q) % (2 ** params.B)
    return decoded_c


def ec(k: int, params: FrodoParams) -> int:
    """Encodes a B-bit integer into Z_q

    Args:
        k (int): B-bit integer that needs encoding
        params (FrodoParams): Parameter set for FrodoKEM

    Returns:
        int: Integer encoded into Z_q
    """
    encoded_k = (k * params.q) // (2 ** params.B)
    return encoded_k


def bytes_to_bits(bytes_str: bytes) -> list[int]:
    """Converts a bytes object into a flat list of individual bits with LSB first.

    Args:
        bytes_str (bytes): Bytes object

    Returns:
        list[int]: Flat list of bits
    """
    # Create list to return individual bits in
    bits_list = []

    # Iterate over the bytes
    for byte in bytes_str:
        # shift bit i to position 0, mask to extract it
        for i in range(8):
            bits_list.append((byte >> i) & 1)
    return bits_list


def bits_to_bytes(bits_list: list[int]) -> bytes:
    """Converts a list of individual bits into a bytes object

    Args:
        bits (list[int]): List of bits

    Returns:
        bytes: Bytes object
    """
    bytes_str = []
    for i in range(0, len(bits_list), 8):
        byte = 0
        for j in range(8):
            byte += bits_list[i+j] * (2 ** j)    # LSB first
        bytes_str.append(byte)
    return bytes(bytes_str)