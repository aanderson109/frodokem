# matrix.py
from frodokem.reference.params import FrodoParams
from frodokem.reference.utils import bytes_to_bits
from Crypto.Cipher import AES

def aes_prf(key: bytes, input_block: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(input_block)


def frodo_sample(rand_bit_string: bytes, params: FrodoParams) -> int:
    bits = bytes_to_bits(rand_bit_string)
    t : int = 0
    for i in range(1, params.length_CHI):
        t += bits[i] * (2 ** (i - 1))
    e : int = 0
    for z in range(params.s):
        if t > params.cdf_table[z]:
            e += 1
    e = ((-1) ** bits[0]) * e
    return e


def frodo_sample_matrix(rand_bit_string: bytes, n1: int, n2: int, params: FrodoParams) -> list[list[int]]:
    bits = bytes_to_bits(rand_bit_string)
    E_matrix = [[0] * n2 for _ in range(n1)]
    for i in range(n1):
        for j in range(n2):
            step = (i * n2 + j) * params.length_CHI
            r = bits[step : step + params.length_CHI]
            E_matrix[i][j] = frodo_sample(bytes(r), params)
    return E_matrix


def frodo_gen_AES128(seed_A: bytes, params: FrodoParams) -> list[list[int]]:
    A_matrix = [[0] * params.n for _ in range(params.n)]
    cipher = AES.new(seed_A, AES.MODE_ECB)
    for i in range(params.n):
        for j in range(0, params.n, 8):
            b = i.to_bytes(2, 'little') + j.to_bytes(2, 'little') + bytes(12)
            c = cipher.encrypt(b)
            for k in range(8):
                value = int.from_bytes(c[2*k : 2*k+2], 'little')
                A_matrix[i][j+k] = value % params.q
    return A_matrix


#def frodo_gen_SHAKE128():
#    raise NotImplementedError