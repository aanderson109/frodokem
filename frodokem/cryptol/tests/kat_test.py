from dataclasses import dataclass
import subprocess
from pathlib import Path
import cryptol
import os


@dataclass
class KATEntry:
    count: int
    seed: str
    pk: str
    sk: str
    ct: str
    ss: str

def get_dirs(kat_file):
    BASE_DIR = Path(__file__).parent
    KAT_FILENAME = BASE_DIR / "kat" / f"{kat_file}"
    PROJ_PATH = BASE_DIR / "../frodokem.cry"

    return BASE_DIR, KAT_FILENAME, PROJ_PATH

def parse_kats(kat_file) -> list[KATEntry]:
    entries = []
    current = {}
    with open(kat_file) as f:
        for line in f:
            line = line.strip()
            if '=' in line:
                key, val = line.split(' = ', 1)
                current[key.strip()] = val.strip()
            elif line == '' and current:
                entries.append(KATEntry(
                    count = int(current['count']),
                    seed = current['seed'],
                    pk = current['pk'],
                    sk = current['sk'],
                    ct = current['ct'],
                    ss = current['ss']
                ))
                current = {}
    return entries


def cryptol_eval(proj_cry_path, proj_function, ct, sk, ss):
    print(f"ct bytes: {len(ct)//2}")
    print(f"sk bytes: {len(sk)//2}")
    print(f"ss bytes: {len(ss)//2}")

    cryptol_input = f"""\
:load {proj_cry_path}
:prove {proj_function} (split`{{21696}} 0x{ct}) (split`{{43088}} 0x{sk}) == split`{{32}} 0x{ss}
"""

    result = subprocess.run(
        ["cryptol"],
        input=cryptol_input,
        capture_output=True,
        text=True
    )

    print(result.stdout)
    expected = f"0x{ss.lower()}"
    print(f"Expected: {expected}")
    print(f"Match: {expected in result.stdout}")

def cryptol_api_eval(proj_file, kat_entry):
    BASE_DIR = Path(__file__).parent
    cryptol_spec_path = BASE_DIR / "../cryptol-specs"
    proj_file = BASE_DIR / "../frodokem.cry"
    os.environ['CRYPTOLPATH'] = str(cryptol_spec_path)


    c = cryptol.connect(reset_server=True)
    c.load_file(str(proj_file))

    # step 1: validate frodo_gen_aes with known seed from KAT
    # extract seed_A from pk (first 128 bits/16 bytes/32 hex chars)
    seed_a = kat_entry.pk[:32]
    result = c.evaluate_expression(
        f"(frodo_gen_aes (0x{seed_a} : SeedA)) @ 0 @ 0"
    ).result()
    print(f"A[0][0] with KAT Seed_A: {result}")

    # step 2: validate pk parsing - unpack the public matrix from pk
    # pk = seed_A (16 bytes) || packed_b (n*nbar*D/8 bytes)
    packed_b = kat_entry.pk[32:]
    result = c.evaluate_expression(
        f"(frodo_unpack`{{n, nbar}} (split`{{PackBytes n nbar}} 0x{packed_b})) @ 0 @ 0"
    ).result()
    print(f"B[0][0] from KAT pk: {result}")

    # step 3: full decaps
    result = c.evaluate_expression(
        f"frodo_decaps (split`{{21696}} 0x{kat_entry.ct}) (split`{{43088}} 0x{kat_entry.sk})"
    ).result()
    got_hex = ''.join(f'{int(bv):02x}' for bv in result)
    print(f"Expected ss: {kat_entry.ss.lower()}")
    print(f"Got ss:      {got_hex}")
    print(f"Match:       {got_hex == kat_entry.ss.lower()}")

    # step 3a: check a few decaps intermediates
    # extract seed_A and ST from sk
    s_bytes = kat_entry.sk[:64]
    seed_a_sk = kat_entry.sk[64:96]
    print(f"Seed A from sk matches pk: {seed_a_sk == kat_entry.pk[:32]}")

    # check c1 unpack - first mbar*n*D/8 bytes of ct
    c1_hex = kat_entry.ct[:43008]
    result = c.evaluate_expression(
        f"(frodo_unpack`{{8,1344}} (split`{{21504}} 0x{c1_hex})) @ 0 @ 0"
    ).result()
    print(f"B'[0][0] from ct: {result}")

    # need to evaluate M = C - B'S in cryptol
    c2_hex = kat_entry.ct[43008:43008+256]
    result = c.evaluate_expression(
        f"(frodo_unpack`{{8,8}} (split`{{128}} 0x{c2_hex})) @ 0 @ 0"
    ).result()
    print(f"C[0][0] from ct: {result}")

    # Checking M[0][0] by checking mu'
    result = c.evaluate_expression(
        f"frodo_decode (groupBy`{{8}} (groupBy`{{16}} (0x{'f0ad'+'0000'*63} : [1024])))"
    ).result()
    print(f"frodo_decode of reference M[0][0]: {result}")

    # extract ST from sk
    st_start = 64 + 32 + 43008
    st_end = st_start + 43008
    st_hex = kat_entry.sk[st_start:st_end]
    result = c.evaluate_expression(
        f"(decode_ST`{{8, 1344}} (split`{{21504}} 0x{st_hex})) @ 0 @ 0"
    ).result()
    print(f"Cryptol ST[0][1]: {result}")

    result2 = c.evaluate_expression(
        f"(decode_ST`{{8, 1344}} (split`{{21504}} 0x{st_hex})) @ 0 @ 1"
    ).result()
    print(f"Cryptol ST[0][1]: {result2}")

    #print(f"shake256(seed_A): {int(result):064x}")

    # test with known simple input
    #result2 = c.evaluate_expression(
    #    f"shake256 (0x00 : [8])"
    #).result()
    #print(f"shake256(0x00): {int(result2):064x}")



    # check mu'
    #pk_hex = kat_entry.pk
    #result = c.evaluate_expression(
    #    f"shake256 (join (split`{{21520}} 0x{pk_hex} : [21520][8]))"
    #).result()
    #pkh_cryptol = f'{int(result):064x}'
    #print(f"Cryptol pkh: {pkh_cryptol}")

    

    #result = c.evaluate_expression("frodo_sample 0x0000").result()
    #print(f"frodo_sample 0x0000 = {result}")

    #result = c.evaluate_expression("frodo_sample 0x0001").result()
    #print(f"frodo_sample 0x0001 = {result}")

    #result = c.evaluate_expression("frodo_sample 0xFFFF").result()
    #print(f"frodo_sample 0xFFFF = {result}")

    #result = c.evaluate_expression(
    #    f"frodo_decaps ( ( (split`{{21696}} 0x{ct}) : [21696][8])) (((split`{{43088}} 0x{sk}) : [43088][8]))"
    #).result()
    #print(type(result[0]))
    #print(dir(result[0]))
    #got_hex = ''.join(f'{int(bv):02x}' for bv in result)
    #print(f"Expected: {ss.lower()}")
    #print(f"Got: {got_hex}")
    #print(f"Match: {got_hex == ss.lower()}")

def debug_entry(entry: KATEntry):
    print("count:", entry.count)
    print("seed len bytes:", len(entry.seed) // 2)
    print("pk len bytes:", len(entry.pk) // 2)
    print("sk len bytes:", len(entry.sk) // 2)
    print("ct len bytes:", len(entry.ct) // 2)
    print("ss len bytes:", len(entry.ss) // 2)
    print("seed len bytes:", len(entry.seed) // 2)

    print("seed prefix:", entry.seed[:32])
    print("pk prefix:", entry.pk[:32])
    print("sk prefix:", entry.sk[:32])
    print("ct prefix:", entry.ct[:32])
    print("ss prefix:", entry.ss[:32])




def main():
    KAT_FILE = "newer_PQCkemKAT_43088.rsp"
    base_dir, kat_dir, proj_dir = get_dirs(KAT_FILE)
    entries = parse_kats(kat_dir)
    entry = entries[0]  # tests count=0
    #debug_entry(entry)

    PROJ_PATH = proj_dir
    PROJ_FUNC = "frodo_decaps"

    #cryptol_eval(PROJ_PATH, PROJ_FUNC, entry.ct, entry.sk, entry.ss)

    #cryptol_api_eval(PROJ_PATH, entry.ct, entry.sk, entry.ss)

    cryptol_api_eval(PROJ_PATH, entry)

if __name__=="__main__":
    main()