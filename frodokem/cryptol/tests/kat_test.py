from dataclasses import dataclass
import subprocess
from pathlib import Path
import cryptol
import os
import time


@dataclass
class KATEntry:
    count: int
    seed: str
    pk: str
    sk: str
    ct: str
    ss: str

def get_dirs(kat_file: str) -> tuple[Path, Path, Path]:
    """Establishes relative directories for the NIST
    KAT file and `frodokem.cry` specification.

    Args:
        kat_file (str): Name of KAT file for testing

    Returns:
        tuple[Path, Path, Path]: Paths to base directory, kat file, and project
    """
    BASE_DIR = Path(__file__).parent
    KAT_FILENAME = BASE_DIR / "kat" / f"{kat_file}"
    PROJ_PATH = BASE_DIR / "../frodokem.cry"

    return BASE_DIR, KAT_FILENAME, PROJ_PATH

def parse_kats(kat_file: Path) -> list[KATEntry]:
    """Parses the provided KAT file, returning the
    count, seed, public key (pk), secret key (sk),
    ciphertext (ct), and shared secret (ss) as a
    list of attributes from the KATEntry dataclass.

    Args:
        kat_file (Path): Path to KAT file

    Returns:
        list[KATEntry]: Dataclass with values from file inserted
    """
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

def cryptol_api_eval(c: cryptol.CryptolConnection, proj_file: Path, kat_entry: KATEntry) -> bool:
    BASE_DIR = Path(__file__).parent

    # step 1: validate frodo_gen_aes with known seed from KAT
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

    start = time.time()
    # step 3: full decaps
    result = c.evaluate_expression(
        f"frodo_decaps (split`{{21696}} 0x{kat_entry.ct}) (split`{{43088}} 0x{kat_entry.sk})"
    ).result()
    elapsed = time.time() - start
    print(f"Decaps took: {elapsed:.1f} seconds")
    got_hex = ''.join(f'{int(bv):02x}' for bv in result)
    print(f"Expected ss: {kat_entry.ss.lower()}")
    print(f"Got ss:      {got_hex}")
    print(f"Match:       {got_hex == kat_entry.ss.lower()}")

    if got_hex == kat_entry.ss.lower():
        return True

    print(f"Debugging with intermediate values...\n\n")

    # step 3a: check a few decaps intermediates
    # extract seed_A and ST from sk
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

    # Sanity check on frodo_decode against known reference M[0][0] = 0xf0ad
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
    print(f"Cryptol ST[0][0]: {result}")

    result2 = c.evaluate_expression(
        f"(decode_ST`{{8, 1344}} (split`{{21504}} 0x{st_hex})) @ 0 @ 1"
    ).result()
    print(f"Cryptol ST[0][1]: {result2}")

    return False

def run_all_kats(c: cryptol.CryptolConnection, kat_file: str) -> dict:
    """Runs the KAT test for all entries in the KAT file.

    Args:
        kat_file (str): Name of KAT file for testing

    Returns:
        dict: Results summary with pass /fail counts
    """
    base_dir, kat_dir, proj_dir = get_dirs(kat_file)
    entries = parse_kats(kat_dir)

    passed = 0
    failed = 0
    failed_counts = []

    for entry in entries:
        print(f"\n{'='*50}")
        print(f"Testing count={entry.count}", flush=True)
        print(f"{'='*50}")
        result = cryptol_api_eval(c, proj_dir, entry)
        if result:
            passed += 1
            print(f"count={entry.count}: PASS")
        else:
            failed += 1
            failed_counts.append(entry.count)
            print(f"count={entry.count}: FAIL")
    
    print(f"\n{'='*50}")
    print(f"Results: {passed}/{passed+failed} passed")
    if failed_counts:
        print(f"Failed counts: {failed_counts}")
    
    results_dict = {"passed": passed, "failed": failed, "failed_counts": failed_counts}
    return results_dict

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

# Used to debug C implementation
def debug_keygen_intermediates(c, randomness_hex: str):
    """Print KeyGen intermediates from Cryptol given raw randomness bytes."""
    
    # parse randomness into s, seed_se, z
    sec_bytes = 32
    se_bytes = 64
    seed_a_bytes = 16
    
    s_hex = randomness_hex[:sec_bytes*2]
    seed_se_hex = randomness_hex[sec_bytes*2:(sec_bytes+se_bytes)*2]
    z_hex = randomness_hex[(sec_bytes+se_bytes)*2:]
    
    print(f"s:       {s_hex[:32]}...")
    print(f"seed_se: {seed_se_hex[:32]}...")
    print(f"z:       {z_hex}")

    # seed_A = SHAKE256(z)
    result = c.evaluate_expression(
        f"take`{{128}} (shake256 (0x{z_hex} : ZSeed))"
    ).result()
    seed_a = f'{int(result):032x}'
    print(f"seed_A: {seed_a}")

    # r stream = SHAKE256(0x5F || seed_se)
    # first r_words
    result = c.evaluate_expression(
        f"""take`{{5}} [ le16 w | w <- split`{{2*n*nbar}} (take`{{2*n*nbar*16}} (shake256 ((0x5f : Byte) # (0x{seed_se_hex} : SeedSE)))) : [2*n*nbar][16] ]"""
    ).result()
    print(f"r_words[0..4]: {result}")

    result = c.evaluate_expression(
        f"frodo_sample_matrix`{{nbar,n}} (take`{{n*nbar}} [ le16 w | w <- split`{{2*n*nbar}} (take`{{2*n*nbar*16}} (shake256 ((0x5f : Byte) # (0x{seed_se_hex} : SeedSE)))) : [2*n*nbar][16] ])"
    ).result()
    print(f"ST[0][0..3]: {[result[0][i] for i in range(4)]}")

    result2 = c.evaluate_expression(
        f"frodo_sample_matrix`{{n,nbar}} (drop`{{n*nbar}} [ le16 w | w <- split`{{2*n*nbar}} (take`{{2*n*nbar*16}} (shake256 ((0x5f : Byte) # (0x{seed_se_hex} : SeedSE)))) : [2*n*nbar][16] ])"
    ).result()
    print(f"E[0][0..3]: {[result2[0][i] for i in range(4)]}")


def main():
    KAT_FILE = "newer_PQCkemKAT_43088.rsp"
    base_dir, kat_dir, proj_dir = get_dirs(KAT_FILE)
    entries = parse_kats(kat_dir)

    # connect once
    cryptol_spec_path = base_dir / "../cryptol-specs"
    proj_file = base_dir / "../frodokem.cry"
    os.environ['CRYPTOLPATH'] = str(cryptol_spec_path)
    c = cryptol.connect(reset_server=True)
    c.load_file(str(proj_file))

    # hex string from C implementation to debug output
    keygen_randomness = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2DB505D7CFAD1B497499323C8686325E4792F267AAFA3F87CA60D01CB54F29202A3E784CCB7EBCDCFD45542B7F6AF778742E0F4479175084AA488B3B74340678AA38E22E9628B0A161FDEB0BD252173B9C"
    debug_keygen_intermediates(c, keygen_randomness)

    # uncomment to run all KAT entries (very slow!)
    #print("\nRunning all KAT tests...")
    #results = run_all_kats(c, KAT_FILE)

if __name__=="__main__":
    main()