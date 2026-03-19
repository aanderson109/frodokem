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

def cryptol_api_eval(proj_file: Path, kat_entry: KATEntry) -> bool:
    BASE_DIR = Path(__file__).parent
    cryptol_spec_path = BASE_DIR / "../cryptol-specs"
    proj_file = BASE_DIR / "../frodokem.cry"
    os.environ['CRYPTOLPATH'] = str(cryptol_spec_path)


    c = cryptol.connect(reset_server=True)
    c.load_file(str(proj_file))

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

def run_all_kats(kat_file: str) -> dict:
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
        print(f"Testing count={entry.count}")
        print(f"{'='*50}")
        result = cryptol_api_eval(proj_dir, entry)
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

def main():
    KAT_FILE = "newer_PQCkemKAT_43088.rsp"
    base_dir, kat_dir, proj_dir = get_dirs(KAT_FILE)
    entries = parse_kats(kat_dir)
    entry = entries[0]  # tests count=0

    print("running single KAT test (count=0)...")
    kat_test = cryptol_api_eval(proj_dir, entry)
    if kat_test:
        print(f"Shared secrets matched!")
    else:
        print(f"Shared secrets did not match -- check debugging values")

    # uncomment to run all KAT entries (very slow!)
    # print("\nRunning all KAT tests...")
    # results = run_all_kats(KAT_FILE)

if __name__=="__main__":
    main()