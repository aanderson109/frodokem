import subprocess

def cryptol_eval(proj_cry_path, proj_function, ct, sk, ss):
    cryptol_input = f"""
    :load {proj_cry_path}
    :eval {proj_function} 0x{ct} 0x{sk}
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


def parse_kats(kat_file) -> list:
    entries = []
    current = {}
    with open(kat_file) as f:
        for line in f:
            line = line.strip()
            if '=' in line:
                key, val = line.split(' = ')
                current[key.strip()] = val.strip()
            elif line == '' and current:
                entries.append(current)
                current = {}
    return entries


def main():
    KAT_FILENAME = "PQCkemKAT_43088.rsp"
    entries = parse_kats(KAT_FILENAME)
    entry = entries[0]  # tests count=0

    ct = entry['ct']
    sk = entry['sk']
    ss = entry['ss']

    PROJ_PATH = "../frodokem.cry"
    PROJ_FUNC = "frodo_decaps"

    cryptol_eval(PROJ_PATH, PROJ_FUNC, ct, sk, ss)


if __name__=="__main__":
    main()