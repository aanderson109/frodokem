import cryptol
import os
from pathlib import Path



BASE_DIR = Path(__file__).parent
cryptol_spec_path = BASE_DIR / "../cryptol-specs"
proj_file = BASE_DIR / "../frodokem.cry"
os.environ['CRYPTOLPATH'] = str(cryptol_spec_path)


c = cryptol.connect(reset_server=True)
c.load_file(str(proj_file))

result = c.evaluate_expression("frodo_sample 0x0000").result()
print(f"frodo_sample 0x0000 = {result}")

result = c.evaluate_expression("frodo_sample 0x0001").result()
print(f"frodo_sample 0x0001 = {result}")

result = c.evaluate_expression("frodo_sample 0xFFFF").result()
print(f"frodo_sample 0xFFFF = {result}")

