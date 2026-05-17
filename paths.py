from pathlib import Path

ROOT = Path(__file__).parent

# Dados (gitignored — ver .gitignore)
DATA         = ROOT / 'data'
PCAPS_DIR    = DATA / 'raw'            # PCAPs baixados por src/00_download.py
PARSED_CSV   = DATA / 'parsed' / 'parsed_packets.csv'   # gerado por src/01_parse.py
FEATURES_DIR = DATA / 'features'       # gerado por src/03_features.py
KIM_DIR      = DATA / 'kim'            # dataset publicado por Kim (opcional)

# Resultados (modelos treinados — pequenos o suficiente para commitar)
RESULTS_V1 = ROOT / 'results' / 'v1_kim16'
RESULTS_V2 = ROOT / 'results' / 'v2_proposed'
