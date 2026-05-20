import os
from pathlib import Path

ROOT = Path(__file__).parent

# SOMEIP_DATA_DIR permite redirecionar os dados para outro volume (ex: Google Drive no Colab).
# Se não definida, usa detection/data/ como padrão local.
DATA         = Path(os.environ['SOMEIP_DATA_DIR']) if 'SOMEIP_DATA_DIR' in os.environ else ROOT / 'data'
PCAPS_DIR    = DATA / 'raw'            # PCAPs baixados por src/00_download.py
PARSED_DIR   = DATA / 'parsed'         # um CSV por PCAP — gerado por src/01_parse.py
PARSED_CSV   = PARSED_DIR / 'parsed_packets.csv'   # CSV combinado (pipeline original Kim)
FEATURES_DIR = DATA / 'features'       # gerado por src/03_features.py
KIM_DIR      = DATA / 'kim'            # dataset publicado por Kim (opcional)

# Resultados (modelos treinados — pequenos o suficiente para commitar)
RESULTS_V1  = ROOT / 'results' / 'v1_kim16'
RESULTS_V2  = ROOT / 'results' / 'v2_proposed'
MODELS_DIR  = ROOT / 'results' / 'models'   # modelos individuais por tipo de ataque
