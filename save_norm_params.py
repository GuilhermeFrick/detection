"""
Salva parametros de normalizacao (min/max por feature) para cada classificador.
Le os features.csv ja gerados e salva norm_params.json no model/ de cada um.

Uso:
    python save_norm_params.py
"""
import json
import numpy as np
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).parent

CLASSIFIERS = {
    'dos': {
        'features_csv': ROOT / 'dos' / 'data' / 'features.csv',
        'model_dir':    ROOT / 'dos' / 'model',
        'feat_cols': [
            'f01_ip_time_interval', 'f08_someip_payload_change',
            'f11_ip_length_change', 'f12_tcpudp_length_change',
            'f13_payload_repeat_rate', 'f15_someip_payload_len',
            'f16_tcpudp_len', 'f17_src_packet_rate', 'f18_src_payload_diversity',
        ],
    },
    'fuzzy': {
        'features_csv': ROOT / 'fuzzy' / 'data' / 'features.csv',
        'model_dir':    ROOT / 'fuzzy' / 'model',
        'feat_cols': [
            'f01_ip_time_interval', 'f08_someip_payload_change',
            'f11_ip_length_change', 'f12_tcpudp_length_change',
            'f13_payload_repeat_rate', 'f15_someip_payload_len',
            'f16_tcpudp_len', 'f17_src_packet_rate', 'f18_src_payload_diversity',
            'f19_is_sd',
        ],
    },
    'mitm': {
        'features_csv': ROOT / 'mitm' / 'data' / 'features.csv',
        'model_dir':    ROOT / 'mitm' / 'model',
        'feat_cols': [
            'f01_ip_time_interval', 'f08_someip_payload_change',
            'f11_ip_length_change', 'f12_tcpudp_length_change',
            'f13_payload_repeat_rate', 'f15_someip_payload_len',
            'f16_tcpudp_len', 'f17_src_packet_rate', 'f18_src_payload_diversity',
            'f19_is_sd', 'f20_src_service_diversity', 'f21_is_relay_service',
        ],
    },
    'mitm_single': {
        'features_csv': ROOT / 'mitm_single' / 'data' / 'features.csv',
        'model_dir':    ROOT / 'mitm_single' / 'model',
        'feat_cols': [
            'f01_ip_time_interval', 'f08_someip_payload_change',
            'f11_ip_length_change', 'f12_tcpudp_length_change',
            'f13_payload_repeat_rate', 'f15_someip_payload_len',
            'f16_tcpudp_len', 'f17_src_packet_rate', 'f18_src_payload_diversity',
            'f19_is_sd', 'f20_src_service_diversity', 'f21_is_relay_service',
        ],
    },
}

CHUNK = 500_000

for name, cfg in CLASSIFIERS.items():
    print(f'[{name}] lendo {cfg["features_csv"].name}...')
    feat_cols = cfg['feat_cols']
    norm = {c: {'min': float('inf'), 'max': float('-inf')} for c in feat_cols}

    for chunk in pd.read_csv(cfg['features_csv'], usecols=feat_cols, chunksize=CHUNK):
        for c in feat_cols:
            norm[c]['min'] = min(norm[c]['min'], float(chunk[c].min()))
            norm[c]['max'] = max(norm[c]['max'], float(chunk[c].max()))

    out = cfg['model_dir'] / 'norm_params.json'
    with open(out, 'w') as f:
        json.dump(norm, f, indent=2)
    print(f'  -> {out}')
    for c in feat_cols:
        print(f'     {c:<32}  [{norm[c]["min"]:>10.4f}, {norm[c]["max"]:>10.4f}]')
    print()

print('Concluido.')
