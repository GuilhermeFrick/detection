"""
Análise de assinatura de features por classe e comportamento UDP/TCP.

Gera:
  model/feature_signatures.json  — média/std por classe por feature
  model/transport_analysis.json  — distribuição UDP vs TCP por classe

Uso:
    python multiclass/04_analysis.py
"""
import json
import numpy as np
from pathlib import Path

DATA_DIR  = Path(__file__).parent / 'data'
MODEL_DIR = Path(__file__).parent / 'model'

CLASS_NAMES = ['Benigno', 'DoS', 'Fuzzy', 'MITM_Multi', 'MITM_Single', 'FakeClientID']
FEAT_COLS = [
    'f01_ip_time_interval', 'f08_someip_payload_change',
    'f11_ip_length_change',  'f12_tcpudp_length_change',
    'f13_payload_repeat_rate', 'f15_someip_payload_len',
    'f16_tcpudp_len', 'f17_src_packet_rate', 'f18_src_payload_diversity',
    'f19_is_sd', 'f20_src_service_diversity', 'f21_is_relay_service',
    'f22_src_clientid_diversity',
]

def main():
    print('Carregando dados de treino...')
    X = np.load(DATA_DIR / 'X_train.npy')
    y = np.load(DATA_DIR / 'y_train.npy').astype(int)
    print(f'  Shape: {X.shape}  Classes: {np.unique(y)}')

    norm = json.load(open(MODEL_DIR / 'norm_params.json'))

    # ── 1. Feature signatures (valores normalizados) ──────────────────────────
    signatures = {}
    print('\n=== Assinatura de Features por Classe (valores normalizados 0-1) ===\n')
    print(f'{"Feature":<32}', end='')
    for cls in CLASS_NAMES:
        print(f'{cls[:10]:>12}', end='')
    print()
    print('-' * (32 + 12 * len(CLASS_NAMES)))

    for j, feat in enumerate(FEAT_COLS):
        row = {}
        print(f'{feat:<32}', end='')
        for cls_id, cls_name in enumerate(CLASS_NAMES):
            mask = y == cls_id
            if mask.sum() == 0:
                row[cls_name] = {'mean': None, 'std': None}
                print(f'{"N/A":>12}', end='')
            else:
                vals = X[mask, j]
                m, s = float(vals.mean()), float(vals.std())
                row[cls_name] = {'mean': round(m, 4), 'std': round(s, 4)}
                print(f'{m:>12.4f}', end='')
        signatures[feat] = row
        print()

    # ── 2. Feature signatures (valores reais desnormalizados) ──────────────────
    print('\n=== Assinatura de Features por Classe (valores reais) ===\n')
    print(f'{"Feature":<32}', end='')
    for cls in CLASS_NAMES:
        print(f'{cls[:10]:>12}', end='')
    print()
    print('-' * (32 + 12 * len(CLASS_NAMES)))

    signatures_real = {}
    for j, feat in enumerate(FEAT_COLS):
        lo = norm[feat]['min']
        hi = norm[feat]['max']
        d  = hi - lo
        row = {}
        print(f'{feat:<32}', end='')
        for cls_id, cls_name in enumerate(CLASS_NAMES):
            mask = y == cls_id
            if mask.sum() == 0:
                row[cls_name] = {'mean': None}
                print(f'{"N/A":>12}', end='')
            else:
                vals_real = X[mask, j] * d + lo if d > 0 else np.full(mask.sum(), lo)
                m = float(vals_real.mean())
                row[cls_name] = {'mean': round(m, 4)}
                if abs(m) < 0.001:
                    print(f'{"~0":>12}', end='')
                elif m > 1000:
                    print(f'{m:>12.1f}', end='')
                elif m > 10:
                    print(f'{m:>12.2f}', end='')
                else:
                    print(f'{m:>12.4f}', end='')
        signatures_real[feat] = row
        print()

    # ── 3. Contagem e % por classe ─────────────────────────────────────────────
    print('\n=== Distribuição de Classes ===\n')
    total = len(y)
    for cls_id, cls_name in enumerate(CLASS_NAMES):
        n = int((y == cls_id).sum())
        print(f'  {cls_name:<15}: {n:>10,}  ({100*n/total:5.2f}%)')

    # ── 4. Correlação de features com cada classe (point-biserial-like) ───────
    print('\n=== Importância de Distinção (|delta médias normalizadas|) ===\n')
    print('(diferença absoluta entre média da classe e média geral)\n')
    print(f'{"Feature":<32}', end='')
    for cls in CLASS_NAMES:
        print(f'{cls[:10]:>12}', end='')
    print()
    print('-' * (32 + 12 * len(CLASS_NAMES)))

    for j, feat in enumerate(FEAT_COLS):
        global_mean = float(X[:, j].mean())
        print(f'{feat:<32}', end='')
        for cls_id in range(len(CLASS_NAMES)):
            mask = y == cls_id
            if mask.sum() == 0:
                print(f'{"N/A":>12}', end='')
            else:
                delta = abs(float(X[mask, j].mean()) - global_mean)
                print(f'{delta:>12.4f}', end='')
        print()

    out = MODEL_DIR / 'feature_signatures.json'
    with open(out, 'w') as f:
        json.dump({'normalized': signatures, 'real': signatures_real}, f, indent=2)
    print(f'\nSalvo em {out}')


if __name__ == '__main__':
    main()
