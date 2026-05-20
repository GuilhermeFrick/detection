"""
Extracao de features para classificador multi-classe SOME/IP.

Combina todos os PCAPs em um unico dataset com 5 classes:
    0 = Benigno       (benign_traffic.csv — todos os pacotes)
    1 = DoS           (dos_noti_flood.csv — apenas label=1)
    2 = Fuzzy         (fuzzy_sd_offer_rand_noti{1,2,3}.csv — apenas label=1)
    3 = MITM_Multi    (mitm_multi_attacker.csv — apenas label=1)
    4 = MITM_Single   (mitm_single_attacker.csv — apenas label=1)

12 features (superconjunto de todos os classificadores individuais):
    f01-f19 compartilhadas + f20 src_service_diversity + f21 is_relay_service

Saida:
    multiclass/data/features.csv
    multiclass/data/X_train.npy  y_train.npy
    multiclass/data/X_test.npy   y_test.npy
    multiclass/data/class_counts.json

Uso:
    python multiclass/01_features.py
"""
import sys, time, json
import numpy as np
import pandas as pd
from pathlib import Path
from collections import defaultdict, deque
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).parent.parent))
from paths import PARSED_DIR

OUT_DIR    = Path(__file__).parent / 'data'
OUT_DIR.mkdir(exist_ok=True)

CHUNK      = 500_000
RAND_STATE = 42
RELAY_SVC  = 0x100B

CLASS_NAMES = {0: 'Benigno', 1: 'DoS', 2: 'Fuzzy', 3: 'MITM_Multi', 4: 'MITM_Single'}

FEAT_COLS = [
    'f01_ip_time_interval',
    'f08_someip_payload_change',
    'f11_ip_length_change',
    'f12_tcpudp_length_change',
    'f13_payload_repeat_rate',
    'f15_someip_payload_len',
    'f16_tcpudp_len',
    'f17_src_packet_rate',
    'f18_src_payload_diversity',
    'f19_is_sd',
    'f20_src_service_diversity',
    'f21_is_relay_service',
]

# (csv_name, multiclass_label, keep_only_attack)
SOURCES = [
    ('benign_traffic.csv',          0, False),  # todos os pacotes -> benigno
    ('dos_noti_flood.csv',          1, True),   # so label=1 -> DoS
    ('fuzzy_sd_offer_rand_noti1.csv', 2, True),
    ('fuzzy_sd_offer_rand_noti2.csv', 2, True),
    ('fuzzy_sd_offer_rand_noti3.csv', 2, True),
    ('mitm_multi_attacker.csv',     3, True),
    ('mitm_single_attacker.csv',    4, True),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_state():
    return {
        'prev_ts':         defaultdict(lambda: None),
        'prev_ip_len':     defaultdict(lambda: None),
        'prev_tl_len':     defaultdict(lambda: None),
        'prev_si_pld':     defaultdict(lambda: None),
        'recent_payloads': defaultdict(lambda: deque(maxlen=5)),
        'src_timestamps':  defaultdict(lambda: deque(maxlen=1000)),
        'src_payloads':    defaultdict(lambda: deque(maxlen=1000)),
        'src_services':    defaultdict(lambda: deque(maxlen=100)),
    }


def _hamming(hex_a, hex_b) -> float:
    if not isinstance(hex_a, str) or not isinstance(hex_b, str):
        return 0.0
    try:
        a = bytes.fromhex(hex_a); b = bytes.fromhex(hex_b)
    except ValueError:
        return 0.0
    L = min(len(a), len(b))
    if L == 0:
        return 0.0
    return float(np.unpackbits(
        np.bitwise_xor(np.frombuffer(a[:L], dtype=np.uint8),
                       np.frombuffer(b[:L], dtype=np.uint8))
    ).sum()) / (8 * L)


def extract(df: pd.DataFrame, state: dict, mc_label: int, keep_only_attack: bool) -> pd.DataFrame:
    df = df.sort_values(['pcap_file', 'timestamp']).reset_index(drop=True)
    n  = len(df)

    ts_v  = df['timestamp'].values
    ip_v  = pd.to_numeric(df['ip_len'],        errors='coerce').values
    tl_v  = pd.to_numeric(df['transport_len'], errors='coerce').values
    si_v  = df['someip_payload_hex'].fillna('').values
    src_v = df['src_ip'].astype(str).values
    dst_v = df['dst_ip'].astype(str).values
    sport = df['src_port'].astype(str).values
    dport = df['dst_port'].astype(str).values
    trans = df['transport'].astype(str).values
    pcap  = df['pcap_file'].astype(str).values
    svc_v = pd.to_numeric(df['service_id'], errors='coerce').values
    orig_label = df['label'].values if 'label' in df.columns else np.zeros(n, dtype=int)

    if 'is_sd' in df.columns:
        is_sd_v = df['is_sd'].fillna(False).astype(bool).astype(float).values
    else:
        is_sd_v = np.zeros(n)

    f01 = np.zeros(n); f08 = np.zeros(n); f11 = np.zeros(n)
    f12 = np.zeros(n); f13 = np.zeros(n); f17 = np.zeros(n)
    f18 = np.zeros(n); f20 = np.ones(n);  f21 = np.zeros(n)

    f15 = pd.to_numeric(df['someip_payload_len'], errors='coerce').fillna(0).values.astype(float)
    f16 = pd.to_numeric(df['transport_len'],       errors='coerce').fillna(0).values.astype(float)

    for i in range(n):
        if not np.isnan(svc_v[i]) and int(svc_v[i]) == RELAY_SVC:
            f21[i] = 1.0

    for i in range(n):
        key  = (pcap[i], src_v[i], dst_v[i], sport[i], dport[i], trans[i])
        ts   = float(ts_v[i])
        ip_l = float(ip_v[i]) if not np.isnan(ip_v[i]) else None
        tl_l = float(tl_v[i]) if not np.isnan(tl_v[i]) else None
        si_h = si_v[i] if si_v[i] else None
        src  = src_v[i]
        svc  = int(svc_v[i]) if not np.isnan(svc_v[i]) else None

        prev_ts = state['prev_ts'][key]
        f01[i]  = abs(ts - prev_ts) if prev_ts is not None else 0.0
        f08[i]  = _hamming(state['prev_si_pld'][key], si_h)

        p_ip = state['prev_ip_len'][key]
        p_tl = state['prev_tl_len'][key]
        f11[i] = abs(ip_l - p_ip) if (p_ip is not None and ip_l is not None) else 0.0
        f12[i] = abs(tl_l - p_tl) if (p_tl is not None and tl_l is not None) else 0.0

        hist   = state['recent_payloads'][key]
        f13[i] = sum(1 for p in hist if p == si_h) / len(hist) if (hist and si_h) else 0.0
        hist.append(si_h)

        win_t = state['src_timestamps'][src]
        win_t.append(ts)
        if len(win_t) >= 2:
            delta = ts - win_t[0]
            f17[i] = (len(win_t) - 1) / delta if delta > 0 else float(len(win_t))

        win_p = state['src_payloads'][src]
        if si_h:
            win_p.append(si_h)
        f18[i] = len(set(win_p)) / len(win_p) if len(win_p) > 1 else 0.0

        win_s = state['src_services'][src]
        if svc is not None:
            win_s.append(svc)
        f20[i] = float(len(set(win_s))) if len(win_s) > 0 else 1.0

        state['prev_ts'][key]     = ts
        state['prev_ip_len'][key] = ip_l
        state['prev_tl_len'][key] = tl_l
        state['prev_si_pld'][key] = si_h

    # Atribuir label multi-classe
    if keep_only_attack:
        mc_labels = np.where(orig_label == 1, mc_label, -1)
    else:
        mc_labels = np.full(n, mc_label, dtype=int)

    out = pd.DataFrame({
        'f01_ip_time_interval':     f01,
        'f08_someip_payload_change':f08,
        'f11_ip_length_change':     f11,
        'f12_tcpudp_length_change': f12,
        'f13_payload_repeat_rate':  f13,
        'f15_someip_payload_len':   f15,
        'f16_tcpudp_len':           f16,
        'f17_src_packet_rate':      f17,
        'f18_src_payload_diversity':f18,
        'f19_is_sd':                is_sd_v,
        'f20_src_service_diversity':f20,
        'f21_is_relay_service':     f21,
        'label': mc_labels,
    })

    # Remover pacotes benigno dos CSVs de ataque (label=-1)
    return out[out['label'] >= 0].reset_index(drop=True)


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    FEAT_CSV = OUT_DIR / 'features.csv'

    for csv_name, _, _ in SOURCES:
        p = PARSED_DIR / csv_name
        if not p.exists():
            raise FileNotFoundError(f'{p} nao encontrado -- rode o parser primeiro.')

    if FEAT_CSV.exists():
        print(f'[OK] {FEAT_CSV} ja existe -- apague para re-extrair.')
    else:
        state   = make_state()
        first   = True
        n_total = 0
        t0      = time.time()

        for csv_name, mc_label, keep_only_attack in SOURCES:
            csv_path = PARSED_DIR / csv_name
            print(f'\nLendo {csv_name}  (classe={mc_label} {CLASS_NAMES[mc_label]}, '
                  f'so_ataque={keep_only_attack})...')
            for chunk in pd.read_csv(csv_path, chunksize=CHUNK, low_memory=False):
                out = extract(chunk, state, mc_label, keep_only_attack)
                out.to_csv(FEAT_CSV, mode='a', header=first, index=False)
                first    = False
                n_total += len(out)
                print(f'  {n_total:,} linhas  ({time.time()-t0:.0f}s)')

        print(f'\nConcluido: {n_total:,} amostras -> {FEAT_CSV}')

    # Estatisticas
    print('\nDistribuicao do dataset:')
    labels = pd.concat(
        c['label'] for c in pd.read_csv(FEAT_CSV, usecols=['label'], chunksize=CHUNK)
    ).values
    counts = {}
    for lbl, name in CLASS_NAMES.items():
        n = (labels == lbl).sum()
        counts[name] = int(n)
        print(f'  {name:<15}: {n:>10,}  ({100*n/len(labels):.1f}%)')

    with open(OUT_DIR / 'class_counts.json', 'w') as f:
        json.dump(counts, f, indent=2)

    print('\nMin/Max por feature:')
    stats = {c: {'min': float('inf'), 'max': float('-inf')} for c in FEAT_COLS}
    for chunk in pd.read_csv(FEAT_CSV, usecols=FEAT_COLS, chunksize=CHUNK):
        for c in FEAT_COLS:
            stats[c]['min'] = min(stats[c]['min'], chunk[c].min())
            stats[c]['max'] = max(stats[c]['max'], chunk[c].max())
    for c in FEAT_COLS:
        print(f'  {c:<32}  min={stats[c]["min"]:>12.4f}  max={stats[c]["max"]:>12.4f}')

    # Split e export
    print('\nSplit treino/teste (50/50 estratificado)...')
    idx = np.arange(len(labels))
    train_idx, test_idx = train_test_split(
        idx, test_size=0.5, stratify=labels, random_state=RAND_STATE
    )
    is_train = np.zeros(len(labels), dtype=bool)
    is_train[train_idx] = True

    norm = {}
    for chunk in pd.read_csv(FEAT_CSV, usecols=FEAT_COLS, chunksize=CHUNK):
        for c in FEAT_COLS:
            lo = chunk[c].min(); hi = chunk[c].max()
            norm[c] = {'min': min(norm.get(c, {}).get('min', lo), lo),
                       'max': max(norm.get(c, {}).get('max', hi), hi)}

    import json as _json
    MODEL_DIR = Path(__file__).parent / 'model'
    MODEL_DIR.mkdir(exist_ok=True)
    with open(MODEL_DIR / 'norm_params.json', 'w') as f:
        _json.dump(norm, f, indent=2)

    def export(split_name, mask):
        xc, yc = [], []
        for chunk in pd.read_csv(FEAT_CSV, chunksize=CHUNK):
            x = chunk[FEAT_COLS].values.astype(np.float32)
            for j, c in enumerate(FEAT_COLS):
                lo = norm[c]['min']; hi = norm[c]['max']; d = hi - lo
                x[:, j] = np.clip((x[:, j] - lo) / d, 0, 1) if d > 0 else 0.0
            xc.append(x[mask[:len(x)]])
            yc.append(chunk['label'].values.astype(np.int8)[mask[:len(x)]])
            mask = mask[len(x):]
        X = np.vstack(xc); y = np.concatenate(yc)
        np.save(OUT_DIR / f'X_{split_name}.npy', X)
        np.save(OUT_DIR / f'y_{split_name}.npy', y)
        print(f'  {split_name}: {X.shape}')
        for lbl, name in CLASS_NAMES.items():
            print(f'    {name:<15}: {(y==lbl).sum():>8,}')

    export('train', is_train.copy())
    export('test',  ~is_train)
    print(f'\nArquivos salvos em {OUT_DIR}')
