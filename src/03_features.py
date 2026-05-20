"""
Pipeline de extração de features — versão proposta (além de Kim et al. 2026).

Features f01–f16: reprodução de Kim com correções documentadas.
Features f17–f18: novas — baseadas em taxa e diversidade por src_ip (janela deslizante).

Uso:
    python src/03_features.py

Saída (em FEATURES_DIR):
    all_features_raw.csv
    train_features.csv / test_features.csv
    X_train.npy, X_test.npy, y_train.npy, y_test.npy
"""
import sys, time, gc
import numpy as np
import pandas as pd
from pathlib import Path
from collections import defaultdict, deque
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).parent.parent))
from paths import PARSED_CSV, FEATURES_DIR
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location('byte_model', Path(__file__).parent / '02_byte_model.py')
_mod  = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_mod)
ByteDistributionModel = _mod.ByteDistributionModel
hamming_distance      = _mod.hamming_distance

FEATURES_DIR.mkdir(exist_ok=True)

CHUNK      = 500_000
N_SAMPLES  = 50_000
RAND_STATE = 42

# ── Colunas de feature (ordem fixa → índice no array numpy) ──────────────────
FEAT_COLS = [
    # f01-f12: reprodução Kim
    'f01_ip_time_interval',
    'f02_someip_likelihood',
    'f03_someipsd_likelihood',
    'f04_tcpudp_likelihood',
    'f05_someip_entropy',
    'f06_someipsd_entropy',
    'f07_tcpudp_entropy',
    'f08_someip_payload_changes',
    'f09_someipsd_payload_changes',
    'f10_tcpudp_payload_changes',
    'f11_ip_length_changes',
    'f12_tcpudp_length_changes',
    # f13-f16: extensões v1
    'f13_payload_repeat_rate',      # fração dos últimos 5 payloads idênticos ao atual
    'f14_duplicate_source',         # mesmo payload visto de src_ip diferente (cross-PCAP)
    'f15_someip_payload_length',    # comprimento real do payload SOME/IP (não truncado)
    'f16_tcpudp_payload_length',    # comprimento real do payload transporte
    # f17-f18: novas features propostas
    'f17_src_packet_rate',          # pacotes/s deste src_ip nos últimos 1000 pacotes
    'f18_src_payload_diversity',    # unique payloads / total pacotes deste src_ip (janela)
]

# ── 1. Treinar modelos de bytes sobre tráfego benigno ────────────────────────

def train_byte_models():
    cols = ['label', 'attack_type', 'is_sd', 'someip_payload_hex', 'transport_payload_hex']
    si_payloads, sd_payloads, tu_payloads = [], [], []
    n_si = n_sd = n_tu = 0

    print('Coletando amostras para modelos de bytes...')
    for chunk in pd.read_csv(PARSED_CSV, usecols=cols, chunksize=CHUNK, low_memory=False):
        b_benign = chunk[(chunk['label'] == 0) & (chunk['attack_type'] == 'normal')]
        b_all    = chunk[chunk['label'] == 0]

        is_sd_b = b_benign['is_sd'].fillna(False).astype(str).str.lower().isin(['true','1'])
        is_sd_a = b_all['is_sd'].fillna(False).astype(str).str.lower().isin(['true','1'])

        if n_si < N_SAMPLES:
            s = b_benign[~is_sd_b]['someip_payload_hex'].dropna()
            take = min(len(s), N_SAMPLES - n_si)
            si_payloads.append(s.iloc[:take]); n_si += take

        if n_sd < N_SAMPLES:
            s = b_all[is_sd_a]['someip_payload_hex'].dropna()
            take = min(len(s), N_SAMPLES - n_sd)
            sd_payloads.append(s.iloc[:take]); n_sd += take

        if n_tu < N_SAMPLES:
            s = b_benign[~is_sd_b]['transport_payload_hex'].dropna()
            take = min(len(s), N_SAMPLES - n_tu)
            tu_payloads.append(s.iloc[:take]); n_tu += take

        if n_si >= N_SAMPLES and n_sd >= N_SAMPLES and n_tu >= N_SAMPLES:
            break

    print(f'  SOME/IP regular  : {n_si:,} amostras')
    print(f'  SOME/IP-SD       : {n_sd:,} amostras')
    print(f'  TCP/UDP          : {n_tu:,} amostras')

    t0 = time.time()
    model_si = ByteDistributionModel(); model_si.fit(pd.concat(si_payloads))
    model_sd = ByteDistributionModel(); model_sd.fit(pd.concat(sd_payloads))
    model_tu = ByteDistributionModel(); model_tu.fit(pd.concat(tu_payloads))
    print(f'Modelos treinados em {time.time()-t0:.1f}s')
    return model_si, model_sd, model_tu


# ── 2. Extração de features por chunk ────────────────────────────────────────

def make_flow_state():
    return {
        'prev_ts':          defaultdict(lambda: None),
        'prev_ip_len':      defaultdict(lambda: None),
        'prev_tl_len':      defaultdict(lambda: None),
        'prev_si_pld':      defaultdict(lambda: None),
        'prev_sd_pld':      defaultdict(lambda: None),
        'prev_tu_pld':      defaultdict(lambda: None),
        'recent_payloads':  defaultdict(lambda: deque(maxlen=5)),
        'last_src_payload': {},
        # f17/f18: janela deslizante por src_ip
        'src_timestamps':   defaultdict(lambda: deque(maxlen=1000)),
        'src_payloads':     defaultdict(lambda: deque(maxlen=1000)),
    }


def _f01_f08_f12(i, key, ts, ip_l, tl_l, si_h, tu_h, sd, state):
    """f01 (time interval) e f08-f12 (payload/length changes) para pacote i."""
    f01 = abs(ts - state['prev_ts'][key]) if state['prev_ts'][key] is not None else 0.0
    f08 = hamming_distance(state['prev_si_pld'][key], si_h) if not sd else 0.0
    f09 = hamming_distance(state['prev_sd_pld'][key], si_h) if sd     else 0.0
    f10 = hamming_distance(state['prev_tu_pld'][key], tu_h)
    p_ip = state['prev_ip_len'][key]
    p_tl = state['prev_tl_len'][key]
    f11 = abs(ip_l - p_ip) if p_ip is not None and ip_l is not None else 0.0
    f12 = abs(tl_l - p_tl) if p_tl is not None and tl_l is not None else 0.0
    return f01, f08, f09, f10, f11, f12


def _f13_repeat_rate(key, si_h, recent_payloads):
    """Fração dos últimos 5 payloads do fluxo idênticos ao atual."""
    hist = recent_payloads[key]
    rate = sum(1 for p in hist if p == si_h) / len(hist) if hist and si_h else 0.0
    hist.append(si_h)
    return rate


def _f14_duplicate_source(src, si_h, last_src_payload):
    """1.0 se o mesmo payload foi visto de src_ip diferente (relay MITM cross-PCAP)."""
    if not si_h:
        return 0.0
    pld_key  = hash(si_h)
    prev_src = last_src_payload.get(pld_key)
    result   = 1.0 if prev_src is not None and prev_src != src else 0.0
    last_src_payload[pld_key] = src
    return result


def _f17_src_rate(src, ts, src_timestamps):
    """Pacotes/s deste src_ip na janela dos últimos 1000 timestamps."""
    ts_win = src_timestamps[src]
    ts_win.append(ts)
    if len(ts_win) < 2:
        return 0.0
    delta = ts - ts_win[0]
    return (len(ts_win) - 1) / delta if delta > 0 else float(len(ts_win))


def _f18_payload_diversity(src, si_h, src_payloads_win):
    """unique payloads / total payloads deste src_ip na janela (0 se <2 pacotes)."""
    pld_win = src_payloads_win[src]
    if si_h:
        pld_win.append(si_h)
    return len(set(pld_win)) / len(pld_win) if len(pld_win) > 1 else 0.0


def _update_state(key, ts, ip_l, tl_l, si_h, tu_h, sd, state):
    """Avança o estado de fluxo para o próximo pacote."""
    state['prev_ts'][key]     = ts
    state['prev_ip_len'][key] = ip_l
    state['prev_tl_len'][key] = tl_l
    state['prev_tu_pld'][key] = tu_h
    if not sd:
        state['prev_si_pld'][key] = si_h
    else:
        state['prev_sd_pld'][key] = si_h


def extract(df, flow_state, model_si, model_sd, model_tu):
    df = df.sort_values(['pcap_file', 'timestamp']).reset_index(drop=True)
    n  = len(df)

    si_hex = df['someip_payload_hex'].fillna('')
    tu_hex = df['transport_payload_hex'].fillna('')

    f02 = model_si.log_likelihood_batch(si_hex)
    f03 = model_sd.log_likelihood_batch(si_hex)
    f04 = model_tu.log_likelihood_batch(tu_hex)
    f05 = model_si.cross_entropy_batch(si_hex)
    f06 = model_sd.cross_entropy_batch(si_hex)
    f07 = model_tu.cross_entropy_batch(tu_hex)

    ts_v   = df['timestamp'].values
    ip_v   = pd.to_numeric(df['ip_len'],       errors='coerce').values
    tl_v   = pd.to_numeric(df['transport_len'], errors='coerce').values
    si_v   = si_hex.values
    tu_v   = tu_hex.values
    is_sd  = df['is_sd'].fillna(False).astype(str).str.lower().isin(['true','1']).values
    src_ip = df['src_ip'].astype(str).values
    dst_ip = df['dst_ip'].astype(str).values
    sport  = df['src_port'].astype(str).values
    dport  = df['dst_port'].astype(str).values
    trans  = df['transport'].astype(str).values
    pcap   = df['pcap_file'].astype(str).values

    f01 = np.zeros(n); f08 = np.zeros(n); f09 = np.zeros(n)
    f10 = np.zeros(n); f11 = np.zeros(n); f12 = np.zeros(n)
    f13 = np.zeros(n); f14 = np.zeros(n); f17 = np.zeros(n); f18 = np.zeros(n)

    f15 = pd.to_numeric(df['someip_payload_len'], errors='coerce').fillna(0).values.astype(float)
    f16 = pd.to_numeric(df['transport_len'],      errors='coerce').fillna(0).values.astype(float)

    for i in range(n):
        key  = (pcap[i], src_ip[i], dst_ip[i], sport[i], dport[i], trans[i])
        ts   = float(ts_v[i])
        ip_l = float(ip_v[i]) if not np.isnan(ip_v[i]) else None
        tl_l = float(tl_v[i]) if not np.isnan(tl_v[i]) else None
        si_h = si_v[i] if si_v[i] else None
        tu_h = tu_v[i] if tu_v[i] else None
        sd   = bool(is_sd[i])
        src  = src_ip[i]

        f01[i], f08[i], f09[i], f10[i], f11[i], f12[i] = _f01_f08_f12(
            i, key, ts, ip_l, tl_l, si_h, tu_h, sd, flow_state)
        f13[i] = _f13_repeat_rate(key, si_h, flow_state['recent_payloads'])
        f14[i] = _f14_duplicate_source(src, si_h, flow_state['last_src_payload'])
        f17[i] = _f17_src_rate(src, ts, flow_state['src_timestamps'])
        f18[i] = _f18_payload_diversity(src, si_h, flow_state['src_payloads'])

        _update_state(key, ts, ip_l, tl_l, si_h, tu_h, sd, flow_state)

    labels      = df['label'].values      if 'label'       in df.columns else np.zeros(n, dtype=int)
    attack_type = df['attack_type'].values if 'attack_type' in df.columns else np.full(n, 'unknown')

    return pd.DataFrame({
        'f01_ip_time_interval':      f01,
        'f02_someip_likelihood':     f02,
        'f03_someipsd_likelihood':   f03,
        'f04_tcpudp_likelihood':     f04,
        'f05_someip_entropy':        f05,
        'f06_someipsd_entropy':      f06,
        'f07_tcpudp_entropy':        f07,
        'f08_someip_payload_changes':  f08,
        'f09_someipsd_payload_changes':f09,
        'f10_tcpudp_payload_changes':  f10,
        'f11_ip_length_changes':     f11,
        'f12_tcpudp_length_changes': f12,
        'f13_payload_repeat_rate':   f13,
        'f14_duplicate_source':      f14,
        'f15_someip_payload_length': f15,
        'f16_tcpudp_payload_length': f16,
        'f17_src_packet_rate':       f17,
        'f18_src_payload_diversity': f18,
        'label':       labels,
        'attack_type': attack_type,
    })


# ── 3. Execução principal ─────────────────────────────────────────────────────

if __name__ == '__main__':
    print(f'CSV: {PARSED_CSV}')
    print(f'Existe: {PARSED_CSV.exists()}')
    if PARSED_CSV.exists():
        print(f'Tamanho: {PARSED_CSV.stat().st_size/1e9:.2f} GB')

    model_si, model_sd, model_tu = train_byte_models()

    RAW_CSV = FEATURES_DIR / 'all_features_raw.csv'
    if RAW_CSV.exists():
        print(f'[OK] {RAW_CSV.name} ja existe — pulando extração.')
    else:
        flow_state = make_flow_state()
        first = True; n_total = 0; t0 = time.time()
        for chunk in pd.read_csv(PARSED_CSV, chunksize=CHUNK, low_memory=False):
            out = extract(chunk, flow_state, model_si, model_sd, model_tu)
            out.to_csv(RAW_CSV, mode='a', header=first, index=False)
            first = False; n_total += len(out)
            print(f'  {n_total:,} features extraidas  ({time.time()-t0:.0f}s)')
        print(f'Concluido: {n_total:,} amostras')

    TRAIN_CSV = FEATURES_DIR / 'train_features.csv'
    TEST_CSV  = FEATURES_DIR / 'test_features.csv'

    if TRAIN_CSV.exists() and TEST_CSV.exists():
        print('[OK] train/test CSVs ja existem — pulando split.')
    else:
        print('Lendo labels para split estratificado...')
        labels = pd.concat(
            c['label'] for c in pd.read_csv(RAW_CSV, usecols=['label'], chunksize=CHUNK)
        ).values
        idx = np.arange(len(labels))
        train_idx, _ = train_test_split(idx, test_size=0.5, stratify=labels, random_state=RAND_STATE)
        is_train = np.zeros(len(labels), dtype=bool)
        is_train[train_idx] = True
        n0 = (labels[is_train] == 0).sum(); n1 = (labels[is_train] == 1).sum()
        print(f'Treino: {is_train.sum():,}  (normal={n0:,}  ataque={n1:,})')
        print(f'Teste : {(~is_train).sum():,}')
        row = 0; ftr = fte = True
        for chunk in pd.read_csv(RAW_CSV, chunksize=CHUNK):
            mask = is_train[row: row + len(chunk)]
            chunk[mask].to_csv(TRAIN_CSV,  mode='a', header=ftr, index=False)
            chunk[~mask].to_csv(TEST_CSV,  mode='a', header=fte, index=False)
            ftr = fte = False; row += len(chunk)
        print('Split concluido.')

    # Normalização Min-Max (calculada só no treino)
    stats = {c: {'min': float('inf'), 'max': float('-inf')} for c in FEAT_COLS}
    for chunk in pd.read_csv(TRAIN_CSV, usecols=FEAT_COLS, chunksize=CHUNK):
        for c in FEAT_COLS:
            stats[c]['min'] = min(stats[c]['min'], chunk[c].min())
            stats[c]['max'] = max(stats[c]['max'], chunk[c].max())

    print('Min/Max por feature (treino):')
    for c in FEAT_COLS:
        print(f'  {c:<35}  min={stats[c]["min"]:10.4f}  max={stats[c]["max"]:10.4f}')

    def export_npy(csv_path, split_name):
        xc, yc = [], []
        for chunk in pd.read_csv(csv_path, chunksize=CHUNK):
            x = chunk[FEAT_COLS].values.astype(np.float32)
            for j, c in enumerate(FEAT_COLS):
                lo, hi = stats[c]['min'], stats[c]['max']
                d = hi - lo
                x[:, j] = np.clip((x[:, j] - lo) / d, 0.0, 1.0) if d > 0 else 0.0
            xc.append(x)
            yc.append(chunk['label'].values.astype(np.int8))
        x_all = np.vstack(xc); y_all = np.concatenate(yc)
        np.save(FEATURES_DIR / f'X_{split_name}.npy', x_all)
        np.save(FEATURES_DIR / f'y_{split_name}.npy', y_all)
        n0, n1 = (y_all==0).sum(), (y_all==1).sum()
        print(f'{split_name}: X={x_all.shape}  normal={n0:,} ({100*n0/len(y_all):.1f}%)  '
              f'ataque={n1:,} ({100*n1/len(y_all):.1f}%)')

    print('\nExportando .npy...')
    export_npy(TRAIN_CSV, 'train')
    export_npy(TEST_CSV,  'test')
    print('Concluido.')
