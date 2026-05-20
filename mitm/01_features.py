"""
Extracao de features para deteccao de MITM SOME/IP (mitm_multi_attacker).

Le benign_traffic.csv + mitm_multi_attacker.csv e extrai 12 features focadas
nas caracteristicas do ataque MITM (relay + SD spoofing + forged notifications):

    f01  ip_time_interval        -- intervalo entre pacotes do fluxo
    f08  someip_payload_change   -- Hamming entre payloads consecutivos (~0 no relay)
    f11  ip_length_change        -- variacao tamanho IP
    f12  tcpudp_length_change    -- variacao tamanho TCP/UDP
    f13  payload_repeat_rate     -- fracao dos ultimos 5 payloads identicos (alto no relay)
    f15  someip_payload_len      -- comprimento payload SOME/IP
    f16  tcpudp_len              -- comprimento camada transporte
    f17  src_packet_rate         -- pacotes/s do src_ip (janela 1000)
    f18  src_payload_diversity   -- payloads unicos / total (baixo no relay)
    f19  is_sd                   -- 1 se service_id=0xFFFF (SOME/IP-SD)
    f20  src_service_diversity   -- servicos distintos por src_ip (janela 100): >= 2 no atacante
    f21  is_relay_service        -- 1 se service_id=0x100B (servico de relay inexistente no benigno)

Perfil do ataque MITM:
    Componente A (relay):    f08 baixo + f13 alto + f18 baixo + f21=1
    Componente B (SD spoof): f19=1
    Componente C (forged):   f17 elevado + f20 >= 2

Saida:
    mitm/data/features.csv
    mitm/data/X_train.npy  y_train.npy
    mitm/data/X_test.npy   y_test.npy

Uso:
    python mitm/01_features.py
"""
import sys, time
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

RELAY_SERVICE_ID = 0x100B

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

PCAP_FILES = [
    PARSED_DIR / 'benign_traffic.csv',
    PARSED_DIR / 'mitm_multi_attacker.csv',
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


def _f17(src, ts, src_timestamps) -> float:
    win = src_timestamps[src]
    win.append(ts)
    if len(win) < 2:
        return 0.0
    delta = ts - win[0]
    return (len(win) - 1) / delta if delta > 0 else float(len(win))


def _f18(src, si_h, src_payloads) -> float:
    win = src_payloads[src]
    if si_h:
        win.append(si_h)
    return len(set(win)) / len(win) if len(win) > 1 else 0.0


def _f20(src, svc_id, src_services) -> float:
    win = src_services[src]
    if svc_id is not None:
        win.append(svc_id)
    return float(len(set(win))) if len(win) > 0 else 1.0


# ── Extracao por chunk ────────────────────────────────────────────────────────

def extract(df: pd.DataFrame, state: dict) -> pd.DataFrame:
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

    if 'is_sd' in df.columns:
        is_sd_v = df['is_sd'].fillna(False).astype(bool).astype(float).values
    else:
        is_sd_v = np.zeros(n)

    f01 = np.zeros(n); f08 = np.zeros(n); f11 = np.zeros(n)
    f12 = np.zeros(n); f13 = np.zeros(n); f17 = np.zeros(n)
    f18 = np.zeros(n); f20 = np.ones(n)

    f15 = pd.to_numeric(df['someip_payload_len'], errors='coerce').fillna(0).values.astype(float)
    f16 = pd.to_numeric(df['transport_len'],       errors='coerce').fillna(0).values.astype(float)

    # f21: 1 se service_id == RELAY_SERVICE_ID
    f21 = np.zeros(n)
    for i in range(n):
        if not np.isnan(svc_v[i]) and int(svc_v[i]) == RELAY_SERVICE_ID:
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

        f08[i] = _hamming(state['prev_si_pld'][key], si_h)

        p_ip = state['prev_ip_len'][key]
        p_tl = state['prev_tl_len'][key]
        f11[i] = abs(ip_l - p_ip) if (p_ip is not None and ip_l is not None) else 0.0
        f12[i] = abs(tl_l - p_tl) if (p_tl is not None and tl_l is not None) else 0.0

        hist   = state['recent_payloads'][key]
        f13[i] = sum(1 for p in hist if p == si_h) / len(hist) if (hist and si_h) else 0.0
        hist.append(si_h)

        f17[i] = _f17(src, ts, state['src_timestamps'])
        f18[i] = _f18(src, si_h, state['src_payloads'])
        f20[i] = _f20(src, svc, state['src_services'])

        state['prev_ts'][key]     = ts
        state['prev_ip_len'][key] = ip_l
        state['prev_tl_len'][key] = tl_l
        state['prev_si_pld'][key] = si_h

    labels = df['label'].values if 'label' in df.columns else np.zeros(n, dtype=int)

    return pd.DataFrame({
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
        'label': labels,
    })


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    FEAT_CSV = OUT_DIR / 'features.csv'

    for p in PCAP_FILES:
        if not p.exists():
            raise FileNotFoundError(
                f'{p} nao encontrado -- rode primeiro:\n'
                f'  python src/01_parse.py --pcaps benign_traffic.pcap mitm_multi_attacker.pcap'
            )

    if FEAT_CSV.exists():
        print(f'[OK] {FEAT_CSV} ja existe -- apague para re-extrair.')
    else:
        state   = make_state()
        first   = True
        n_total = 0
        t0      = time.time()

        for pcap_csv in PCAP_FILES:
            print(f'\nLendo {pcap_csv.name}...')
            for chunk in pd.read_csv(pcap_csv, chunksize=CHUNK, low_memory=False):
                out = extract(chunk, state)
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
    n0, n1 = (labels == 0).sum(), (labels == 1).sum()
    print(f'  Benigno : {n0:>10,}  ({100*n0/len(labels):.1f}%)')
    print(f'  MITM    : {n1:>10,}  ({100*n1/len(labels):.1f}%)')

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
        n0, n1 = (y==0).sum(), (y==1).sum()
        print(f'  {split_name}: {X.shape}  benigno={n0:,}  mitm={n1:,}')

    export('train', is_train.copy())
    export('test',  ~is_train)
    print(f'\nArquivos salvos em {OUT_DIR}')
