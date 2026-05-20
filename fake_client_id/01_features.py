"""
Extracao de features para classe FakeClientID — dados do someip_traces.

Parseia PCAPs com scapy e alinha com labels dos CSVs (1:1 por indice de pacote).

Classes geradas:
    0 = Benigno
    5 = FakeClientID

13 features (f01-f22, incluindo f22_clientid_ip_mismatch):
    f01 ip_time_interval, f08 someip_payload_change,
    f11 ip_length_change, f12 tcpudp_length_change,
    f13 payload_repeat_rate, f15 someip_payload_len,
    f16 tcpudp_len, f17 src_packet_rate,
    f18 src_payload_diversity, f19 is_sd,
    f20 src_service_diversity, f21 is_relay_service,
    f22 clientid_ip_mismatch  <-- nova feature

Saida:
    fake_client_id/data/features.csv
    fake_client_id/data/X_train.npy  y_train.npy
    fake_client_id/data/X_test.npy   y_test.npy
    fake_client_id/data/class_counts.json

Uso:
    python fake_client_id/01_features.py
"""
import sys, struct, time, json
import numpy as np
import pandas as pd
from pathlib import Path
from collections import defaultdict, deque
from sklearn.model_selection import train_test_split

SOMEIP_PORTS   = {30490, 30491, 30492, 30501, 30502, 30503}
SOMEIP_SD_SVC  = 0xFFFF
SOMEIP_HDR_LEN = 16
RELAY_SVC      = 0x100B

ROOT        = Path(__file__).parent.parent.parent
RAW_DIR     = Path(__file__).parent.parent / 'data' / 'raw'
FRAMES_DIR  = ROOT / 'experiments' / 'someip_traces' / 'dataframes'
OUT_DIR     = Path(__file__).parent / 'data'
OUT_DIR.mkdir(exist_ok=True)

RAND_STATE  = 42

CLASS_NAMES = {0: 'Benigno', 5: 'FakeClientID'}

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
    'f22_src_clientid_diversity',
]

# (pcap_file, label_csv, attack_label)
SOURCES = [
    ('fakeClientID.pcap',  'fakeclientid1.csv', 5),
    ('fakeClientID2.pcap', 'fakeclientid2.csv', 5),
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
        'src_services':  defaultdict(lambda: deque(maxlen=100)),
        'src_clientids': defaultdict(lambda: deque(maxlen=100)),
    }


def _hamming(hex_a, hex_b) -> float:
    if not hex_a or not hex_b:
        return 0.0
    try:
        a = bytes.fromhex(hex_a)
        b = bytes.fromhex(hex_b)
    except ValueError:
        return 0.0
    L = min(len(a), len(b))
    if L == 0:
        return 0.0
    return float(np.unpackbits(
        np.bitwise_xor(np.frombuffer(a[:L], dtype=np.uint8),
                       np.frombuffer(b[:L], dtype=np.uint8))
    ).sum()) / (8 * L)



def _parse_someip_fields(pkt):
    """Retorna (ip_layer, l4, transport, sport, dport, transport_len) ou None."""
    from scapy.all import IP, UDP, TCP
    if not pkt.haslayer(IP):
        return None
    ip_layer = pkt[IP]
    if pkt.haslayer(UDP):
        l4 = pkt[UDP]
        return ip_layer, l4, 'UDP', l4.sport, l4.dport, max(0, l4.len - 8)
    if pkt.haslayer(TCP):
        l4 = pkt[TCP]
        return ip_layer, l4, 'TCP', l4.sport, l4.dport, len(bytes(l4.payload))
    return None


def _parse_someip_header(l4):
    """Extrai campos do header SOME/IP. Retorna None se inválido."""
    raw = bytes(l4.payload)
    if len(raw) < SOMEIP_HDR_LEN:
        return None
    try:
        service_id, method_id, _ = struct.unpack_from('>HHI', raw, 0)
        client_id, _             = struct.unpack_from('>HH',  raw, 8)
        msg_type                 = raw[14]
        payload = raw[SOMEIP_HDR_LEN:]
        return service_id, method_id, client_id, msg_type, payload.hex() if payload else '', len(payload)
    except struct.error:
        return None


def _extract_features(state, key, src, ts, ip_len, tl_len,
                      payload_hex, payload_len, service_id, client_id, msg_type, is_sd):
    """Calcula as 13 features a partir do estado stateful."""
    prev_ts = state['prev_ts'][key]
    f01 = abs(ts - prev_ts) if prev_ts is not None else 0.0
    f08 = _hamming(state['prev_si_pld'][key], payload_hex)

    p_ip = state['prev_ip_len'][key]
    p_tl = state['prev_tl_len'][key]
    f11  = abs(ip_len - p_ip) if p_ip is not None else 0.0
    f12  = abs(tl_len  - p_tl) if p_tl is not None else 0.0

    hist = state['recent_payloads'][key]
    f13  = sum(1 for p in hist if p == payload_hex) / len(hist) if (hist and payload_hex) else 0.0
    hist.append(payload_hex)

    f15 = float(payload_len)
    f16 = float(tl_len)

    win_t = state['src_timestamps'][src]
    win_t.append(ts)
    if len(win_t) >= 2:
        delta = ts - win_t[0]
        f17   = (len(win_t) - 1) / delta if delta > 0 else float(len(win_t))
    else:
        f17 = 0.0

    win_p = state['src_payloads'][src]
    if payload_hex:
        win_p.append(payload_hex)
    f18 = len(set(win_p)) / len(win_p) if len(win_p) > 1 else 0.0

    f19 = 1.0 if is_sd else 0.0

    win_s = state['src_services'][src]
    win_s.append(service_id)
    f20 = float(len(set(win_s)))

    f21 = 1.0 if service_id == RELAY_SVC else 0.0

    win_c = state['src_clientids'][src]
    if client_id is not None and msg_type < 0x80:
        win_c.append(client_id)
    f22 = float(len(set(win_c))) if win_c else 1.0

    state['prev_ts'][key]     = ts
    state['prev_ip_len'][key] = ip_len
    state['prev_tl_len'][key] = tl_len
    state['prev_si_pld'][key] = payload_hex

    return [f01, f08, f11, f12, f13, f15, f16, f17, f18, f19, f20, f21, f22]


def parse_pcap(pcap_path: Path, label_csv_path: Path, attack_label: int,
               state: dict) -> pd.DataFrame:
    from scapy.all import rdpcap

    print(f'  Lendo {pcap_path.name}...')
    pkts   = rdpcap(str(pcap_path))
    labels = pd.read_csv(label_csv_path)['label'].values

    if len(pkts) != len(labels):
        print(f'  AVISO: {len(pkts)} pacotes vs {len(labels)} labels — usando min')

    rows = []
    for i in range(min(len(pkts), len(labels))):
        parsed = _parse_someip_fields(pkts[i])
        if parsed is None:
            continue
        ip_layer, l4, transport, sport, dport, tl_len = parsed

        if sport not in SOMEIP_PORTS and dport not in SOMEIP_PORTS:
            continue

        hdr = _parse_someip_header(l4)
        if hdr is None:
            continue
        service_id, _method_id, client_id, msg_type, payload_hex, payload_len = hdr

        ts  = float(pkts[i].time)
        src = ip_layer.src
        dst = ip_layer.dst
        key = (src, dst, sport, dport, transport)

        feats = _extract_features(
            state, key, src, ts, ip_layer.len, tl_len,
            payload_hex, payload_len, service_id, client_id, msg_type,
            is_sd=(service_id == SOMEIP_SD_SVC),
        )
        mc_label = attack_label if int(labels[i]) != 0 else 0
        rows.append(dict(zip(FEAT_COLS, feats)) | {'label': mc_label})

    return pd.DataFrame(rows)


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    FEAT_CSV = OUT_DIR / 'features.csv'

    for pcap_name, csv_name, _ in SOURCES:
        for p, label in [(RAW_DIR / pcap_name, 'PCAP'), (FRAMES_DIR / csv_name, 'CSV')]:
            if not p.exists():
                raise FileNotFoundError(f'{label} nao encontrado: {p}')

    if FEAT_CSV.exists():
        print(f'[OK] {FEAT_CSV} ja existe -- apague para re-extrair.')
    else:
        state  = make_state()
        frames = []
        t0     = time.time()

        for pcap_name, csv_name, attack_label in SOURCES:
            df = parse_pcap(
                RAW_DIR / pcap_name,
                FRAMES_DIR / csv_name,
                attack_label,
                state,
            )
            frames.append(df)
            print(f'  {pcap_name}: {len(df):,} pacotes parseados  ({time.time()-t0:.1f}s)')

        all_df = pd.concat(frames, ignore_index=True)
        all_df.to_csv(FEAT_CSV, index=False)
        print(f'\nConcluido: {len(all_df):,} amostras -> {FEAT_CSV}')

    # Estatísticas
    all_df = pd.read_csv(FEAT_CSV)
    labels = all_df['label'].values
    print('\nDistribuicao do dataset:')
    counts = {}
    for lbl, name in CLASS_NAMES.items():
        n = int((labels == lbl).sum())
        counts[name] = n
        print(f'  {name:<15}: {n:>8,}  ({100*n/len(labels):.1f}%)')
    with open(OUT_DIR / 'class_counts.json', 'w') as f:
        json.dump(counts, f, indent=2)

    print('\nMin/Max por feature:')
    for c in FEAT_COLS:
        print(f'  {c:<32}  min={all_df[c].min():>10.4f}  max={all_df[c].max():>10.4f}')

    # Split e export
    print('\nSplit treino/teste (70/30 estratificado)...')
    idx = np.arange(len(labels))
    train_idx, test_idx = train_test_split(
        idx, test_size=0.3, stratify=labels, random_state=RAND_STATE
    )
    is_train = np.zeros(len(labels), dtype=bool)
    is_train[train_idx] = True

    norm = {}
    for c in FEAT_COLS:
        norm[c] = {'min': float(all_df[c].min()), 'max': float(all_df[c].max())}

    MODEL_DIR = Path(__file__).parent / 'model'
    MODEL_DIR.mkdir(exist_ok=True)
    with open(MODEL_DIR / 'norm_params.json', 'w') as f:
        json.dump(norm, f, indent=2)

    X = all_df[FEAT_COLS].values.astype(np.float32)
    for j, c in enumerate(FEAT_COLS):
        lo = norm[c]['min']; hi = norm[c]['max']; d = hi - lo
        X[:, j] = np.clip((X[:, j] - lo) / d, 0, 1) if d > 0 else 0.0
    y = labels.astype(np.int8)

    for split_name, mask in [('train', is_train), ('test', ~is_train)]:
        np.save(OUT_DIR / f'X_{split_name}.npy', X[mask])
        np.save(OUT_DIR / f'y_{split_name}.npy', y[mask])
        print(f'  {split_name}: {X[mask].shape}')
        for lbl, name in CLASS_NAMES.items():
            print(f'    {name:<15}: {(y[mask] == lbl).sum():>8,}')

    print(f'\nArquivos salvos em {OUT_DIR}')
