"""
Teste out-of-scope: avalia o classificador multiclasse (6 classes) em
PCAPs do someip_traces que contêm tipos de ataque NÃO vistos no treino.

Para cada PCAP:
  - Parseia com scapy (extrai 13 features incluindo f22)
  - Carrega labels do CSV correspondente (se disponível e com contagem igual)
  - Roda o classificador
  - Reporta distribuição de predições por classe (e por label real se disponível)

Uso:
    python multiclass/03_test_outofscope.py
"""
import struct, json
import numpy as np
import pandas as pd
from pathlib import Path
from collections import defaultdict, deque

ROOT       = Path(__file__).parent.parent.parent
RAW_DIR    = Path(__file__).parent.parent / 'data' / 'raw'
LABELS_DIR = ROOT / 'experiments' / 'someip_traces'
FRAMES_DIR = LABELS_DIR / 'dataframes'
MODEL_DIR  = Path(__file__).parent / 'model'

SOMEIP_PORTS   = {30490, 30491, 30492, 30501, 30502, 30503}
SOMEIP_SD_SVC  = 0xFFFF
SOMEIP_HDR_LEN = 16
RELAY_SVC      = 0x100B

CLASS_NAMES = ['Benigno', 'DoS', 'Fuzzy', 'MITM_Multi', 'MITM_Single', 'FakeClientID']

FEAT_COLS = [
    'f01_ip_time_interval', 'f08_someip_payload_change',
    'f11_ip_length_change',  'f12_tcpudp_length_change',
    'f13_payload_repeat_rate', 'f15_someip_payload_len',
    'f16_tcpudp_len', 'f17_src_packet_rate', 'f18_src_payload_diversity',
    'f19_is_sd', 'f20_src_service_diversity', 'f21_is_relay_service',
    'f22_src_clientid_diversity',
]

# (pcap, csv_labels_or_None, attack_name)
SCENARIOS = [
    ('eerror.pcap',              None,                           'Error on Error'),
    ('eevent.pcap',              'erroronevent1.csv',            'Error on Event'),
    ('drequest.pcap',            None,                           'Delete Request'),
    ('dresponse.pcap',           None,                           'Delete Response'),
    ('wrongInterface.pcap',      'wronginterface1.csv',          'Wrong Interface'),
    ('wrongInterface2.pcap',     'wronginterface2.csv',          'Wrong Interface 2'),
    ('deleteRequest_test1.pcap', None,                           'Delete Request Test'),
]


def _hamming(hex_a, hex_b):
    if not hex_a or not hex_b:
        return 0.0
    try:
        a = bytes.fromhex(hex_a); b = bytes.fromhex(hex_b)
    except ValueError:
        return 0.0
    L = min(len(a), len(b))
    if L == 0:
        return 0.0
    return float(np.unpackbits(
        np.bitwise_xor(np.frombuffer(a[:L], np.uint8),
                       np.frombuffer(b[:L], np.uint8))
    ).sum()) / (8 * L)


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
        'src_clientids':   defaultdict(lambda: deque(maxlen=100)),
    }


def extract_features(pkts, state):
    from scapy.all import IP, UDP, TCP
    rows = []
    for pkt in pkts:
        if not pkt.haslayer(IP):
            rows.append(None); continue
        ip = pkt[IP]

        if pkt.haslayer(UDP):
            l4 = pkt[UDP]; transport = 'UDP'; tl_len = max(0, l4.len - 8)
        elif pkt.haslayer(TCP):
            l4 = pkt[TCP]; transport = 'TCP'; tl_len = len(bytes(l4.payload))
        else:
            rows.append(None); continue

        sport, dport = l4.sport, l4.dport
        if sport not in SOMEIP_PORTS and dport not in SOMEIP_PORTS:
            rows.append(None); continue

        raw = bytes(l4.payload)
        if len(raw) < SOMEIP_HDR_LEN:
            rows.append(None); continue

        try:
            svc, _mid, _ = struct.unpack_from('>HHI', raw, 0)
            cid, _       = struct.unpack_from('>HH',  raw, 8)
            msg_type     = raw[14]
            payload = raw[SOMEIP_HDR_LEN:]
            ph = payload.hex() if payload else ''; pl = len(payload)
        except struct.error:
            rows.append(None); continue

        ts  = float(pkt.time); src = ip.src; dst = ip.dst
        key = (src, dst, sport, dport, transport)

        prev_ts = state['prev_ts'][key]
        f01 = abs(ts - prev_ts) if prev_ts is not None else 0.0
        f08 = _hamming(state['prev_si_pld'][key], ph)
        p_ip = state['prev_ip_len'][key]; p_tl = state['prev_tl_len'][key]
        f11  = abs(ip.len - p_ip) if p_ip is not None else 0.0
        f12  = abs(tl_len  - p_tl) if p_tl is not None else 0.0
        hist = state['recent_payloads'][key]
        f13  = sum(1 for p in hist if p == ph) / len(hist) if (hist and ph) else 0.0
        hist.append(ph)
        f15 = float(pl); f16 = float(tl_len)
        win_t = state['src_timestamps'][src]; win_t.append(ts)
        if len(win_t) >= 2:
            d = ts - win_t[0]; f17 = (len(win_t)-1)/d if d > 0 else float(len(win_t))
        else:
            f17 = 0.0
        win_p = state['src_payloads'][src]
        if ph: win_p.append(ph)
        f18 = len(set(win_p)) / len(win_p) if len(win_p) > 1 else 0.0
        f19 = 1.0 if svc == SOMEIP_SD_SVC else 0.0
        win_s = state['src_services'][src]; win_s.append(svc)
        f20 = float(len(set(win_s)))
        f21 = 1.0 if svc == RELAY_SVC else 0.0
        win_c = state['src_clientids'][src]
        if msg_type < 0x80:
            win_c.append(cid)
        f22 = float(len(set(win_c))) if win_c else 1.0

        state['prev_ts'][key]     = ts
        state['prev_ip_len'][key] = ip.len
        state['prev_tl_len'][key] = tl_len
        state['prev_si_pld'][key] = ph

        rows.append([f01,f08,f11,f12,f13,f15,f16,f17,f18,f19,f20,f21,f22])

    return rows


def normalize(X, norm):
    X = X.copy()
    for j, c in enumerate(FEAT_COLS):
        lo = norm[c]['min']; hi = norm[c]['max']; d = hi - lo
        X[:, j] = np.clip((X[:, j] - lo) / d, 0, 1) if d > 0 else 0.0
    return X


def main():
    import xgboost as xgb
    from scapy.all import rdpcap

    print('Carregando modelo e norm_params...')
    model = xgb.XGBClassifier()
    model.load_model(str(MODEL_DIR / 'multiclass_classifier.json'))
    norm = json.load(open(MODEL_DIR / 'norm_params.json'))

    results = []

    for pcap_name, csv_name, attack_name in SCENARIOS:
        pcap_path = RAW_DIR / pcap_name
        if not pcap_path.exists():
            print(f'[SKIP] {pcap_name} não encontrado'); continue

        print(f'\n{"="*60}')
        print(f'  {attack_name}  ({pcap_name})')
        print(f'{"="*60}')

        pkts = rdpcap(str(pcap_path))

        # Labels do CSV (se disponível e alinhado)
        labels = None
        if csv_name:
            csv_candidates = [FRAMES_DIR / csv_name, LABELS_DIR / csv_name]
            for cp in csv_candidates:
                if cp.exists():
                    df_csv = pd.read_csv(cp)
                    if len(df_csv) == len(pkts):
                        labels = df_csv['label'].values
                        print(f'  Labels: {dict(pd.Series(labels).value_counts().sort_index())}')
                    else:
                        print(f'  CSV tem {len(df_csv)} linhas vs {len(pkts)} pkts — sem alinhamento')
                    break

        state = make_state()
        rows  = extract_features(pkts, state)

        valid_idx = [i for i, r in enumerate(rows) if r is not None]
        X_raw = np.array([rows[i] for i in valid_idx], dtype=np.float32)
        X_norm = normalize(X_raw, norm)
        preds = model.predict(X_norm)

        print(f'  Pacotes válidos (SOME/IP): {len(valid_idx)} / {len(pkts)}')
        print(f'\n  Distribuição de predições:')
        total = len(preds)
        for cls_id, cls_name in enumerate(CLASS_NAMES):
            n = (preds == cls_id).sum()
            bar = '#' * int(40 * n / total) if total > 0 else ''
            print(f'    {cls_name:<15}: {n:>6,}  ({100*n/total:5.1f}%)  {bar}')

        if labels is not None:
            print(f'\n  Predições por label real:')
            valid_labels = labels[valid_idx]
            for raw_lbl in sorted(set(valid_labels)):
                mask = valid_labels == raw_lbl
                sub_preds = preds[mask]
                dominant = CLASS_NAMES[np.bincount(sub_preds).argmax()]
                print(f'    label={raw_lbl} ({mask.sum():>5} pkts) -> predito como: {dominant}  '
                      f'{dict(zip(*np.unique(sub_preds, return_counts=True)))}')

        res = {'attack': attack_name, 'pcap': pcap_name, 'total': total}
        for cls_id, cls_name in enumerate(CLASS_NAMES):
            res[cls_name] = int((preds == cls_id).sum())
        results.append(res)

    print(f'\n{"="*60}')
    print('  RESUMO GERAL')
    print(f'{"="*60}')
    df = pd.DataFrame(results).set_index('attack')
    print(df[CLASS_NAMES].to_string())

    out = MODEL_DIR / 'outofscope_results.json'
    with open(out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f'\nResultados salvos em {out}')


if __name__ == '__main__':
    main()
