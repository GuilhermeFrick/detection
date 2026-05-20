"""
IDS Orchestrator — deteccao e atribuicao multi-ataque SOME/IP.

Estagio 1: Parser (src/01_parse.py) -> CSV por PCAP
Estagio 2: Orquestrador (este script) -> extrair features + inferencia + atribuicao

Para cada pacote do CSV de entrada:
  - Extrai 21 features (superconjunto de todos os classificadores)
  - Normaliza por conjunto de min/max de cada modelo
  - Roda 4 classificadores XGBoost em paralelo
  - Agrega probabilidades por src_ip
  - Reporta tipo de ataque detectado

Uso:
    python orchestrator.py --csv data/parsed/dos_noti_flood.csv
    python orchestrator.py --csv data/parsed/mitm_multi_attacker.csv --threshold 0.5
    python orchestrator.py --csv data/parsed/benign_traffic.csv
"""
import sys, json, time, argparse
import numpy as np
import pandas as pd
import xgboost as xgb
from pathlib import Path
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).parent

RELAY_SERVICE_ID = 0x100B

# ── Definicao dos classificadores ─────────────────────────────────────────────

CLASSIFIERS = {
    'DoS': {
        'model': ROOT / 'dos'         / 'model' / 'dos_classifier.json',
        'norm':  ROOT / 'dos'         / 'model' / 'norm_params.json',
        'feat_cols': [
            'f01_ip_time_interval', 'f08_someip_payload_change',
            'f11_ip_length_change', 'f12_tcpudp_length_change',
            'f13_payload_repeat_rate', 'f15_someip_payload_len',
            'f16_tcpudp_len', 'f17_src_packet_rate', 'f18_src_payload_diversity',
        ],
    },
    'Fuzzy': {
        'model': ROOT / 'fuzzy'       / 'model' / 'fuzzy_classifier.json',
        'norm':  ROOT / 'fuzzy'       / 'model' / 'norm_params.json',
        'feat_cols': [
            'f01_ip_time_interval', 'f08_someip_payload_change',
            'f11_ip_length_change', 'f12_tcpudp_length_change',
            'f13_payload_repeat_rate', 'f15_someip_payload_len',
            'f16_tcpudp_len', 'f17_src_packet_rate', 'f18_src_payload_diversity',
            'f19_is_sd',
        ],
    },
    'MITM_Multi': {
        'model': ROOT / 'mitm'        / 'model' / 'mitm_classifier.json',
        'norm':  ROOT / 'mitm'        / 'model' / 'norm_params.json',
        'feat_cols': [
            'f01_ip_time_interval', 'f08_someip_payload_change',
            'f11_ip_length_change', 'f12_tcpudp_length_change',
            'f13_payload_repeat_rate', 'f15_someip_payload_len',
            'f16_tcpudp_len', 'f17_src_packet_rate', 'f18_src_payload_diversity',
            'f19_is_sd', 'f20_src_service_diversity', 'f21_is_relay_service',
        ],
    },
    'MITM_Single': {
        'model': ROOT / 'mitm_single' / 'model' / 'mitm_single_classifier.json',
        'norm':  ROOT / 'mitm_single' / 'model' / 'norm_params.json',
        'feat_cols': [
            'f01_ip_time_interval', 'f08_someip_payload_change',
            'f11_ip_length_change', 'f12_tcpudp_length_change',
            'f13_payload_repeat_rate', 'f15_someip_payload_len',
            'f16_tcpudp_len', 'f17_src_packet_rate', 'f18_src_payload_diversity',
            'f19_is_sd', 'f20_src_service_diversity', 'f21_is_relay_service',
        ],
    },
}

ALL_FEAT_COLS = [
    'f01_ip_time_interval', 'f08_someip_payload_change',
    'f11_ip_length_change', 'f12_tcpudp_length_change',
    'f13_payload_repeat_rate', 'f15_someip_payload_len',
    'f16_tcpudp_len', 'f17_src_packet_rate', 'f18_src_payload_diversity',
    'f19_is_sd', 'f20_src_service_diversity', 'f21_is_relay_service',
]

CHUNK = 500_000


# ── Feature extraction ────────────────────────────────────────────────────────

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


def extract_chunk(df: pd.DataFrame, state: dict) -> pd.DataFrame:
    df = df.sort_values('timestamp').reset_index(drop=True)
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
    pcap  = df['pcap_file'].astype(str).values if 'pcap_file' in df.columns else np.full(n, 'live')
    svc_v = pd.to_numeric(df['service_id'], errors='coerce').values

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

    return pd.DataFrame({
        'src_ip': src_v,
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
    })


# ── Inference helpers ─────────────────────────────────────────────────────────

def normalize(X: np.ndarray, feat_cols: list, norm: dict) -> np.ndarray:
    X = X.copy()
    for j, c in enumerate(feat_cols):
        lo = norm[c]['min']; hi = norm[c]['max']; d = hi - lo
        X[:, j] = np.clip((X[:, j] - lo) / d, 0, 1) if d > 0 else 0.0
    return X


def predict_clf(model, norm_params, feat_cols, feat_df):
    X = feat_df[feat_cols].values.astype(np.float32)
    X = normalize(X, feat_cols, norm_params)
    return model.predict_proba(X)[:, 1]


# ── Main ──────────────────────────────────────────────────────────────────────

def run(csv_path: Path, threshold: float = 0.5, top_n: int = 20):
    print(f'\n{"="*60}')
    print(f'  IDS SOME/IP — Orquestrador Multi-Ataque')
    print(f'{"="*60}')
    print(f'  Entrada    : {csv_path.name}')
    print(f'  Threshold  : {threshold}')

    # Carrega modelos e norm params
    print('\nCarregando modelos...')
    models = {}
    norms  = {}
    for clf_name, cfg in CLASSIFIERS.items():
        m = xgb.XGBClassifier()
        m.load_model(str(cfg['model']))
        models[clf_name] = m
        with open(cfg['norm']) as f:
            norms[clf_name] = json.load(f)
        print(f'  [{clf_name}] OK')

    # Extracao de features e inferencia por chunk
    print('\nProcessando pacotes...')
    state = make_state()

    ip_scores   = defaultdict(lambda: {k: [] for k in CLASSIFIERS})
    ip_packets  = defaultdict(int)
    n_total     = 0
    t0          = time.time()

    for chunk in pd.read_csv(csv_path, chunksize=CHUNK, low_memory=False):
        feat_df = extract_chunk(chunk, state)

        def _predict(args):
            clf_name, cfg = args
            probs = predict_clf(models[clf_name], norms[clf_name],
                                cfg['feat_cols'], feat_df)
            return clf_name, probs

        with ThreadPoolExecutor(max_workers=4) as ex:
            results = list(ex.map(_predict, CLASSIFIERS.items()))

        for clf_name, probs in results:
            for ip, prob in zip(feat_df['src_ip'], probs):
                ip_scores[ip][clf_name].append(float(prob))

        for ip in feat_df['src_ip']:
            ip_packets[ip] += 1

        n_total += len(chunk)
        print(f'  {n_total:>8,} pacotes  |  {len(ip_scores):>4} IPs unicos  '
              f'({time.time()-t0:.1f}s)')

    elapsed = time.time() - t0
    print(f'\nTotal: {n_total:,} pacotes em {elapsed:.1f}s '
          f'({n_total/elapsed:,.0f} pkt/s)')

    # Agregacao por src_ip: media das probabilidades
    print(f'\n{"="*60}')
    print(f'  RELATORIO DE DETECCAO (threshold={threshold})')
    print(f'{"="*60}')

    rows = []
    for ip, scores in ip_scores.items():
        row = {'src_ip': ip, 'n_packets': ip_packets[ip]}
        detected = []
        for clf_name in CLASSIFIERS:
            avg = float(np.mean(scores[clf_name])) if scores[clf_name] else 0.0
            row[clf_name] = avg
            if avg >= threshold:
                detected.append(clf_name)
        row['detected_as'] = '+'.join(detected) if detected else 'Benigno'
        rows.append(row)

    df_report = pd.DataFrame(rows).sort_values('n_packets', ascending=False)

    # Resumo por tipo de ataque
    attack_ips = df_report[df_report['detected_as'] != 'Benigno']
    print(f'\n  IPs suspeitos: {len(attack_ips)} / {len(df_report)} total\n')

    clf_cols = list(CLASSIFIERS.keys())
    header = f"  {'src_ip':<18} {'pkts':>7}  " + \
             '  '.join(f'{c[:12]:>12}' for c in clf_cols) + \
             f"  {'Deteccao'}"
    print(header)
    print('  ' + '-'*(len(header)-2))

    for _, row in df_report.head(top_n).iterrows():
        flag = '*** ATAQUE ***' if row['detected_as'] != 'Benigno' else ''
        scores_str = '  '.join(f'{row[c]:>12.4f}' for c in clf_cols)
        print(f"  {row['src_ip']:<18} {row['n_packets']:>7,}  {scores_str}"
              f"  {row['detected_as']:<20} {flag}")

    # Tabela completa dos atacantes
    if len(attack_ips) > 0:
        print(f'\n  Atacantes confirmados (score >= {threshold}):')
        for _, row in attack_ips.iterrows():
            print(f"    {row['src_ip']:<18}  {row['detected_as']}  "
                  f"(pkts={row['n_packets']:,})")

    return df_report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='IDS SOME/IP Multi-Ataque Orchestrator')
    parser.add_argument('--csv',       required=True,      help='CSV de entrada (saida do parser)')
    parser.add_argument('--threshold', type=float, default=0.5, help='Limiar de deteccao (0-1)')
    parser.add_argument('--top-n',     type=int,   default=20,  help='Top N IPs no relatorio')
    args = parser.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f'ERRO: {csv_path} nao encontrado.')
        sys.exit(1)

    run(csv_path, threshold=args.threshold, top_n=args.top_n)
