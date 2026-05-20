"""
Incorpora a classe FakeClientID ao dataset multiclasse existente.

Lê o features.csv de 5 classes (já extraído por 01_features.py),
adiciona f22_src_clientid_diversity=1.0 para todas as linhas, e appenda
os pacotes de ataque FakeClientID (label=5) extraídos por
fake_client_id/01_features.py.

Recomputa norm_params, normaliza e re-salva X/y train/test com 6 classes
e 13 features.

Uso:
    python multiclass/01b_merge_fakeclientid.py
"""
import json, time
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split

ROOT       = Path(__file__).parent.parent
DATA_DIR   = Path(__file__).parent / 'data'
MODEL_DIR  = Path(__file__).parent / 'model'
FCI_CSV    = ROOT / 'fake_client_id' / 'data' / 'features.csv'
FEAT_CSV   = DATA_DIR / 'features.csv'
RAND_STATE = 42
CHUNK      = 500_000

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

CLASS_NAMES = {0: 'Benigno', 1: 'DoS', 2: 'Fuzzy',
               3: 'MITM_Multi', 4: 'MITM_Single', 5: 'FakeClientID'}


def main():
    for p in [FEAT_CSV, FCI_CSV]:
        if not p.exists():
            raise FileNotFoundError(f'Não encontrado: {p}')

    # ── 1. Carregar FakeClientID — ataques (label=5) + benignos do PCAP real ─
    # Os benignos do PCAP real (label=0) têm f13≈0 e f17≈0, preenchendo a
    # região do espaço de features vazia na simulação. Sem eles, o modelo
    # associa f13≈0 exclusivamente a FakeClientID e vira o classificador padrão.
    print('Carregando FakeClientID features...')
    fci = pd.read_csv(FCI_CSV)
    fci_atk = fci[fci['label'] == 5].copy()
    fci_ben = fci[fci['label'] == 0].copy()   # Benignos do PCAP real
    print(f'  FakeClientID (label=5): {len(fci_atk):,} amostras')
    print(f'  Benigno PCAP real (label=0): {len(fci_ben):,} amostras')

    # ── 2. Ler features.csv existente em chunks e calcular norm_params ─────
    print('\nCalculando norm_params combinados (pode demorar ~30s)...')
    t0   = time.time()
    norm = {c: {'min': float('inf'), 'max': float('-inf')} for c in FEAT_COLS}

    # f22 nos dados existentes é sempre 1.0 (nenhum IP existente rotaciona client_ids)
    norm['f22_src_clientid_diversity']['min'] = 1.0

    for chunk in pd.read_csv(FEAT_CSV, usecols=[c for c in FEAT_COLS if c != 'f22_src_clientid_diversity'],
                             chunksize=CHUNK):
        for c in FEAT_COLS[:-1]:
            norm[c]['min'] = min(norm[c]['min'], float(chunk[c].min()))
            norm[c]['max'] = max(norm[c]['max'], float(chunk[c].max()))

    # Incorporar range do FakeClientID em todas as features
    for c in FEAT_COLS:
        if c in fci_atk.columns:
            norm[c]['min'] = min(norm[c]['min'], float(fci_atk[c].min()))
            norm[c]['max'] = max(norm[c]['max'], float(fci_atk[c].max()))

    print(f'  Concluído em {time.time()-t0:.1f}s')
    print(f'  f22 range: [{norm["f22_src_clientid_diversity"]["min"]}, '
          f'{norm["f22_src_clientid_diversity"]["max"]}]')

    MODEL_DIR.mkdir(exist_ok=True)
    with open(MODEL_DIR / 'norm_params.json', 'w') as f:
        json.dump(norm, f, indent=2)

    # ── 3. Normalizar FakeClientID ─────────────────────────────────────────
    def normalize(df):
        X = df[FEAT_COLS].copy().values.astype(np.float32)
        for j, c in enumerate(FEAT_COLS):
            lo = norm[c]['min']; hi = norm[c]['max']; d = hi - lo
            X[:, j] = np.clip((X[:, j] - lo) / d, 0, 1) if d > 0 else 0.0
        return X

    X_fci = normalize(fci_atk)
    y_fci = fci_atk['label'].values.astype(np.int8)

    # Split FakeClientID 50/50 (espelha split existente)
    fci_idx = np.arange(len(y_fci))
    tr_idx, te_idx = train_test_split(fci_idx, test_size=0.5, random_state=RAND_STATE)
    X_fci_tr, y_fci_tr = X_fci[tr_idx], y_fci[tr_idx]
    X_fci_te, y_fci_te = X_fci[te_idx], y_fci[te_idx]

    # Split Benignos do PCAP real 50/50
    x_ben = normalize(fci_ben)
    y_ben = fci_ben['label'].values.astype(np.int8)
    ben_idx = np.arange(len(y_ben))
    tr_ben, te_ben = train_test_split(ben_idx, test_size=0.5, random_state=RAND_STATE)
    x_ben_tr, y_ben_tr = x_ben[tr_ben], y_ben[tr_ben]
    x_ben_te, y_ben_te = x_ben[te_ben], y_ben[te_ben]

    # ── 4. Ler, normalizar e remontar dados existentes em chunks ───────────
    print('\nNormalizando dados existentes e construindo novos arrays...')
    t0 = time.time()
    X_tr_chunks, y_tr_chunks = [], []
    X_te_chunks, y_te_chunks = [], []

    # Reutilizar o split original (50/50 estratificado) — regeneramos com o mesmo seed
    # Lemos o CSV completo em chunks para obter labels e depois re-split
    all_labels = np.concatenate(
        [c['label'].values for c in pd.read_csv(FEAT_CSV, usecols=['label'], chunksize=CHUNK)]
    )
    n_existing = len(all_labels)
    idx_all    = np.arange(n_existing)
    is_train   = np.zeros(n_existing, dtype=bool)
    tr_e, te_e = train_test_split(idx_all, test_size=0.5, stratify=all_labels,
                                  random_state=RAND_STATE)
    is_train[tr_e] = True

    offset = 0
    for chunk in pd.read_csv(FEAT_CSV, chunksize=CHUNK):
        n = len(chunk)
        chunk['f22_src_clientid_diversity'] = 1.0
        X_chunk = normalize(chunk)
        y_chunk = chunk['label'].values.astype(np.int8)

        mask_tr = is_train[offset: offset + n]
        X_tr_chunks.append(X_chunk[mask_tr])
        y_tr_chunks.append(y_chunk[mask_tr])
        X_te_chunks.append(X_chunk[~mask_tr])
        y_te_chunks.append(y_chunk[~mask_tr])
        offset += n
        if offset % 2_000_000 == 0:
            print(f'  {offset:,} / {n_existing:,}  ({time.time()-t0:.0f}s)')

    print(f'  Concluído em {time.time()-t0:.1f}s')

    # ── 5. Concatenar e salvar ─────────────────────────────────────────────
    X_train = np.vstack(X_tr_chunks + [X_fci_tr, x_ben_tr])
    y_train = np.concatenate(y_tr_chunks + [y_fci_tr, y_ben_tr])
    X_test  = np.vstack(X_te_chunks + [X_fci_te, x_ben_te])
    y_test  = np.concatenate(y_te_chunks + [y_fci_te, y_ben_te])

    np.save(DATA_DIR / 'X_train.npy', X_train)
    np.save(DATA_DIR / 'y_train.npy', y_train)
    np.save(DATA_DIR / 'X_test.npy',  X_test)
    np.save(DATA_DIR / 'y_test.npy',  y_test)

    print(f'\nDataset final:')
    print(f'  Treino : {X_train.shape}')
    print(f'  Teste  : {X_test.shape}')
    print('\nDistribuição treino:')
    for lbl, name in CLASS_NAMES.items():
        n = int((y_train == lbl).sum())
        print(f'  {name:<15}: {n:>10,}')

    print(f'\nArquivos salvos em {DATA_DIR}')
    print(f'norm_params atualizado em {MODEL_DIR}/norm_params.json')


if __name__ == '__main__':
    main()
