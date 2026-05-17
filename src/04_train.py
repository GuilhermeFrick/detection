"""
Treinamento XGBoost — binário e multi-classe.

Modo binário  : reprodução de Kim et al. (2026) — normal vs ataque
Modo multi    : 4 classes — normal / dos / fuzzy / mitm

Uso:
    python src/04_train.py --mode binary    # padrão
    python src/04_train.py --mode multi
    python src/04_train.py --mode both
"""
import sys, time, argparse
import numpy as np
from pathlib import Path
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
)

sys.path.insert(0, str(Path(__file__).parent.parent))
from paths import FEATURES_DIR, RESULTS_V2

RESULTS_V2.mkdir(exist_ok=True)

# Classes para modo multi (ordem fixa → índice)
CLASSES    = ['normal', 'dos', 'fuzzy', 'mitm']
CLASS2IDX  = {c: i for i, c in enumerate(CLASSES)}

FEAT_COLS = [
    'f01_ip_time_interval', 'f02_someip_likelihood', 'f03_someipsd_likelihood',
    'f04_tcpudp_likelihood', 'f05_someip_entropy', 'f06_someipsd_entropy',
    'f07_tcpudp_entropy', 'f08_someip_payload_changes', 'f09_someipsd_payload_changes',
    'f10_tcpudp_payload_changes', 'f11_ip_length_changes', 'f12_tcpudp_length_changes',
    'f13_payload_repeat_rate', 'f14_duplicate_source',
    'f15_someip_payload_length', 'f16_tcpudp_payload_length',
    'f17_src_packet_rate', 'f18_src_payload_diversity',
]

XGB_BASE = dict(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.3,
    subsample=1.0,
    colsample_bytree=1.0,
    random_state=42,
    n_jobs=-1,
    tree_method='hist',
)


def load_data(npy_dir: Path):
    print('Carregando npy...')
    X_train = np.load(npy_dir / 'X_train.npy')
    y_train = np.load(npy_dir / 'y_train.npy').astype(int)
    X_test  = np.load(npy_dir / 'X_test.npy')
    y_test  = np.load(npy_dir / 'y_test.npy').astype(int)
    print(f'  Treino: {X_train.shape}  Teste: {X_test.shape}')
    return X_train, y_train, X_test, y_test


def load_attack_types(npy_dir: Path):
    import pandas as pd
    CHUNK = 500_000
    parts = []
    for chunk in pd.read_csv(npy_dir / 'test_features.csv',
                             usecols=['attack_type'], chunksize=CHUNK):
        parts.append(chunk['attack_type'].values)
    return np.concatenate(parts)


def run_binary(X_train, y_train, X_test, y_test, attack_type):
    print('\n' + '='*60)
    print('  MODO BINÁRIO — normal vs ataque')
    print('='*60)
    params = {**XGB_BASE, 'eval_metric': 'logloss'}
    model = xgb.XGBClassifier(**params)
    t0 = time.time()
    model.fit(X_train, y_train, verbose=False)
    print(f'  Treino em {time.time()-t0:.1f}s')

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    auc  = roc_auc_score(y_test, y_prob)
    cm   = confusion_matrix(y_test, y_pred)

    print(f'  Acuracia  : {acc:.4f}')
    print(f'  Precision : {prec:.4f}')
    print(f'  Recall    : {rec:.4f}')
    print(f'  F1-Score  : {f1:.4f}')
    print(f'  AUC-ROC   : {auc:.4f}')
    print(f'  TN={cm[0,0]:>9,}  FP={cm[0,1]:>7,}')
    print(f'  FN={cm[1,0]:>9,}  TP={cm[1,1]:>7,}')

    _print_recall_by_type(y_test, y_pred, attack_type, model)
    model.save_model(str(RESULTS_V2 / 'model_binary.json'))
    print(f'  Modelo salvo em results/v2_proposed/model_binary.json')
    return model


def run_multi(X_train, y_train_bin, X_test, y_test_bin, attack_type):
    print('\n' + '='*60)
    print('  MODO MULTI-CLASSE — normal / dos / fuzzy / mitm')
    print('='*60)

    # Carrega attack_type do treino para montar y_train multi
    import pandas as pd
    CHUNK = 500_000
    parts = []
    for chunk in pd.read_csv(FEATURES_DIR / 'train_features.csv',
                             usecols=['attack_type'], chunksize=CHUNK):
        parts.append(chunk['attack_type'].values)
    train_at = np.concatenate(parts)
    y_train  = np.array([CLASS2IDX.get(t, 0) for t in train_at])
    y_test   = np.array([CLASS2IDX.get(t, 0) for t in attack_type])

    params = {**XGB_BASE,
              'objective': 'multi:softmax',
              'num_class': len(CLASSES),
              'eval_metric': 'mlogloss'}
    model = xgb.XGBClassifier(**params)
    t0 = time.time()
    model.fit(X_train, y_train, verbose=False)
    print(f'  Treino em {time.time()-t0:.1f}s')

    y_pred = model.predict(X_test)

    print(f'\n  {"Classe":<10}  {"Total":>8}  {"TP":>8}  {"FN":>8}  {"Recall":>8}  {"Precision":>10}')
    print(f'  {"-"*60}')
    for idx, cls in enumerate(CLASSES):
        mask   = (y_test == idx)
        n_tot  = mask.sum()
        n_tp   = ((y_test == idx) & (y_pred == idx)).sum()
        n_fn   = ((y_test == idx) & (y_pred != idx)).sum()
        n_fp   = ((y_test != idx) & (y_pred == idx)).sum()
        rec_c  = n_tp / (n_tp + n_fn) if (n_tp + n_fn) > 0 else 0.0
        prec_c = n_tp / (n_tp + n_fp) if (n_tp + n_fp) > 0 else 0.0
        print(f'  {cls:<10}  {n_tot:>8,}  {n_tp:>8,}  {n_fn:>8,}  {rec_c:>8.4f}  {prec_c:>10.4f}')

    _print_importances(model)
    model.save_model(str(RESULTS_V2 / 'model_multi.json'))
    print(f'  Modelo salvo em results/v2_proposed/model_multi.json')
    return model


def _print_recall_by_type(y_test, y_pred, attack_type, model):
    print(f'\n  {"Tipo":<10}  {"Total":>8}  {"TP":>8}  {"FN":>8}  {"Recall":>8}')
    print(f'  {"-"*50}')
    for at in sorted(set(attack_type)):
        mask = (attack_type == at)
        yt   = y_test[mask]; yp = y_pred[mask]
        if at == 'normal':
            fp = (yp == 1).sum()
            print(f'  {"normal":<10}  {mask.sum():>8,}  {"—":>8}  {"—":>8}  {"—":>8}  FP={fp:,}')
        else:
            tp = ((yt == 1) & (yp == 1)).sum()
            fn = ((yt == 1) & (yp == 0)).sum()
            rc = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            print(f'  {at:<10}  {mask.sum():>8,}  {tp:>8,}  {fn:>8,}  {rc:>8.4f}')
    _print_importances(model)


def _print_importances(model):
    print(f'\n  Importância das features:')
    pairs = sorted(zip(FEAT_COLS, model.feature_importances_), key=lambda x: -x[1])
    for name, imp in pairs:
        bar = '#' * int(imp * 40)
        print(f'  {name:<35}  {imp:.4f}  {bar}')


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['binary','multi','both'], default='both')
    parser.add_argument('--npy',  default=str(FEATURES_DIR))
    args = parser.parse_args()

    npy_dir = Path(args.npy)
    X_train, y_train, X_test, y_test = load_data(npy_dir)
    attack_type = load_attack_types(npy_dir)

    if args.mode in ('binary', 'both'):
        run_binary(X_train, y_train, X_test, y_test, attack_type)

    if args.mode in ('multi', 'both'):
        run_multi(X_train, y_train, X_test, y_test, attack_type)
