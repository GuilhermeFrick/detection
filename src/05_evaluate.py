"""
Avaliação comparativa — Kim baseline vs modelo proposto.

Carrega modelos salvos em results/ e gera tabela comparativa por tipo de ataque.

Uso:
    python src/05_evaluate.py --model binary     # avalia model_binary.json
    python src/05_evaluate.py --model multi      # avalia model_multi.json
    python src/05_evaluate.py --model both       # ambos lado a lado
"""
import sys, argparse
import numpy as np
import pandas as pd
from pathlib import Path
import xgboost as xgb
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).parent.parent))
from paths import FEATURES_DIR, RESULTS_V2

CLASSES   = ['normal', 'dos', 'fuzzy', 'mitm']
CLASS2IDX = {c: i for i, c in enumerate(CLASSES)}
CHUNK     = 500_000

FEAT_COLS = [
    'f01_ip_time_interval', 'f02_someip_likelihood', 'f03_someipsd_likelihood',
    'f04_tcpudp_likelihood', 'f05_someip_entropy', 'f06_someipsd_entropy',
    'f07_tcpudp_entropy', 'f08_someip_payload_changes', 'f09_someipsd_payload_changes',
    'f10_tcpudp_payload_changes', 'f11_ip_length_changes', 'f12_tcpudp_length_changes',
    'f13_payload_repeat_rate', 'f14_duplicate_source',
    'f15_someip_payload_length', 'f16_tcpudp_payload_length',
    'f17_src_packet_rate', 'f18_src_payload_diversity',
]


def load_test_data():
    X_test      = np.load(FEATURES_DIR / 'X_test.npy')
    y_test      = np.load(FEATURES_DIR / 'y_test.npy').astype(int)
    attack_type = np.concatenate([
        c['attack_type'].values
        for c in pd.read_csv(FEATURES_DIR / 'test_features.csv',
                             usecols=['attack_type'], chunksize=CHUNK)
    ])
    return X_test, y_test, attack_type


def eval_binary(X_test, y_test, attack_type):
    path = RESULTS_V2 / 'model_binary.json'
    if not path.exists():
        print(f'[SKIP] {path} não encontrado — rode 04_train.py --mode binary primeiro.')
        return

    model  = xgb.XGBClassifier()
    model.load_model(str(path))
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print('\n' + '='*65)
    print('  BINÁRIO — resultados globais')
    print('='*65)
    print(f'  Acuracia  : {accuracy_score(y_test, y_pred):.4f}')
    print(f'  Precision : {precision_score(y_test, y_pred, zero_division=0):.4f}')
    print(f'  Recall    : {recall_score(y_test, y_pred, zero_division=0):.4f}')
    print(f'  F1-Score  : {f1_score(y_test, y_pred, zero_division=0):.4f}')
    print(f'  AUC-ROC   : {roc_auc_score(y_test, y_prob):.4f}')

    print(f'\n  {"Tipo":<10}  {"Total":>9}  {"TP":>8}  {"FN":>8}  {"Recall":>8}')
    print(f'  {"-"*55}')
    for at in CLASSES:
        mask = (attack_type == at)
        if not mask.any():
            continue
        yt = y_test[mask]; yp = y_pred[mask]
        if at == 'normal':
            fp = (yp == 1).sum()
            print(f'  {at:<10}  {mask.sum():>9,}  {"—":>8}  {"—":>8}  {"—":>8}  FP={fp:,}')
        else:
            tp = ((yt==1)&(yp==1)).sum(); fn = ((yt==1)&(yp==0)).sum()
            rc = tp/(tp+fn) if (tp+fn)>0 else 0.0
            print(f'  {at:<10}  {mask.sum():>9,}  {tp:>8,}  {fn:>8,}  {rc:>8.4f}')

    _print_importances(model, 'Binário')


def eval_multi(X_test, y_test, attack_type):
    path = RESULTS_V2 / 'model_multi.json'
    if not path.exists():
        print(f'[SKIP] {path} não encontrado — rode 04_train.py --mode multi primeiro.')
        return

    model  = xgb.XGBClassifier()
    model.load_model(str(path))
    y_pred  = model.predict(X_test)
    y_true  = np.array([CLASS2IDX.get(t, 0) for t in attack_type])

    print('\n' + '='*65)
    print('  MULTI-CLASSE — recall e precision por tipo')
    print('='*65)
    print(f'  {"Tipo":<10}  {"Total":>9}  {"TP":>8}  {"FN":>8}  {"Recall":>8}  {"Precision":>10}')
    print(f'  {"-"*65}')
    for idx, cls in enumerate(CLASSES):
        n_tot  = (y_true == idx).sum()
        n_tp   = ((y_true==idx) & (y_pred==idx)).sum()
        n_fn   = ((y_true==idx) & (y_pred!=idx)).sum()
        n_fp   = ((y_true!=idx) & (y_pred==idx)).sum()
        rec_c  = n_tp/(n_tp+n_fn) if (n_tp+n_fn)>0 else 0.0
        prec_c = n_tp/(n_tp+n_fp) if (n_tp+n_fp)>0 else 0.0
        print(f'  {cls:<10}  {n_tot:>9,}  {n_tp:>8,}  {n_fn:>8,}  {rec_c:>8.4f}  {prec_c:>10.4f}')

    _print_importances(model, 'Multi-classe')


def _print_importances(model, label):
    n_feat = len(model.feature_importances_)
    cols   = FEAT_COLS[:n_feat]
    print(f'\n  Importância das features ({label}):')
    for name, imp in sorted(zip(cols, model.feature_importances_), key=lambda x: -x[1])[:10]:
        bar = '#' * int(imp * 40)
        print(f'  {name:<35}  {imp:.4f}  {bar}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', choices=['binary','multi','both'], default='both')
    args = parser.parse_args()

    X_test, y_test, attack_type = load_test_data()

    if args.model in ('binary', 'both'):
        eval_binary(X_test, y_test, attack_type)

    if args.model in ('multi', 'both'):
        eval_multi(X_test, y_test, attack_type)
