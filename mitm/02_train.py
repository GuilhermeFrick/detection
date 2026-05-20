"""
Treinamento do classificador MITM SOME/IP.

Uso:
    python mitm/02_train.py
"""
import sys, time
import numpy as np
from pathlib import Path
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
)

DATA_DIR  = Path(__file__).parent / 'data'
MODEL_DIR = Path(__file__).parent / 'model'
MODEL_DIR.mkdir(exist_ok=True)

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


if __name__ == '__main__':
    print('Carregando dados...')
    X_train = np.load(DATA_DIR / 'X_train.npy')
    y_train = np.load(DATA_DIR / 'y_train.npy').astype(int)
    X_test  = np.load(DATA_DIR / 'X_test.npy')
    y_test  = np.load(DATA_DIR / 'y_test.npy').astype(int)
    print(f'  Treino : {X_train.shape}  (benigno={(y_train==0).sum():,}  mitm={(y_train==1).sum():,})')
    print(f'  Teste  : {X_test.shape}   (benigno={(y_test==0).sum():,}   mitm={(y_test==1).sum():,})')

    print('\nTreinando XGBoost...')
    model = xgb.XGBClassifier(
        n_estimators=100, max_depth=6, learning_rate=0.3,
        subsample=1.0, colsample_bytree=1.0,
        tree_method='hist', eval_metric='logloss',
        random_state=42, n_jobs=-1,
    )
    t0 = time.time()
    model.fit(X_train, y_train, verbose=False)
    print(f'  Concluido em {time.time()-t0:.1f}s')

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    cm     = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print('\n' + '='*50)
    print('  RESULTADOS -- MITM vs Benigno')
    print('='*50)
    print(f'  Acuracia  : {accuracy_score(y_test, y_pred):.4f}')
    print(f'  Precision : {precision_score(y_test, y_pred, zero_division=0):.4f}')
    print(f'  Recall    : {recall_score(y_test, y_pred, zero_division=0):.4f}')
    print(f'  F1-Score  : {f1_score(y_test, y_pred, zero_division=0):.4f}')
    print(f'  AUC-ROC   : {roc_auc_score(y_test, y_prob):.4f}')
    print(f'\n  TN={tn:>9,}  FP={fp:>7,}')
    print(f'  FN={fn:>9,}  TP={tp:>7,}')

    print('\n  Importancia das features:')
    pairs = sorted(zip(FEAT_COLS, model.feature_importances_), key=lambda x: -x[1])
    for name, imp in pairs:
        bar = '#' * int(imp * 50)
        print(f'  {name:<32}  {imp:.4f}  {bar}')

    path = MODEL_DIR / 'mitm_classifier.json'
    model.save_model(str(path))
    print(f'\n  Modelo salvo em {path}')
