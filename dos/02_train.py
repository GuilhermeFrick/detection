"""
Treinamento do classificador DoS SOME/IP.

Carrega os arrays .npy gerados por 01_features.py e treina um XGBoost binario
(benigno=0 vs DoS=1). Salva o modelo em dos/model/dos_classifier.json.

Uso:
    python dos/02_train.py
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
]


def load():
    print('Carregando dados...')
    X_train = np.load(DATA_DIR / 'X_train.npy')
    y_train = np.load(DATA_DIR / 'y_train.npy').astype(int)
    X_test  = np.load(DATA_DIR / 'X_test.npy')
    y_test  = np.load(DATA_DIR / 'y_test.npy').astype(int)
    print(f'  Treino : {X_train.shape}  (benigno={( y_train==0).sum():,}  dos={(y_train==1).sum():,})')
    print(f'  Teste  : {X_test.shape}   (benigno={(y_test==0).sum():,}   dos={(y_test==1).sum():,})')
    return X_train, y_train, X_test, y_test


def train(X_train, y_train, X_test, y_test):
    print('\nTreinando XGBoost...')
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.3,
        subsample=1.0,
        colsample_bytree=1.0,
        tree_method='hist',
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1,
    )
    t0 = time.time()
    model.fit(X_train, y_train, verbose=False)
    print(f'  Treino concluido em {time.time()-t0:.1f}s')

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    cm     = confusion_matrix(y_test, y_pred)

    print('\n' + '='*50)
    print('  RESULTADOS — DoS vs Benigno')
    print('='*50)
    print(f'  Acuracia  : {accuracy_score(y_test, y_pred):.4f}')
    print(f'  Precision : {precision_score(y_test, y_pred, zero_division=0):.4f}')
    print(f'  Recall    : {recall_score(y_test, y_pred, zero_division=0):.4f}')
    print(f'  F1-Score  : {f1_score(y_test, y_pred, zero_division=0):.4f}')
    print(f'  AUC-ROC   : {roc_auc_score(y_test, y_prob):.4f}')
    print(f'\n  TN={cm[0,0]:>9,}  FP={cm[0,1]:>7,}')
    print(f'  FN={cm[1,0]:>9,}  TP={cm[1,1]:>7,}')

    print('\n  Importancia das features:')
    pairs = sorted(zip(FEAT_COLS, model.feature_importances_), key=lambda x: -x[1])
    for name, imp in pairs:
        bar = '#' * int(imp * 50)
        print(f'  {name:<30}  {imp:.4f}  {bar}')

    path = MODEL_DIR / 'dos_classifier.json'
    model.save_model(str(path))
    print(f'\n  Modelo salvo em {path}')
    return model


if __name__ == '__main__':
    X_train, y_train, X_test, y_test = load()
    train(X_train, y_train, X_test, y_test)
