"""
Treinamento do classificador FakeClientID SOME/IP.

Carrega os arrays .npy gerados por 01_features.py e treina um XGBoost binario
(benigno=0 vs FakeClientID=1). Os labels originais usam 0/5; este script remapeia
5->1 internamente para o XGBoost e restaura na reportagem.

Uso:
    python fake_client_id/02_train.py
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
    'f22_src_clientid_diversity',
]


def load():
    print('Carregando dados...')
    X_train = np.load(DATA_DIR / 'X_train.npy')
    y_train = np.load(DATA_DIR / 'y_train.npy').astype(int)
    X_test  = np.load(DATA_DIR / 'X_test.npy')
    y_test  = np.load(DATA_DIR / 'y_test.npy').astype(int)
    # Remap: 5 -> 1 (XGBoost precisa de 0/1 para binario)
    y_train_bin = (y_train == 5).astype(int)
    y_test_bin  = (y_test  == 5).astype(int)
    n_ben_tr = (y_train_bin == 0).sum()
    n_atk_tr = (y_train_bin == 1).sum()
    n_ben_te = (y_test_bin  == 0).sum()
    n_atk_te = (y_test_bin  == 1).sum()
    print(f'  Treino : {X_train.shape}  (benigno={n_ben_tr:,}  fakeclientid={n_atk_tr:,})')
    print(f'  Teste  : {X_test.shape}   (benigno={n_ben_te:,}   fakeclientid={n_atk_te:,})')
    return X_train, y_train_bin, X_test, y_test_bin


def train(X_train, y_train, X_test, y_test):
    scale_pos = int((y_train == 0).sum()) / max(int((y_train == 1).sum()), 1)
    print(f'\nTreinando XGBoost (scale_pos_weight={scale_pos:.1f})...')
    model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos,
        tree_method='hist',
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1,
    )
    t0 = time.time()
    model.fit(X_train, y_train, verbose=False)
    print(f'  Concluido em {time.time()-t0:.1f}s')

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    cm     = confusion_matrix(y_test, y_pred)

    print('\n' + '='*50)
    print('  RESULTADOS — FakeClientID vs Benigno')
    print('='*50)
    print(f'  Acuracia  : {accuracy_score(y_test, y_pred):.4f}')
    print(f'  Precision : {precision_score(y_test, y_pred, zero_division=0):.4f}')
    print(f'  Recall    : {recall_score(y_test, y_pred, zero_division=0):.4f}')
    print(f'  F1-Score  : {f1_score(y_test, y_pred, zero_division=0):.4f}')
    print(f'  AUC-ROC   : {roc_auc_score(y_test, y_prob):.4f}')
    print(f'\n  TN={cm[0,0]:>7,}  FP={cm[0,1]:>5,}')
    print(f'  FN={cm[1,0]:>7,}  TP={cm[1,1]:>5,}')

    print('\n  Importancia das features:')
    pairs = sorted(zip(FEAT_COLS, model.feature_importances_), key=lambda x: -x[1])
    max_imp = pairs[0][1] if pairs else 1.0
    for name, imp in pairs:
        bar = '#' * int(imp / max_imp * 46)
        print(f'  {name:<35}  {imp:.4f}  {bar}')

    path = MODEL_DIR / 'fakeclientid_classifier.json'
    model.save_model(str(path))
    print(f'\n  Modelo salvo em {path}')
    return model


if __name__ == '__main__':
    X_train, y_train, X_test, y_test = load()
    train(X_train, y_train, X_test, y_test)
