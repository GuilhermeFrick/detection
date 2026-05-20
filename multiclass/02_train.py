"""
Treinamento do classificador multi-classe SOME/IP.

6 classes: 0=Benigno, 1=DoS, 2=Fuzzy, 3=MITM_Multi, 4=MITM_Single, 5=FakeClientID
Algoritmo: XGBoost multi:softprob

Uso:
    python multiclass/02_train.py
"""
import sys, time, json
import numpy as np
from pathlib import Path
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, roc_auc_score,
)
import pandas as pd

DATA_DIR  = Path(__file__).parent / 'data'
MODEL_DIR = Path(__file__).parent / 'model'
MODEL_DIR.mkdir(exist_ok=True)

CLASS_NAMES = ['Benigno', 'DoS', 'Fuzzy', 'MITM_Multi', 'MITM_Single', 'FakeClientID']
N_CLASSES   = 6

FEAT_COLS = [
    'f01_ip_time_interval', 'f08_someip_payload_change',
    'f11_ip_length_change', 'f12_tcpudp_length_change',
    'f13_payload_repeat_rate', 'f15_someip_payload_len',
    'f16_tcpudp_len', 'f17_src_packet_rate', 'f18_src_payload_diversity',
    'f19_is_sd', 'f20_src_service_diversity', 'f21_is_relay_service',
    'f22_src_clientid_diversity',
]

OVR_F1 = {
    'DoS':         0.9998,
    'Fuzzy':       0.9990,
    'MITM_Multi':  0.9979,
    'MITM_Single': 0.9994,
}


if __name__ == '__main__':
    print('Carregando dados...')
    X_train = np.load(DATA_DIR / 'X_train.npy')
    y_train = np.load(DATA_DIR / 'y_train.npy').astype(int)
    X_test  = np.load(DATA_DIR / 'X_test.npy')
    y_test  = np.load(DATA_DIR / 'y_test.npy').astype(int)

    print(f'  Treino : {X_train.shape}')
    for i, name in enumerate(CLASS_NAMES):
        print(f'    {name:<15}: {(y_train==i).sum():>8,}')
    print(f'  Teste  : {X_test.shape}')

    print('\nTreinando XGBoost multi-classe...')
    model = xgb.XGBClassifier(
        objective='multi:softprob',
        num_class=N_CLASSES,
        n_estimators=200,
        max_depth=6,
        learning_rate=0.2,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method='hist',
        eval_metric='mlogloss',
        random_state=42,
        n_jobs=-1,
    )
    # Balanced weighting with ratio capped at 100x to avoid FakeClientID
    # becoming the default prediction due to extreme class imbalance (~700x raw).
    counts = pd.Series(y_train).value_counts().to_dict()
    n_total = len(y_train)
    raw_w = {cls: n_total / (N_CLASSES * cnt) for cls, cnt in counts.items()}
    min_w = min(raw_w.values())
    capped_w = {cls: min(w, min_w * 100.0) for cls, w in raw_w.items()}
    weights = np.array([capped_w[v] for v in y_train], dtype=float)
    t0 = time.time()
    model.fit(X_train, y_train, sample_weight=weights, verbose=False)
    t_train = time.time() - t0
    print(f'  Concluido em {t_train:.1f}s')

    # Inferencia
    t0 = time.perf_counter()
    y_pred = model.predict(X_test)
    t_batch = time.perf_counter() - t0
    y_prob  = model.predict_proba(X_test)

    # Latencia por pacote
    single = X_test[:1]
    _ = model.predict(single)
    t0 = time.perf_counter()
    for _ in range(1000):
        model.predict(single)
    t_single_ms = (time.perf_counter() - t0) / 1000 * 1000

    acc = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average='macro', zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, average='weighted', zero_division=0)

    print('\n' + '='*60)
    print('  RESULTADOS -- Classificador Multi-Classe')
    print('='*60)
    print(f'  Acuracia global  : {acc:.4f}')
    print(f'  F1 macro         : {f1_macro:.4f}')
    print(f'  F1 weighted      : {f1_weighted:.4f}')
    print(f'  Tempo treino     : {t_train:.1f}s')
    print(f'  Latencia/pacote  : {t_single_ms:.3f} ms')
    print(f'  Throughput       : {len(X_test)/t_batch:,.0f} pkt/s')

    print('\n  Por classe:')
    f1_per_class = f1_score(y_test, y_pred, average=None, zero_division=0)
    print(f'  {"Classe":<15}  {"F1 Multi":>10}  {"F1 OvR":>10}  {"Delta":>8}  {"N Teste":>10}')
    print('  ' + '-'*60)
    for i, name in enumerate(CLASS_NAMES):
        ovr = OVR_F1.get(name, None)
        delta = f'{f1_per_class[i] - ovr:+.4f}' if ovr else '  N/A   '
        ovr_s = f'{ovr:.4f}' if ovr else '   N/A'
        n_test = (y_test == i).sum()
        print(f'  {name:<15}  {f1_per_class[i]:>10.4f}  {ovr_s:>10}  {delta:>8}  {n_test:>10,}')

    print('\n  Matriz de Confusao:')
    cm = confusion_matrix(y_test, y_pred)
    header = '  ' + ' '.join(f'{n[:8]:>9}' for n in CLASS_NAMES)
    print(header)
    for i, row in enumerate(cm):
        vals = ' '.join(f'{v:>9,}' for v in row)
        print(f'  {CLASS_NAMES[i]:<10}  {vals}')

    print('\n  Importancia das features:')
    pairs = sorted(zip(FEAT_COLS, model.feature_importances_), key=lambda x: -x[1])
    for name, imp in pairs:
        bar = '#' * int(imp * 40)
        print(f'  {name:<32}  {imp:.4f}  {bar}')

    # Salvar modelo e resultados
    path = MODEL_DIR / 'multiclass_classifier.json'
    model.save_model(str(path))

    results = {
        'accuracy': float(acc),
        'f1_macro': float(f1_macro),
        'f1_weighted': float(f1_weighted),
        'f1_per_class': {name: float(f1_per_class[i]) for i, name in enumerate(CLASS_NAMES)},
        'ovr_f1': OVR_F1,
        't_train_s': float(t_train),
        't_single_ms': float(t_single_ms),
        'throughput_pkt_s': float(len(X_test)/t_batch),
        'confusion_matrix': cm.tolist(),
    }
    with open(MODEL_DIR / 'results.json', 'w') as f:
        json.dump(results, f, indent=2)

    print(f'\n  Modelo salvo em {path}')
    print(f'  Resultados em   {MODEL_DIR}/results.json')
