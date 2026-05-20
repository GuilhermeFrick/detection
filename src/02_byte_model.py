"""
ByteDistributionModel e hamming_distance — Kim et al. (2026) Eq. 2-7.
Importado por 03_features.py e qualquer script que precise dos modelos.
"""
import numpy as np
import pandas as pd


class ByteDistributionModel:
    """Distribuição de bytes por posição aprendida sobre tráfego benigno.

    Implementa as Equações 2-6 de Kim et al. (2026) com Laplace smoothing.
    Valor de log-likelihood mais negativo → payload mais anômalo.
    """

    def __init__(self, alpha: float = 1.0, max_positions: int = 256):
        self.alpha         = alpha
        self.max_positions = max_positions
        self._log_probs    = None   # (max_positions, 256) após fit

    def fit(self, payloads_hex: pd.Series) -> None:
        counts = np.zeros((self.max_positions, 256), dtype=np.float64)
        for h in payloads_hex.dropna():
            try:
                raw = bytes.fromhex(str(h))
            except ValueError:
                continue
            for i, b in enumerate(raw[:self.max_positions]):
                counts[i, b] += 1
        totals = counts.sum(axis=1, keepdims=True)
        probs  = (counts + self.alpha) / (totals + 256 * self.alpha)
        self._log_probs = np.log(probs + 1e-12)

    def log_likelihood_batch(self, series: pd.Series) -> np.ndarray:
        results = np.zeros(len(series), dtype=np.float64)
        if self._log_probs is None:
            return results
        for i, h in enumerate(series):
            if not isinstance(h, str) or len(h) < 2:
                continue
            try:
                raw = bytes.fromhex(h)
            except ValueError:
                continue
            if not raw:
                continue
            b = np.frombuffer(raw[:self.max_positions], dtype=np.uint8)
            results[i] = self._log_probs[np.arange(len(b)), b].sum()
        return results

    def cross_entropy_batch(self, series: pd.Series) -> np.ndarray:
        results = np.zeros(len(series), dtype=np.float64)
        if self._log_probs is None:
            return results
        for i, h in enumerate(series):
            if not isinstance(h, str) or len(h) < 2:
                continue
            try:
                raw = bytes.fromhex(h)
            except ValueError:
                continue
            L = len(raw)
            if L == 0:
                continue
            b = np.frombuffer(raw[:self.max_positions], dtype=np.uint8)
            results[i] = -self._log_probs[np.arange(len(b)), b].sum() / L
        return results


def hamming_distance(hex_a: str, hex_b: str) -> float:
    """Fração de bits diferentes entre dois payloads hex [0, 1] — Eq. 7."""
    if not isinstance(hex_a, str) or not isinstance(hex_b, str):
        return 0.0
    try:
        raw_a = bytes.fromhex(hex_a)
        raw_b = bytes.fromhex(hex_b)
    except ValueError:
        return 0.0
    L = min(len(raw_a), len(raw_b))
    if L == 0:
        return 0.0
    a = np.frombuffer(raw_a[:L], dtype=np.uint8)
    b = np.frombuffer(raw_b[:L], dtype=np.uint8)
    return float(np.unpackbits(np.bitwise_xor(a, b)).sum()) / (8 * L)
