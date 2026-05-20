# SOME/IP Anomaly Detection

Reproducible XGBoost-based anomaly detection for SOME/IP traffic in Software-Defined Vehicles (SDV).

Reproduces and extends:
> Kim et al. (2026). *XGBoost-Based Anomaly Detection Framework for SOME/IP in In-Vehicle Networks.* Systems, 14(2), 196. https://doi.org/10.3390/systems14020196

---

## Dataset

7 PCAP files from Figshare — downloaded automatically by `src/00_download.py`:

https://figshare.com/articles/dataset/SOME_IP_traffic_normal_and_abnormal_traffic_/30970450

| PCAP | Label | Attacker IP(s) |
|------|-------|----------------|
| `benign_traffic.pcap` | normal | — |
| `dos_noti_flood.pcap` | dos | 172.18.0.11 |
| `fuzzy_sd_offer_rand_noti(1).pcap` | fuzzy | 172.18.0.17 |
| `fuzzy_sd_offer_rand_noti(2).pcap` | fuzzy | 172.18.0.12 |
| `fuzzy_sd_offer_rand_noti(3).pcap` | fuzzy | 172.18.0.12 |
| `mitm_multi_attacker.pcap` | mitm | 172.18.0.14, 172.18.0.15 |
| `mitm_single_attacker.pcap` | mitm | 172.18.0.13 |

---

## Setup

**Requirements**: Python 3.10+, ~10 GB disk space.

```bash
pip install -r requirements.txt
```

---

## Reproduction

Run the pipeline notebook end-to-end:

```
notebooks/pipeline.ipynb
```

Or run the scripts in order:

```bash
# 0. Download PCAPs (~2 GB, 5-30 min depending on connection)
python src/00_download.py

# 1. Parse PCAPs → CSV (~3.5 GB, 30-60 min)
python src/01_parse.py

# 2. Extract 18 features → .npy arrays (~30-60 min)
python src/03_features.py

# 3. Train XGBoost (binary: normal vs attack)
python src/04_train.py --mode binary

# 4. Evaluate
python src/05_evaluate.py --model binary
```

Each script skips its output stage if the output already exists, so re-runs are safe.

---

## Features

### Kim et al. reproduction (f01–f12)

| Feature | Description |
|---------|-------------|
| f01 | IP time interval between consecutive packets in flow |
| f02 | SOME/IP byte-distribution log-likelihood (vs benign model) |
| f03 | SOME/IP-SD byte-distribution log-likelihood |
| f04 | TCP/UDP payload byte-distribution log-likelihood |
| f05 | SOME/IP payload cross-entropy |
| f06 | SOME/IP-SD payload cross-entropy |
| f07 | TCP/UDP payload cross-entropy |
| f08 | SOME/IP payload Hamming distance vs previous packet |
| f09 | SOME/IP-SD payload Hamming distance vs previous |
| f10 | TCP/UDP payload Hamming distance vs previous |
| f11 | IP total length delta vs previous packet |
| f12 | TCP/UDP length delta vs previous packet |

### Extensions (f13–f16)

| Feature | Description |
|---------|-------------|
| f13 | Repeat rate: fraction of last 5 SOME/IP payloads identical to current |
| f14 | Duplicate-source flag: same payload seen from different src_ip |
| f15 | SOME/IP payload length in bytes (actual, not truncated) |
| f16 | TCP/UDP transport length |

### New features (f17–f18)

| Feature | Description | Key insight |
|---------|-------------|-------------|
| f17 | `src_packet_rate`: packets/s from this src_ip over last 1000 packets | DoS/fuzzy attacker: up to 5809 pkt/s; normal hosts: <50 pkt/s |
| f18 | `src_payload_diversity`: unique payloads / total (same window) | Fuzzy attack sends randomised payloads → diversity ≈ 1.0 |

---

## Results

Binary XGBoost (normal vs attack), 50/50 train-test split:

| Metric | Value |
|--------|-------|
| F1-Score | **0.9979** |
| Precision | 0.9970 |
| Recall | 0.9988 |
| AUC-ROC | 0.9999 |

Per-attack-type recall:

| Attack | Recall |
|--------|--------|
| DoS | ~0.9998 |
| Fuzzy | ~0.9991 |
| MITM | ~0.9972 |

### Comparison with Kim et al.

Kim et al. report F1 = 0.98 using 12 features. Direct reproduction with those 12 features yields F1 ≈ 0.84, with fuzzy recall ≈ 0.34. The gap is caused by a **dataset labeling issue**: all packets in the fuzzy PCAPs are labeled "fuzzy", including ~83% background normal traffic. Features f17/f18 resolve this by identifying the flooding attacker via its packet rate.

---

## Directory Structure

```
detection/
├── src/
│   ├── 00_download.py      # Download PCAPs from Figshare
│   ├── 01_parse.py         # PCAP → CSV parser (Scapy)
│   ├── 02_byte_model.py    # ByteDistributionModel (Kim Eq. 2-7)
│   ├── 03_features.py      # Feature extraction (f01–f18)
│   ├── 04_train.py         # XGBoost training
│   └── 05_evaluate.py      # Evaluation + metrics
├── notebooks/
│   └── pipeline.ipynb      # End-to-end notebook
├── results/
│   └── v2_proposed/
│       ├── model_binary.json
│       └── model_multi.json
├── data/                   # gitignored — generated locally
│   ├── raw/                # PCAPs (from Figshare)
│   ├── parsed/             # parsed_packets.csv
│   └── features/           # .npy arrays + split CSVs
├── paths.py                # Centralised path config
├── requirements.txt
└── README.md
```

---

## Caveats

- **f17 (src_packet_rate) does not generalise** to attackers that rotate source IPs or to benign high-rate sources (e.g., video streaming ECUs).
- **Multi-class classification** is not suitable for this dataset: labels are assigned at PCAP level, not packet level, so background traffic in attack PCAPs carries the wrong label.
- **Kim F1 = 0.98** is not directly reproducible; the reported value likely uses a different train/test split or label assignment.

---

## Reference

```bibtex
@article{kim2026xgboost,
  title   = {XGBoost-Based Anomaly Detection Framework for SOME/IP in In-Vehicle Networks},
  author  = {Kim, ...},
  journal = {Systems},
  volume  = {14},
  number  = {2},
  pages   = {196},
  year    = {2026},
  doi     = {10.3390/systems14020196}
}
```
