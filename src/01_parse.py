"""
Parser PCAP → CSV.

Lê os 7 arquivos .pcap de data/raw/ e gera data/parsed/parsed_packets.csv
(~14.2M linhas, ~3.5 GB). Cada linha é um frame TCP/UDP com campos SOME/IP
extraídos e rótulo de ataque por src_ip.

Fonte do dataset:
    https://figshare.com/articles/dataset/SOME_IP_traffic_normal_and_abnormal_traffic_/30970450

Referência:
    Kim et al. (2026). XGBoost-Based Anomaly Detection Framework for SOME/IP
    in In-Vehicle Networks. Systems, 14(2), 196.
    DOI: https://doi.org/10.3390/systems14020196

Uso:
    python src/01_parse.py
    python src/01_parse.py --pcap-dir data/raw --output data/parsed/parsed_packets.csv
"""
import struct, csv, sys, argparse
from pathlib import Path

try:
    from scapy.all import PcapReader, IP, TCP, UDP, Raw
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

sys.path.insert(0, str(Path(__file__).parent.parent))
from paths import PCAPS_DIR, PARSED_CSV

# ── Constantes SOME/IP (AUTOSAR R22-11) ──────────────────────────────────────

SOMEIP_MIN_LEN         = 16
SOMEIP_SD_SERVICE      = 0xFFFF
SOMEIP_VALID_MSG_TYPES = {0x00, 0x01, 0x02, 0x40, 0x41, 0x42, 0x80, 0x81, 0xC0, 0xC1}
SOMEIP_VALID_PROTO_VER = {0x01}

MSG_TYPE_NAMES = {
    0x00: "REQUEST", 0x01: "REQUEST_NO_RETURN", 0x02: "NOTIFICATION",
    0x80: "RESPONSE", 0x81: "ERROR",
}

PCAP_LABEL_MAP = {
    "benign_traffic.pcap":               "normal",
    "dos_noti_flood.pcap":               "dos",
    "fuzzy_sd_offer_rand_noti(1).pcap":  "fuzzy",
    "fuzzy_sd_offer_rand_noti(2).pcap":  "fuzzy",
    "fuzzy_sd_offer_rand_noti(3).pcap":  "fuzzy",
    "mitm_multi_attacker.pcap":          "mitm",
    "mitm_single_attacker.pcap":         "mitm",
}

ATTACKER_IPS_MAP = {
    "benign_traffic.pcap":               set(),
    "dos_noti_flood.pcap":               {"172.18.0.11"},
    "fuzzy_sd_offer_rand_noti(1).pcap":  {"172.18.0.17"},
    "fuzzy_sd_offer_rand_noti(2).pcap":  {"172.18.0.12"},
    "fuzzy_sd_offer_rand_noti(3).pcap":  {"172.18.0.12"},
    "mitm_multi_attacker.pcap":          {"172.18.0.14", "172.18.0.15"},
    "mitm_single_attacker.pcap":         {"172.18.0.13"},
}

COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "ip_proto", "ip_ttl", "ip_len",
    "ip_id", "ip_flags", "transport", "src_port", "dst_port",
    "transport_len", "tcp_seq", "tcp_ack", "tcp_flags",
    "someip_valid", "service_id", "method_id", "someip_len",
    "client_id", "session_id", "proto_ver", "iface_ver",
    "msg_type", "msg_type_name", "return_code", "is_sd",
    "transport_payload_hex", "someip_payload_hex", "someip_payload_len",
    "label", "attack_type", "pcap_file",
]


# ── Funções de parsing ────────────────────────────────────────────────────────

def parse_someip_header(payload_bytes: bytes) -> dict | None:
    if len(payload_bytes) < SOMEIP_MIN_LEN:
        return None
    try:
        service_id, method_id, length = struct.unpack_from(">HHI", payload_bytes, 0)
        client_id, session_id         = struct.unpack_from(">HH",  payload_bytes, 8)
        proto_ver, iface_ver          = struct.unpack_from(">BB",  payload_bytes, 12)
        msg_type, return_code         = struct.unpack_from(">BB",  payload_bytes, 14)
        someip_payload = payload_bytes[SOMEIP_MIN_LEN:]
        return {
            "service_id": service_id, "method_id": method_id, "length": length,
            "client_id": client_id, "session_id": session_id,
            "proto_ver": proto_ver, "iface_ver": iface_ver,
            "msg_type": msg_type, "return_code": return_code,
            "msg_type_name": MSG_TYPE_NAMES.get(msg_type, f"0x{msg_type:02X}"),
            "is_sd": service_id == SOMEIP_SD_SERVICE,
            "payload_bytes": someip_payload,
            "someip_payload_hex": someip_payload[:64].hex(),
        }
    except struct.error:
        return None


def is_valid_someip(raw_payload: bytes) -> bool:
    if len(raw_payload) < SOMEIP_MIN_LEN:
        return False
    try:
        length    = struct.unpack_from(">I", raw_payload, 4)[0]
        proto_ver = raw_payload[12]
        msg_type  = raw_payload[14]
    except (struct.error, IndexError):
        return False
    return (proto_ver in SOMEIP_VALID_PROTO_VER
            and msg_type in SOMEIP_VALID_MSG_TYPES
            and length >= 8)


def _extract_transport(pkt) -> tuple[dict, bytes | None]:
    """Extrai campos da camada TCP/UDP. Retorna (campos, raw_payload) ou ({}, None) se não for TCP/UDP."""
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        raw = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else None
        return ({"transport": "TCP", "src_port": tcp.sport, "dst_port": tcp.dport,
                 "transport_len": len(tcp), "tcp_seq": tcp.seq,
                 "tcp_ack": tcp.ack, "tcp_flags": int(tcp.flags)}, raw)
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        raw = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else None
        return ({"transport": "UDP", "src_port": udp.sport, "dst_port": udp.dport,
                 "transport_len": udp.len}, raw)
    return {}, None


def _extract_someip(raw_payload: bytes) -> dict:
    """Tenta parsear SOME/IP do payload. Retorna campos ou dict vazio."""
    if not raw_payload or not is_valid_someip(raw_payload):
        return {}
    sh = parse_someip_header(raw_payload)
    if not sh:
        return {}
    return {
        "someip_valid": True, "service_id": sh["service_id"],
        "method_id": sh["method_id"], "someip_len": sh["length"],
        "client_id": sh["client_id"], "session_id": sh["session_id"],
        "proto_ver": sh["proto_ver"], "iface_ver": sh["iface_ver"],
        "msg_type": sh["msg_type"], "msg_type_name": sh["msg_type_name"],
        "return_code": sh["return_code"], "is_sd": sh["is_sd"],
        "someip_payload_hex": sh["someip_payload_hex"],
        "someip_payload_len": len(sh["payload_bytes"]),
    }


def parse_packet(pkt, attack_type: str, pcap_file: str, attacker_ips: set) -> dict | None:
    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]
    transport_fields, raw_payload = _extract_transport(pkt)
    if not transport_fields:
        return None   # não é TCP nem UDP

    rec = {
        "timestamp": float(pkt.time), "src_ip": ip.src, "dst_ip": ip.dst,
        "ip_proto": ip.proto, "ip_ttl": ip.ttl, "ip_len": ip.len,
        "ip_id": ip.id, "ip_flags": int(ip.flags),
        "transport": None, "src_port": None, "dst_port": None,
        "transport_len": None, "tcp_seq": None, "tcp_ack": None, "tcp_flags": None,
        "someip_valid": False, "service_id": None, "method_id": None,
        "someip_len": None, "client_id": None, "session_id": None,
        "proto_ver": None, "iface_ver": None, "msg_type": None,
        "msg_type_name": None, "return_code": None, "is_sd": None,
        "transport_payload_hex": None, "someip_payload_hex": None,
        "someip_payload_len": None,
        "label": 1 if ip.src in attacker_ips else 0,
        "attack_type": attack_type, "pcap_file": pcap_file,
    }
    rec.update(transport_fields)
    if raw_payload:
        rec["transport_payload_hex"] = raw_payload[:64].hex()
        rec.update(_extract_someip(raw_payload))
    return rec


def process_all_pcaps(pcap_dir: Path, output_csv: Path) -> None:
    if not SCAPY_OK:
        raise RuntimeError("scapy é necessário: pip install scapy")
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    total_pkts = total_written = 0
    with open(output_csv, "w", newline="", encoding="utf-8") as fout:
        writer = csv.DictWriter(fout, fieldnames=COLUMNS)
        writer.writeheader()
        for pcap_name, attack_type in PCAP_LABEL_MAP.items():
            pcap_path = pcap_dir / pcap_name
            if not pcap_path.exists():
                print(f"  [PULANDO] {pcap_path} não encontrado")
                continue
            attacker_ips = ATTACKER_IPS_MAP.get(pcap_name, set())
            print(f"\n[>>] {pcap_name}  tipo={attack_type}")
            n_pkts = n_written = n_attack = 0
            try:
                with PcapReader(str(pcap_path)) as reader:
                    for pkt in reader:
                        n_pkts += 1
                        rec = parse_packet(pkt, attack_type, pcap_name, attacker_ips)
                        if rec:
                            writer.writerow({c: rec.get(c) for c in COLUMNS})
                            n_written += 1
                            if rec["label"] == 1:
                                n_attack += 1
                        if n_pkts % 100_000 == 0:
                            print(f"  ... {n_pkts:,} pkts | {n_written:,} escritos"
                                  f" | {n_attack:,} ataque")
            except Exception as e:
                print(f"  [ERRO] {e}")
                continue
            total_pkts   += n_pkts
            total_written += n_written
            print(f"  {pcap_name}: {n_pkts:,} pkts → {n_written:,} escritos"
                  f" ({100*n_attack/max(n_written,1):.1f}% ataque)")
    print(f"\nConcluído: {total_pkts:,} pkts → {total_written:,} linhas → {output_csv}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir", default=str(PCAPS_DIR))
    ap.add_argument("--output",   default=str(PARSED_CSV))
    args = ap.parse_args()

    out = Path(args.output)
    if out.exists():
        print(f"[OK] {out} já existe ({out.stat().st_size/1e9:.2f} GB) — apague para re-parsear.")
        sys.exit(0)

    process_all_pcaps(Path(args.pcap_dir), out)
