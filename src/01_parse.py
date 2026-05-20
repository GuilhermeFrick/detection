"""
Parser PCAP → CSV (um arquivo por PCAP).

Lê os 7 arquivos .pcap de data/raw/ e gera um CSV separado para cada um em
data/parsed/. Cada linha é um frame TCP/UDP com campos SOME/IP extraídos.

Rótulo por pacote (coluna `label`):
    0 = tráfego benigno (qualquer IP não-atacante)
    1 = pacote de ataque (src_ip pertence aos atacantes conhecidos do PCAP)

Isso permite treinar classificadores individuais por tipo de ataque usando
apenas os PCAPs relevantes, com rótulo limpo no nível de pacote.

Uso:
    python src/01_parse.py
    python src/01_parse.py --pcap-dir data/raw --output-dir data/parsed
"""
import re, struct, csv, sys, argparse
from pathlib import Path

try:
    from scapy.all import PcapReader, IP, TCP, UDP, Raw
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

sys.path.insert(0, str(Path(__file__).parent.parent))
from paths import PCAPS_DIR, PARSED_DIR

# ── Constantes SOME/IP (AUTOSAR R22-11) ──────────────────────────────────────

SOMEIP_MIN_LEN         = 16
SOMEIP_SD_SERVICE      = 0xFFFF
SOMEIP_VALID_MSG_TYPES = {0x00, 0x01, 0x02, 0x40, 0x41, 0x42, 0x80, 0x81, 0xC0, 0xC1}
SOMEIP_VALID_PROTO_VER = {0x01}

MSG_TYPE_NAMES = {
    0x00: "REQUEST", 0x01: "REQUEST_NO_RETURN", 0x02: "NOTIFICATION",
    0x80: "RESPONSE", 0x81: "ERROR",
}

# Mapeamento: nome do PCAP → (tipo de ataque, conjunto de IPs atacantes)
PCAP_INFO = {
    "benign_traffic.pcap":               ("normal", set()),
    "dos_noti_flood.pcap":               ("dos",    {"172.18.0.11"}),
    "fuzzy_sd_offer_rand_noti(1).pcap":  ("fuzzy",  {"172.18.0.17"}),
    "fuzzy_sd_offer_rand_noti(2).pcap":  ("fuzzy",  {"172.18.0.12"}),
    "fuzzy_sd_offer_rand_noti(3).pcap":  ("fuzzy",  {"172.18.0.12"}),
    "mitm_multi_attacker.pcap":          ("mitm",   {"172.18.0.14", "172.18.0.15"}),
    "mitm_single_attacker.pcap":         ("mitm",   {"172.18.0.13"}),
}

COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "ip_proto", "ip_ttl", "ip_len",
    "ip_id", "ip_flags", "transport", "src_port", "dst_port",
    "transport_len", "tcp_seq", "tcp_ack", "tcp_flags",
    "someip_valid", "service_id", "method_id", "someip_len",
    "client_id", "session_id", "proto_ver", "iface_ver",
    "msg_type", "msg_type_name", "return_code", "is_sd",
    "transport_payload_hex", "someip_payload_hex", "someip_payload_len",
    "label",        # 0 = benigno, 1 = ataque
    "attack_type",  # normal / dos / fuzzy / mitm
    "pcap_file",
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
        return None

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
        "attack_type": attack_type,
        "pcap_file": pcap_file,
    }
    rec.update(transport_fields)
    if raw_payload:
        rec["transport_payload_hex"] = raw_payload[:64].hex()
        rec.update(_extract_someip(raw_payload))
    return rec


def _csv_name(pcap_name: str) -> str:
    """Converte nome do PCAP em nome de CSV seguro para filesystem."""
    name = re.sub(r'[()]', '', pcap_name)   # remove parênteses
    name = re.sub(r'\s+', '_', name)        # espaços → underscore
    return Path(name).with_suffix('.csv').name


def parse_pcap(pcap_path: Path, output_dir: Path, attack_type: str,
               attacker_ips: set, overwrite: bool = False) -> None:
    out_csv = output_dir / _csv_name(pcap_path.name)
    if out_csv.exists() and not overwrite:
        size_mb = out_csv.stat().st_size / 1e6
        print(f"  [OK] {out_csv.name} já existe ({size_mb:.0f} MB) — pulando.")
        return

    print(f"\n[>>] {pcap_path.name}  tipo={attack_type}  atacantes={attacker_ips or '—'}")
    n_pkts = n_written = n_attack = 0
    with open(out_csv, "w", newline="", encoding="utf-8") as fout:
        writer = csv.DictWriter(fout, fieldnames=COLUMNS)
        writer.writeheader()
        try:
            with PcapReader(str(pcap_path)) as reader:
                for pkt in reader:
                    n_pkts += 1
                    rec = parse_packet(pkt, attack_type, pcap_path.name, attacker_ips)
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
            out_csv.unlink(missing_ok=True)
            return

    pct = 100 * n_attack / max(n_written, 1)
    print(f"  -> {out_csv.name}: {n_written:,} pacotes  "
          f"(benigno={n_written-n_attack:,}  ataque={n_attack:,}  {pct:.1f}%)")


def process_all_pcaps(pcap_dir: Path, output_dir: Path,
                      overwrite: bool = False,
                      only: list[str] | None = None) -> None:
    if not SCAPY_OK:
        raise RuntimeError("scapy é necessário: pip install scapy")
    output_dir.mkdir(parents=True, exist_ok=True)

    for pcap_name, (attack_type, attacker_ips) in PCAP_INFO.items():
        if only and pcap_name not in only:
            continue
        pcap_path = pcap_dir / pcap_name
        if not pcap_path.exists():
            print(f"  [PULANDO] {pcap_path} não encontrado")
            continue
        parse_pcap(pcap_path, output_dir, attack_type, attacker_ips, overwrite)

    print(f"\nConcluído. CSVs em: {output_dir}")
    for f in sorted(output_dir.glob("*.csv")):
        print(f"  {f.name:50s}  {f.stat().st_size/1e6:>8.0f} MB")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir",   default=str(PCAPS_DIR))
    ap.add_argument("--output-dir", default=str(PARSED_DIR))
    ap.add_argument("--overwrite",  action="store_true",
                    help="Re-processa mesmo se o CSV já existir")
    ap.add_argument("--pcaps", nargs="+", metavar="PCAP",
                    help="Processa apenas os PCAPs listados (ex: benign_traffic.pcap dos_noti_flood.pcap)")
    args = ap.parse_args()

    process_all_pcaps(Path(args.pcap_dir), Path(args.output_dir),
                      args.overwrite, args.pcaps)
