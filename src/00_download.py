"""
Download dos PCAPs do dataset SOME/IP.

Fonte: Figshare — https://figshare.com/articles/dataset/SOME_IP_traffic_normal_and_abnormal_traffic_/30970450

Os 7 arquivos .pcap são baixados para data/raw/ (~2 GB total).

Uso:
    python src/00_download.py
    python src/00_download.py --check   # só verifica se os arquivos existem
"""
import sys, hashlib, argparse
from pathlib import Path
import requests
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).parent.parent))
from paths import PCAPS_DIR

# IDs dos arquivos no Figshare (article_id=30970450)
# Cada entrada: (nome_local, file_id_figshare)
FIGSHARE_ARTICLE = 30970450
PCAP_FILES = [
    "benign_traffic.pcap",
    "dos_noti_flood.pcap",
    "fuzzy_sd_offer_rand_noti(1).pcap",
    "fuzzy_sd_offer_rand_noti(2).pcap",
    "fuzzy_sd_offer_rand_noti(3).pcap",
    "mitm_multi_attacker.pcap",
    "mitm_single_attacker.pcap",
]


def fetch_file_list() -> list[dict]:
    """Busca a lista de arquivos do artigo via API do Figshare."""
    url = f"https://api.figshare.com/v2/articles/{FIGSHARE_ARTICLE}/files"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()


def download_file(url: str, dest: Path, name: str) -> None:
    resp = requests.get(url, stream=True, timeout=60)
    resp.raise_for_status()
    total = int(resp.headers.get("content-length", 0))
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as f, tqdm(
        total=total, unit="B", unit_scale=True, desc=name, ncols=70
    ) as bar:
        for chunk in resp.iter_content(chunk_size=1 << 20):
            f.write(chunk)
            bar.update(len(chunk))


def check(quiet: bool = False) -> bool:
    missing = [f for f in PCAP_FILES if not (PCAPS_DIR / f).exists()]
    if missing:
        if not quiet:
            print(f"Faltando {len(missing)} arquivo(s):")
            for f in missing:
                print(f"  ✗  {f}")
        return False
    if not quiet:
        print(f"[OK] Todos os {len(PCAP_FILES)} PCAPs estão em {PCAPS_DIR}")
    return True


def main(check_only: bool = False) -> None:
    if check_only:
        sys.exit(0 if check(quiet=False) else 1)

    already = [f for f in PCAP_FILES if (PCAPS_DIR / f).exists()]
    needed  = [f for f in PCAP_FILES if f not in already]

    if not needed:
        print("[OK] Todos os PCAPs já existem em data/raw/")
        return

    print(f"Buscando lista de arquivos do Figshare (article {FIGSHARE_ARTICLE})...")
    try:
        files_meta = fetch_file_list()
    except Exception as e:
        print(f"[ERRO] Falha ao contactar API do Figshare: {e}")
        print("       Baixe manualmente em:")
        print(f"       https://figshare.com/articles/dataset/SOME_IP_traffic_normal_and_abnormal_traffic_/{FIGSHARE_ARTICLE}")
        sys.exit(1)

    name_to_url = {m["name"]: m["download_url"] for m in files_meta}

    PCAPS_DIR.mkdir(parents=True, exist_ok=True)
    for fname in needed:
        if fname not in name_to_url:
            print(f"[AVISO] {fname} não encontrado no Figshare — pulando.")
            continue
        dest = PCAPS_DIR / fname
        print(f"\nBaixando {fname}...")
        download_file(name_to_url[fname], dest, fname)

    print(f"\n{'='*50}")
    print(f"Download concluído. PCAPs em: {PCAPS_DIR}")
    check()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="Apenas verifica se os arquivos existem")
    args = parser.parse_args()
    main(check_only=args.check)
