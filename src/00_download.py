"""
Download dos PCAPs do dataset SOME/IP.

Fontes:
  - Kim et al.      : Figshare (7 PCAPs, ~1.4 GB)
    https://figshare.com/articles/dataset/SOME_IP_traffic_normal_and_abnormal_traffic_/30970450
  - Alkhatib et al. : GitHub SOMEIP_Dataset (9 PCAPs, ~10 MB)
    https://github.com/GuilhermeFrick/SOMEIP_Dataset.git

Todos os PCAPs são colocados em data/raw/.

Uso:
    python src/00_download.py
    python src/00_download.py --check   # só verifica se os arquivos existem
"""
import sys, os, shutil, subprocess, argparse
from pathlib import Path
import requests
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).parent.parent))
from paths import PCAPS_DIR

# ── Kim et al. — Figshare ─────────────────────────────────────────────────────
FIGSHARE_ARTICLE = 30970450
KIM_PCAP_FILES = [
    "benign_traffic.pcap",
    "dos_noti_flood.pcap",
    "fuzzy_sd_offer_rand_noti(1).pcap",
    "fuzzy_sd_offer_rand_noti(2).pcap",
    "fuzzy_sd_offer_rand_noti(3).pcap",
    "mitm_multi_attacker.pcap",
    "mitm_single_attacker.pcap",
]

# ── Alkhatib et al. — GitHub SOMEIP_Dataset ──────────────────────────────────
DATASET_REPO = "https://github.com/GuilhermeFrick/SOMEIP_Dataset.git"
ALKHATIB_PCAP_FILES = [
    "fakeClientID.pcap",
    "fakeClientID2.pcap",
    "eerror.pcap",
    "eevent.pcap",
    "drequest.pcap",
    "dresponse.pcap",
    "deleteRequest_test1.pcap",
    "wrongInterface.pcap",
    "wrongInterface2.pcap",
]

PCAP_FILES = KIM_PCAP_FILES + ALKHATIB_PCAP_FILES


# ── Helpers ───────────────────────────────────────────────────────────────────

def fetch_file_list() -> list[dict]:
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


def clone_alkhatib_pcaps(dest_dir: Path) -> None:
    """Clona SOMEIP_Dataset e copia os PCAPs Alkhatib para dest_dir."""
    needed = [f for f in ALKHATIB_PCAP_FILES if not (dest_dir / f).exists()]
    if not needed:
        print("[OK] PCAPs Alkhatib já existem em data/raw/")
        return

    tmp = dest_dir / "_someip_dataset_tmp"
    if tmp.exists():
        shutil.rmtree(tmp)

    print(f"\nClonando {DATASET_REPO} ...")
    result = subprocess.run(
        ["git", "clone", "--depth=1", DATASET_REPO, str(tmp)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"[ERRO] git clone falhou:\n{result.stderr}")
        print(f"       Clone manual: git clone {DATASET_REPO}")
        shutil.rmtree(tmp, ignore_errors=True)
        sys.exit(1)

    for fname in needed:
        src = tmp / fname
        if src.exists():
            shutil.copy2(src, dest_dir / fname)
            print(f"  [OK] {fname}")
        else:
            print(f"  [AVISO] {fname} não encontrado no repo clonado")

    import stat
    def _rm_readonly(func, path, _):
        os.chmod(path, stat.S_IWRITE)
        func(path)
    shutil.rmtree(tmp, onerror=_rm_readonly)
    print(f"PCAPs Alkhatib copiados para {dest_dir}")


def download_kim_pcaps(dest_dir: Path) -> None:
    """Baixa os PCAPs Kim do Figshare."""
    needed = [f for f in KIM_PCAP_FILES if not (dest_dir / f).exists()]
    if not needed:
        print("[OK] PCAPs Kim já existem em data/raw/")
        return

    print(f"\nBuscando lista de arquivos do Figshare (article {FIGSHARE_ARTICLE})...")
    try:
        files_meta = fetch_file_list()
    except Exception as e:
        print(f"[ERRO] Falha ao contactar API do Figshare: {e}")
        print("       Baixe manualmente em:")
        print(f"       https://figshare.com/articles/dataset/SOME_IP_traffic_normal_and_abnormal_traffic_/{FIGSHARE_ARTICLE}")
        sys.exit(1)

    name_to_url = {m["name"]: m["download_url"] for m in files_meta}
    for fname in needed:
        if fname not in name_to_url:
            print(f"[AVISO] {fname} não encontrado no Figshare — pulando.")
            continue
        print(f"\nBaixando {fname}...")
        download_file(name_to_url[fname], dest_dir / fname, fname)


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


# ── Main ──────────────────────────────────────────────────────────────────────

def main(check_only: bool = False) -> None:
    if check_only:
        sys.exit(0 if check(quiet=False) else 1)

    PCAPS_DIR.mkdir(parents=True, exist_ok=True)

    clone_alkhatib_pcaps(PCAPS_DIR)   # git clone (~10 MB, rápido)
    download_kim_pcaps(PCAPS_DIR)      # Figshare (~1.4 GB, pode demorar)

    print(f"\n{'='*50}")
    print(f"Download concluído. PCAPs em: {PCAPS_DIR}")
    check()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="Apenas verifica se os arquivos existem")
    args = parser.parse_args()
    main(check_only=args.check)
