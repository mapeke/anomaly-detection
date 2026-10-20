"""Загрузка NF-UNSW-NB15-v3 (UQ, doi:10.48610/6E0EDA1) — parquet-зеркало на Hugging Face."""
from pathlib import Path
from urllib.request import urlretrieve

BASE = "https://huggingface.co/datasets/keys-i/netFlow/resolve/main/"
FILES = {"data/NF-UNSW-NB15-v3.parquet": "NF-UNSW-NB15-v3.parquet",
         "metadata/NetFlow_v3_Features.csv": "NetFlow_v3_Features.csv"}

out = Path(__file__).resolve().parents[1] / "data" / "raw"
out.mkdir(parents=True, exist_ok=True)
for remote, local in FILES.items():
    dst = out / local
    if not dst.exists():
        print("download", remote)
        urlretrieve(BASE + remote, dst)
    print(dst, dst.stat().st_size, "bytes")
