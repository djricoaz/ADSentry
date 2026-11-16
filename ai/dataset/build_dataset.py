"""Génère le jeu d'entraînement (JSONL, format chat) pour le modèle analyste.

Deux sources :
1. **Synthétique** : on tire au hasard des combinaisons de règles du catalogue pour fabriquer de
   faux résultats d'audit, et on produit la réponse attendue à partir des textes d'expert du
   catalogue (description, remédiation, détection). Cela apprend au modèle le FORMAT, la
   PRIORISATION et l'ANCRAGE (ne citer que les règles présentes).
2. **Gold** : analyses rédigées ou relues par un humain (ai/dataset/gold/*.json, même format
   {"messages": [...]}) — ce sont elles qui apprennent la qualité rédactionnelle.

⚠ Aucune donnée d'un vrai client ne doit entrer dans ce jeu : uniquement du synthétique ou du
lab, éventuellement anonymisé.

Usage :  python ai/dataset/build_dataset.py --n 1500 --out ai/dataset/train.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from adsentry.ai.dataset import iter_samples


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1500)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=Path("ai/dataset/train.jsonl"))
    ap.add_argument("--gold", type=Path, default=Path("ai/dataset/gold"))
    args = ap.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with args.out.open("w", encoding="utf-8") as fh:
        for sample in iter_samples(args.n, args.seed, args.gold):
            fh.write(json.dumps(sample, ensure_ascii=False) + "\n")
            count += 1
    print(f"{count} exemples écrits dans {args.out}")


if __name__ == "__main__":
    main()
