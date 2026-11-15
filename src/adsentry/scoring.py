"""Calcul du score de risque.

Principe :
* chaque catégorie cumule les points de ses constats, plafonnés à 100 ;
* le score global est le MAXIMUM des catégories (le maillon le plus faible détermine
  le risque du domaine). 0 = aucun risque détecté, 100 = risque maximal.
"""

from __future__ import annotations

from .models import Category, Finding


def compute_scores(findings: list[Finding]) -> tuple[dict[Category, int], int]:
    scores = {cat: 0 for cat in Category}
    for f in findings:
        scores[f.category] = min(100, scores[f.category] + f.points)
    return scores, max(scores.values(), default=0)


def maturity_level(global_score: int) -> str:
    """Niveau lisible pour un humain (affiché dans le rapport et donné à l'IA)."""
    if global_score >= 75:
        return "Critique"
    if global_score >= 50:
        return "Élevé"
    if global_score >= 25:
        return "Modéré"
    return "Faible"
