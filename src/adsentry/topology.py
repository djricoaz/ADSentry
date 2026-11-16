"""Topologie : graphe des comptes et groupes à risque, et carte des approbations entre domaines et forêts.

Calcul pur à partir du Snapshot (aucun réseau), enregistré à côté du rapport (<scan>.graph.json) car les
rapports ne conservent pas les données brutes de l'annuaire.

Graphe orienté dans le sens d'une attaque : « A → B » signifie que A peut agir sur B (membre du groupe B,
droit d'écriture sur B, délégation vers B…). On garde les cibles Tier 0, tout ce qui peut les atteindre
(parcours en largeur inverse), et les comptes à risque isolés (SPN, pré-authentification désactivée,
délégation non contrainte). Inconnu ≠ vulnérable : seules les relations collectées sont tracées.
"""

from __future__ import annotations

from collections import deque
from datetime import timedelta

from . import constants as c
from .models import Snapshot
from .rules.checks.privileged import DCSYNC_RIGHTS, WRITE_RIGHTS

MAX_NODES = 400
MAX_PATHS = 25

EDGE_LABELS = {
    "MemberOf": "Membre de",
    "GenericAll": "Contrôle total",
    "GenericWrite": "Écriture générique",
    "WriteDacl": "Modification des permissions",
    "WriteOwner": "Changement de propriétaire",
    "Owner": "Propriétaire",
    "WriteProperty": "Écriture d'attributs",
    "AllExtendedRights": "Tous les droits étendus",
    "AddMember": "Ajout de membres",
    "User-Force-Change-Password": "Réinitialisation du mot de passe",
    "CreateChild": "Création d'objets",
    "DCSync": "Réplication des secrets (DCSync)",
    "AllowedToDelegate": "Délégation contrainte",
    "AllowedToAct": "Délégation basée sur la ressource",
    "Unconstrained": "Délégation non contrainte",
    "SIDHistory": "Historique SID",
}
EDGE_FAMILY = {
    "MemberOf": "membership",
    "AllowedToDelegate": "delegation",
    "AllowedToAct": "delegation",
    "Unconstrained": "delegation",
    "SIDHistory": "sidhistory",
}
TRUST_KINDS = {
    "forest": "Approbation de forêt",
    "external": "Approbation externe",
    "realm": "Royaume Kerberos",
    "downlevel": "Domaine NT4",
    "within_forest": "Intra-forêt (parent-enfant ou racine d'arbre)",
}


def _family(kind: str) -> str:
    return EDGE_FAMILY.get(kind, "acl")


# ----------------------------------------------------------------------------- comptes et groupes


def _domain_node(snap: Snapshot) -> str:
    return f"domain:{snap.domain.name if snap.domain else '?'}"


def build_graph(snap: Snapshot) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    users = {u.sid: u for u in snap.users}
    computers = {cp.sid: cp for cp in snap.computers}
    groups = {g.sid: g for g in snap.groups}
    dom = _domain_node(snap)

    def node(nid: str) -> dict:
        if nid in nodes:
            return nodes[nid]
        if nid == dom:
            n = {"id": nid, "label": snap.domain.name if snap.domain else "domaine", "type": "domain", "flags": []}
        elif nid.startswith("object:"):
            label = {"adminsdholder": "AdminSDHolder"}.get(nid.split(":", 1)[1], nid.split(":", 1)[1])
            n = {"id": nid, "label": label, "type": "object", "flags": []}
        elif nid in users:
            u = users[nid]
            flags = []
            if u.spns and u.enabled:
                flags.append("spn")
            if u.dont_require_preauth and u.enabled:
                flags.append("asrep")
            if u.trusted_for_delegation:
                flags.append("unconstrained")
            if u.sid_history:
                flags.append("sid_history")
            if u.password_never_expires and snap.user_is_privileged(u):
                flags.append("pwd_never_expires")
            if not u.enabled:
                flags.append("disabled")
            n = {"id": nid, "label": u.sam, "type": "user", "flags": flags, "enabled": u.enabled}
        elif nid in computers:
            cp = computers[nid]
            flags = ["dc"] if cp.is_dc else []
            if cp.trusted_for_delegation and not cp.is_dc:
                flags.append("unconstrained")
            if cp.rbcd_principals:
                flags.append("rbcd")
            if not cp.enabled:
                flags.append("disabled")
            n = {"id": nid, "label": cp.name, "type": "computer", "flags": flags, "enabled": cp.enabled}
        else:
            n = {"id": nid, "label": snap.principal_name(nid), "type": "group", "flags": []}
            if nid in groups:
                n["members"] = len(groups[nid].members)
        n["tier0"] = nid == dom or nid.startswith("object:adminsdholder") or snap.is_tier0(nid)
        n["low_priv"] = snap.is_low_privileged(nid)
        nodes[nid] = n
        return n

    def edge(src: str, dst: str, kind: str) -> None:
        node(src), node(dst)
        edges.append({"source": src, "target": dst, "kind": kind, "family": _family(kind)})

    # Appartenances directes ; repli sur l'appartenance transitive si le groupe ne liste pas ses membres
    # L'appartenance aux groupes « tout le monde » (Utilisateurs du domaine…) est universelle : le nœud du
    # groupe représente déjà tous les comptes, on n'en trace pas les membres un par un.
    listed = {g.sid for g in snap.groups if g.members}
    for g in snap.groups:
        if snap.is_low_privileged(g.sid):
            continue
        for m in g.members:
            edge(m, g.sid, "MemberOf")
    for u in snap.users:
        for gsid in u.member_of:
            if gsid not in listed and not snap.is_low_privileged(gsid):
                edge(u.sid, gsid, "MemberOf")

    # Droits (ACL) sur des principaux, sur l'objet domaine et sur AdminSDHolder
    for e in snap.acl_edges:
        if e.target_sid and e.right in WRITE_RIGHTS:
            edge(e.principal_sid, e.target_sid, e.right)
        elif e.target_type == "domain" and e.right in DCSYNC_RIGHTS | {"WriteDacl", "WriteOwner", "Owner"}:
            edge(e.principal_sid, dom, "DCSync" if e.right in DCSYNC_RIGHTS else e.right)
        elif e.target_type == "adminsdholder" and e.right in WRITE_RIGHTS:
            edge(e.principal_sid, "object:adminsdholder", e.right)

    # Délégations
    by_host = {}
    for cp in snap.computers:
        for h in filter(None, (cp.name, cp.dns_hostname)):
            by_host[h.lower().rstrip("$")] = cp.sid
    for principal in [*snap.users, *snap.computers]:
        if principal.trusted_for_delegation and not getattr(principal, "is_dc", False):
            edge(principal.sid, dom, "Unconstrained")
        for spn in principal.allowed_to_delegate_to:
            host = spn.split("/", 1)[-1].split(":", 1)[0].split("/", 1)[0].lower()
            target = by_host.get(host) or by_host.get(host.split(".", 1)[0])
            if target:
                edge(principal.sid, target, "AllowedToDelegate")
        for s in principal.sid_history:
            edge(principal.sid, s, "SIDHistory")
    for cp in snap.computers:
        for p in cp.rbcd_principals:
            edge(p, cp.sid, "AllowedToAct")

    # Parcours inverse depuis le Tier 0 : distance et prochain saut vers le Tier 0
    targets = {nid for nid, n in nodes.items() if n["tier0"]}
    targets |= {u.sid for u in snap.users if snap.user_is_privileged(u) and u.sid in nodes}
    preds: dict[str, list[dict]] = {}
    for e in edges:
        preds.setdefault(e["target"], []).append(e)
    dist = {t: 0 for t in targets}
    nxt: dict[str, dict] = {}
    queue = deque(targets)
    while queue:
        cur = queue.popleft()
        for e in preds.get(cur, ()):
            src = e["source"]
            if src not in dist:
                dist[src] = dist[cur] + 1
                nxt[src] = e
                queue.append(src)

    risky = {nid for nid, n in nodes.items() if {"spn", "asrep", "unconstrained", "sid_history"} & set(n["flags"])}
    keep = set(dist) | risky
    truncated = False
    if len(keep) > MAX_NODES:
        truncated = True
        keep = set(sorted(keep, key=lambda n: (dist.get(n, 99), n not in targets))[:MAX_NODES])
    for nid in keep:
        n = nodes[nid]
        n["distance"] = dist.get(nid)
        n["privileged"] = nid in targets
        n["exposed"] = nid in dist and nid not in targets
    out_nodes = [nodes[n] for n in keep]
    out_edges = [e for e in edges if e["source"] in keep and e["target"] in keep]
    for e in out_edges:
        e["to_tier0"] = nxt.get(e["source"]) is e

    paths = _paths(snap, keep, dist, nxt, targets, nodes)
    return {
        "nodes": out_nodes,
        "edges": [{k: v for k, v in e.items()} for e in out_edges],
        "paths": paths,
        "edge_labels": EDGE_LABELS,
        "truncated": truncated,
        "stats": {
            "tier0": len([n for n in out_nodes if n["privileged"]]),
            "exposed": len([n for n in out_nodes if n["exposed"]]),
            "exposed_users": len([n for n in out_nodes if n["exposed"] and n["type"] == "user"]),
            "low_priv_paths": len([p for p in paths if nodes[p["nodes"][0]]["low_priv"]]),
            "risky_accounts": len(risky),
            "nodes": len(out_nodes),
            "edges": len(out_edges),
        },
    }


def _paths(snap, keep, dist, nxt, targets, nodes) -> list[dict]:
    """Chemins les plus courts vers le Tier 0, en partant des comptes et des groupes « tout le monde »."""
    starts = [n for n in keep if n in nxt and (nodes[n]["type"] in ("user", "computer") or nodes[n]["low_priv"])]
    starts.sort(key=lambda n: (not nodes[n]["low_priv"], dist[n], nodes[n]["label"].lower()))
    out = []
    for s in starts[:MAX_PATHS]:
        seq, kinds, cur = [s], [], s
        while cur in nxt:
            e = nxt[cur]
            kinds.append(e["kind"])
            cur = e["target"]
            seq.append(cur)
        out.append({"nodes": seq, "kinds": kinds, "length": len(kinds), "target": nodes[seq[-1]]["label"]})
    return out


# ----------------------------------------------------------------------------- approbations


def build_trust_map(snap: Snapshot) -> dict:
    """Domaines, forêts et approbations, vus depuis le domaine audité."""
    if snap.domain is None:
        return {"domains": [], "trusts": []}
    me = snap.domain.name
    forest = snap.domain.forest or me
    domains = {me: {"name": me, "forest": forest, "current": True}}
    if forest != me:
        domains[forest] = {"name": forest, "forest": forest, "current": False}
    trusts = []
    for t, internal in [*[(t, True) for t in snap.intra_forest_trusts], *[(t, False) for t in snap.trusts]]:
        kind = t.kind or ("within_forest" if internal else None)
        tgt_forest = forest if internal else (t.target if kind == "forest" else None)
        domains.setdefault(t.target, {"name": t.target, "forest": tgt_forest, "current": False})
        risks = []
        if not internal and not t.sid_filtering:
            risks.append({"label": "Filtrage SID désactivé", "severity": "high"})
        if t.tgt_delegation:
            risks.append({"label": "Délégation de TGT autorisée", "severity": "high"})
        if t.aes_enabled is False:
            risks.append({"label": "Chiffrement RC4 uniquement", "severity": "medium"})
        if t.trust_type == 1:
            risks.append({"label": "Domaine NT4 (protocole obsolète)", "severity": "medium"})
        if t.last_change and snap.collected_at - t.last_change > timedelta(days=45):
            risks.append({"label": "Secret d'approbation non renouvelé depuis plus de 45 jours", "severity": "low"})
        # Sens de l'accès : le domaine approuvé (trusted) accède au domaine qui approuve (trusting)
        access = {
            "outbound": [(t.target, me)],
            "inbound": [(me, t.target)],
            "bidirectional": [(t.target, me), (me, t.target)],
        }
        trusts.append(
            {
                "source": me,
                "target": t.target,
                "direction": t.direction,
                "kind": kind,
                "kind_label": TRUST_KINDS.get(kind, "Type non collecté"),
                "transitive": True
                if kind in ("forest", "within_forest")
                else False
                if kind in ("external", "downlevel")
                else None,
                "sid_filtering": None if internal else t.sid_filtering,
                "access": [{"from": a, "to": b} for a, b in access.get(t.direction, [])],
                "risks": risks,
                "severity": max((r["severity"] for r in risks), key=["low", "medium", "high"].index, default=None),
            }
        )
    forests: dict[str, list[str]] = {}
    for d in domains.values():
        forests.setdefault(d["forest"] or f"?{d['name']}", []).append(d["name"])
    return {
        "current": me,
        "forest": forest,
        "domains": list(domains.values()),
        "forests": [{"name": k if not k.startswith("?") else None, "domains": v} for k, v in forests.items()],
        "trusts": trusts,
    }


def build(snap: Snapshot) -> dict:
    return {
        "domain": snap.domain.name if snap.domain else None,
        "collected_at": snap.collected_at.isoformat(),
        "graph": build_graph(snap),
        "trust_map": build_trust_map(snap),
        "well_known": {"everyone": c.SID_EVERYONE, "authenticated_users": c.SID_AUTHENTICATED_USERS},
    }
