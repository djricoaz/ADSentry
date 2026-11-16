"""Interface en ligne de commande.

adsentry collect --dc 10.0.0.10 --domain corp.local --user audit -o snapshot.json
adsentry collect-entra --tenant <id> --client <id> --cert entra.pem --thumbprint <x> -o entra.json
adsentry scan snapshot.json -o result.json
adsentry navigator result.json -o layer.json
adsentry explain result.json                 # analyse IA locale (Ollama)
adsentry mitre-check                         # valide les IDs ATT&CK du catalogue
adsentry serve | worker | run <cible>        # appliance
adsentry secret set <nom>                    # secret chiffré (mot de passe du compte d'audit...)
adsentry user add <identifiant> --role admin # comptes de la console web (admin | viewer)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import typer

from .models import CATEGORY_LABELS, ScanResult, Snapshot
from .rules.engine import analyze, load_rules
from .scoring import maturity_level

app = typer.Typer(help="ADSentry – audit AD + PKI + Entra ID, MITRE ATT&CK, IA locale", no_args_is_help=True)
secret_app = typer.Typer(help="Secrets chiffrés de l'appliance")
app.add_typer(secret_app, name="secret")
user_app = typer.Typer(help="Comptes de la console web (rôles : admin, viewer)")
app.add_typer(user_app, name="user")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@app.command()
def collect(
    dc: str = typer.Option(..., help="IP ou FQDN d'un contrôleur de domaine"),
    domain: str = typer.Option(..., help="Nom DNS du domaine"),
    user: str = typer.Option(..., help="Compte (un utilisateur standard suffit)"),
    password: str = typer.Option(..., prompt=True, hide_input=True),
    ldaps: bool = typer.Option(False, help="Utiliser LDAPS (636)"),
    sysvol: bool = typer.Option(True, help="Lire les GPO dans SYSVOL (SMB)"),
    probes: bool = typer.Option(True, help="Sondes réseau en lecture seule sur les DC"),
    output: Path = typer.Option(Path("snapshot.json"), "-o"),
):
    """Collecte Active Directory en lecture seule et écrit un snapshot JSON."""
    from .appliance.config import AdTarget, Target
    from .appliance.runner import collect_target

    class _Inline:
        def get(self, _name: str) -> str:
            return password

    target = Target(
        name="cli",
        ad=AdTarget(
            domain=domain, dc=dc, username=user, password_secret="-", ldaps=ldaps, sysvol=sysvol, probes=probes
        ),
    )
    snap = collect_target(target, _Inline())
    output.write_text(snap.model_dump_json(indent=1), encoding="utf-8")
    typer.echo(
        f"Snapshot écrit : {output} ({len(snap.users)} utilisateurs, {len(snap.pki.templates)} modèles, "
        f"{len(snap.gpos or [])} GPO, {len(snap.dc_probes)} DC sondés)"
    )


@app.command("collect-entra")
def collect_entra(
    tenant: str = typer.Option(..., help="ID du tenant"),
    client: str = typer.Option(..., help="ID de l'application d'audit"),
    cert: Path = typer.Option(None, help="Clé privée + certificat PEM"),
    thumbprint: str = typer.Option(None),
    connect_version: str = typer.Option(None, help="Version d'Entra Connect (non exposée par Graph)"),
    merge: Path = typer.Option(None, help="Snapshot AD existant à compléter"),
    output: Path = typer.Option(Path("snapshot.json"), "-o"),
):
    """Collecte Entra ID (Microsoft Graph, lecture seule)."""
    from .collectors.entra_collector import EntraCollector

    secret = None if cert else typer.prompt("Secret client", hide_input=True)
    snap = EntraCollector(tenant, client, cert, thumbprint, secret, connect_version).collect()
    if merge:
        base = Snapshot.model_validate_json(merge.read_text(encoding="utf-8"))
        base.entra = snap.entra
        snap = base
    output.write_text(snap.model_dump_json(indent=1), encoding="utf-8")
    typer.echo(f"Snapshot écrit : {output} ({len(snap.entra.users)} utilisateurs Entra, {len(snap.entra.apps)} apps)")


@app.command()
def scan(snapshot: Path, output: Path = typer.Option(Path("result.json"), "-o")):
    """Applique le catalogue de règles à un snapshot."""
    snap = Snapshot.model_validate_json(snapshot.read_text(encoding="utf-8"))
    result = analyze(snap)
    output.write_text(result.model_dump_json(indent=1), encoding="utf-8")

    typer.echo(f"\n{result.domain} – score global {result.global_score}/100 ({maturity_level(result.global_score)})")
    for cat, score in result.scores.items():
        typer.echo(f"  {CATEGORY_LABELS[cat]:<28} {score:>3}/100")
    typer.echo(f"\n{len(result.findings)} constat(s), {len(result.not_evaluated)} règle(s) hors périmètre :")
    for f in sorted(result.findings, key=lambda f: -f.points):
        mitre = ",".join(m.technique for m in f.mitre)
        typer.echo(f"  [{f.severity.value:<8}] {f.rule_id:<28} {f.title[:70]} ({len(f.affected)}) {mitre}")
    typer.echo(f"\nRésultat complet : {output}")


@app.command()
def navigator(result: Path, output: Path = typer.Option(Path("attack-layer.json"), "-o")):
    """Exporte une couche ATT&CK Navigator."""
    from .mitre.navigator import build_layer

    res = ScanResult.model_validate_json(result.read_text(encoding="utf-8"))
    output.write_text(json.dumps(build_layer(res), indent=1, ensure_ascii=False), encoding="utf-8")
    typer.echo(f"Couche Navigator : {output}")


@app.command()
def explain(
    result: Path,
    model: str = typer.Option("adsentry-analyst", help="Nom du modèle Ollama"),
    rag: bool = typer.Option(True, help="Ajouter le contexte de la base de connaissances"),
    output: Path = typer.Option(Path("analysis.json"), "-o"),
):
    """Analyse IA locale des résultats (Ollama)."""
    from .ai import rag as rag_mod
    from .ai.ollama_client import OllamaClient, analyze_with_llm

    res = ScanResult.model_validate_json(result.read_text(encoding="utf-8"))
    client = OllamaClient(model=model)
    snippets: list[str] = []
    if rag:
        for f in sorted(res.findings, key=lambda f: -f.points)[:5]:
            snippets += rag_mod.search(f"{f.title} {f.remediation}", k=2, client=client)
    analysis = analyze_with_llm(res, client=client, context_snippets=list(dict.fromkeys(snippets)))
    output.write_text(json.dumps(analysis, ensure_ascii=False, indent=1), encoding="utf-8")
    typer.echo(analysis.get("resume_executif", ""))
    if not analysis["_controle_qualite"]["fiable"]:
        typer.secho("⚠ Le modèle a cité des règles inexistantes (retirées).", fg="yellow")


@app.command("rag-index")
def rag_index(knowledge: Path = typer.Option(Path("knowledge"))):
    """Construit l'index RAG (catalogue + knowledge/*.md)."""
    from .ai.rag import build_index

    typer.echo(f"{build_index(knowledge)} documents indexés")


@app.command("mitre-check")
def mitre_check():
    """Vérifie que les techniques du catalogue existent dans la version ATT&CK courante."""
    from .mitre.attack import load

    kb = load()
    ids = sorted({m.technique for r in load_rules() for m in r.mitre})
    report = kb.validate(ids)
    typer.echo(f"ATT&CK v{kb.version} – {len(ids)} techniques référencées")
    for k, v in report.items():
        typer.echo(f"  {k}: {v or 'aucune'}")
    if any(report.values()):
        raise typer.Exit(1)
    from .mitre.attack import export_subset

    typer.echo(f"Référentiel hors ligne mis à jour : {export_subset(kb, ids)}")


# ----------------------------------------------------------------------------- appliance


@app.command()
def serve(
    host: str = "127.0.0.1",
    port: int = 8000,
    worker: bool = typer.Option(False, "--worker", help="Exécuter aussi les scans dans ce processus (sans Docker)"),
    web: Path = typer.Option(None, help="Dossier du tableau de bord à servir (ex. appliance/web)"),
    tls_cert: Path = typer.Option(None, help="Certificat TLS (PEM) pour servir directement en HTTPS"),
    tls_key: Path = typer.Option(None, help="Clé privée TLS (PEM)"),
):
    """Démarre l'API et la console web."""
    import os

    import uvicorn

    if worker:
        os.environ["ADSENTRY_EMBEDDED_WORKER"] = "1"
    if web:
        os.environ["ADSENTRY_WEB_DIR"] = str(web.resolve())
    # Derrière Caddy (réseau Docker interne) : faire confiance aux en-têtes X-Forwarded-*.
    trusted = os.environ.get("ADSENTRY_TRUSTED_PROXIES", "127.0.0.1")
    if host not in ("127.0.0.1", "localhost", "::1") and not tls_cert:
        typer.secho(
            "Attention : console exposée en HTTP clair. Utilisez --tls-cert/--tls-key ou un proxy HTTPS.", fg="yellow"
        )
    uvicorn.run(
        "adsentry.api.main:app",
        host=host,
        port=port,
        reload=False,
        proxy_headers=True,
        forwarded_allow_ips=trusted,
        ssl_certfile=str(tls_cert) if tls_cert else None,
        ssl_keyfile=str(tls_key) if tls_key else None,
    )


@app.command()
def worker():
    """Planificateur : exécute les scans demandés depuis la console et ceux planifiés (cron)."""
    from .appliance.runner import worker_loop

    worker_loop()


@app.command()
def run(target: str):
    """Exécute immédiatement le scan d'une cible déclarée dans targets.yaml."""
    from .appliance.config import load_targets
    from .appliance.runner import run_target

    t = next((x for x in load_targets() if x.name == target), None)
    if t is None:
        raise typer.BadParameter(f"Cible inconnue : {target}")
    typer.echo(f"Résultat : {run_target(t)}")


@user_app.command("add")
def user_add(
    username: str,
    role: str = typer.Option("viewer", help="admin (gestion complète) ou viewer (consultation)"),
    display_name: str = typer.Option("", "--name", help="Nom affiché"),
    password: str = typer.Option(
        ..., prompt=True, hide_input=True, confirmation_prompt=True, envvar="ADSENTRY_USER_PASSWORD"
    ),
):
    """Crée un compte de la console web."""
    from .appliance.auth import AuthError, Role, UserStore, setup_token_path

    try:
        UserStore().create(username, password, Role(role), display_name)
    except (AuthError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    setup_token_path().unlink(missing_ok=True)
    typer.echo(f"Compte « {username} » créé ({role}).")


@user_app.command("list")
def user_list():
    """Liste les comptes de la console."""
    from .appliance.auth import UserStore

    for u in UserStore().list():
        state = " (désactivé)" if u.disabled else ""
        typer.echo(f"{u.username:<24} {u.role.value:<8} {u.display_name}{state}")


@user_app.command("passwd")
def user_passwd(
    username: str,
    password: str = typer.Option(
        ..., prompt=True, hide_input=True, confirmation_prompt=True, envvar="ADSENTRY_USER_PASSWORD"
    ),
):
    """Réinitialise le mot de passe d'un compte (et le réactive)."""
    from .appliance.auth import AuthError, UserStore

    try:
        UserStore().update(username, password=password, disabled=False)
    except AuthError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"Mot de passe de « {username} » réinitialisé.")


@user_app.command("delete")
def user_delete(username: str):
    """Supprime un compte."""
    from .appliance.auth import AuthError, UserStore

    try:
        UserStore().delete(username)
    except AuthError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"Compte « {username} » supprimé.")


@secret_app.command("set")
def secret_set(name: str, value: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True)):
    """Enregistre un secret chiffré."""
    from .appliance.config import SecretStore

    SecretStore().set(name, value)
    typer.echo(f"Secret « {name} » enregistré.")


@secret_app.command("list")
def secret_list():
    """Liste les noms des secrets (jamais les valeurs)."""
    from .appliance.config import SecretStore

    for n in SecretStore().names():
        typer.echo(n)


if __name__ == "__main__":
    app()
