# Guide technique complet — `rapport_wazuh.py`

Document unique réunissant **le code complet et son explication**, section par section.
Objectif : comprendre et redéployer le script de rapport hebdomadaire sur n'importe quel serveur Wazuh.

> Toutes les valeurs sensibles (clés SMTP, emails, nom d'organisation) ont été remplacées
> par des exemples. Les vrais secrets se renseignent via des variables d'environnement.

---

## 1. Vue d'ensemble

Le script lit les alertes de Wazuh, les trie et les classe (À investiguer / À vérifier / Faux positif), compare avec le rapport précédent (tendance, nouvelles règles, postes en hausse), puis génère un **Excel** et un **PDF** et les envoie par **email**. Le classement combine une logique « analyste sécurité » (SOC) et une **IA locale** (Ollama).

## 2. Prérequis

- **Python 3**
- Bibliothèques : `openpyxl` (Excel), `reportlab` (PDF), `requests` (appel à l'IA)
- Accès en lecture aux journaux Wazuh (exécution avec `sudo` en général)
- Un compte **SMTP** pour l'envoi des emails
- *(optionnel)* **Ollama** en local avec le modèle `gemma3:1b` pour l'analyse IA

```bash
pip install openpyxl reportlab requests
```

## 3. Fichiers utilisés

| Fichier | Rôle | Accès |
|---------|------|-------|
| `/var/ossec/logs/alerts/alerts.json` | Journal d'alertes courant | lecture |
| `/var/ossec/logs/alerts/*.json.gz` | Archives des jours précédents | lecture |
| `~/rapports_wazuh/historique.json` | Historique des rapports (pour la tendance) | lecture + écriture |
| `~/rapports_wazuh/rapport_wazuh_S*.xlsx` | Rapport Excel généré | écriture |
| `~/rapports_wazuh/analyse_ia_S*.pdf` | Rapport PDF généré | écriture |
| `.env` / variables d'environnement | Identifiants SMTP et destinataires | lecture |

---

## 4. En-tête et imports

L'en-tête documente l'usage et les options de lancement, et rappelle de ne jamais mettre de secret en clair. Les imports incluent la bibliothèque standard plus, plus loin dans le code, `openpyxl` et `reportlab` (importés à l'intérieur des fonctions qui les utilisent).

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
 RAPPORT HEBDOMADAIRE WAZUH
=============================================================================
 Lecture directe des alertes Wazuh, generation d'un rapport Excel + PDF,
 puis envoi par email.

 Usage :
   sudo python3 rapport_wazuh.py
   sudo python3 rapport_wazuh.py --days 14
   sudo python3 rapport_wazuh.py --no-email
   sudo python3 rapport_wazuh.py --no-ai

 -----------------------------------------------------------------------------
 CONFIGURATION DES SECRETS
 -----------------------------------------------------------------------------
 Ne mettez JAMAIS de mot de passe ou de cle API en clair dans ce fichier.
 Renseignez plutot des variables d'environnement (ou un fichier .env charge
 avant l'execution) :

   export SMTP_USER="votre_cle_api"
   export SMTP_PASS="votre_cle_secrete"
   export SMTP_SENDER="alertes@exemple.com"
   export EMAIL_TO="destinataire1@exemple.com,destinataire2@exemple.com"

 Les valeurs ci-dessous sont des EXEMPLES a remplacer.
=============================================================================
"""

import argparse
import gzip
import glob
import json
import os
import re
import smtplib
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
```


## 5. Configuration

Toutes les constantes à adapter : emplacement des journaux, dossier de sortie, paramètres SMTP (lus depuis l'environnement avec des exemples par défaut), destinataires, modèle d'IA (`OLLAMA_MODEL`) et seuil au-delà duquel une règle est jugée « bruyante ».

```python

# =============================================================================
# CONFIGURATION
# =============================================================================

# Nom de l'organisation affiche dans les rapports (a personnaliser).
ORG_NAME = "Entreprise"

ALERTS_DIR = "/var/ossec/logs/alerts"
ALERTS_FILE = os.path.join(ALERTS_DIR, "alerts.json")
OUTPUT_DIR = os.path.expanduser("~/rapports_wazuh")

# --- Parametres SMTP (a renseigner via variables d'environnement) ---
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.exemple.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "VOTRE_CLE_API_SMTP")
SMTP_PASS = os.environ.get("SMTP_PASS", "VOTRE_CLE_SECRETE_SMTP")
SMTP_SENDER = os.environ.get("SMTP_SENDER", "alertes@exemple.com")

EMAIL_FROM = os.environ.get("EMAIL_FROM", f"Supervision securite {ORG_NAME} <alertes@exemple.com>")
EMAIL_TO = [
    addr.strip()
    for addr in os.environ.get(
        "EMAIL_TO",
        "destinataire1@exemple.com,destinataire2@exemple.com",
    ).split(",")
    if addr.strip()
]
EMAIL_SUBJECT = "Rapport securite " + ORG_NAME + " - Semaine {week}"

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "gemma3:1b"

SEUIL_NOUVELLE_REGLE_BRUYANTE = 500
HISTORY_FILE = os.path.join(OUTPUT_DIR, "historique.json")
```


## 6. Historique et tendances

Ce groupe de fonctions donne au script sa mémoire d'une semaine sur l'autre. `load_history` / `save_history` lisent et écrivent `historique.json` (les 10 derniers rapports). `compute_trend` calcule l'évolution du volume d'alertes, `find_new_rules` repère les règles jamais vues auparavant, et `find_agent_changes` détecte les postes dont l'activité a fortement varié (plus de 20 %).

```python

# =============================================================================
# HISTORIQUE
# =============================================================================

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"runs": []}


def save_history(history, total, hc_count, rules_seen, top_agents_data):
    history["runs"].append({
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "total": total,
        "high_critical": hc_count,
        "rules": list(rules_seen),
        "top_agents": {a["agent"]: a["total"] for a in top_agents_data[:10]},
    })
    history["runs"] = history["runs"][-10:]

    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def compute_trend(history, total, hc_count):
    trend = {"total": None, "hc": None, "total_pct": None, "hc_pct": None}
    runs = history.get("runs", [])

    if len(runs) >= 1:
        prev = runs[-1]
        prev_total = prev.get("total", 0)
        prev_hc = prev.get("high_critical", 0)

        if prev_total > 0:
            trend["total"] = total - prev_total
            trend["total_pct"] = round((total - prev_total) / prev_total * 100, 1)

        if prev_hc > 0:
            trend["hc"] = hc_count - prev_hc
            trend["hc_pct"] = round((hc_count - prev_hc) / prev_hc * 100, 1)

    return trend


def find_new_rules(history, current_rules):
    runs = history.get("runs", [])
    if len(runs) >= 1:
        prev_rules = set(runs[-1].get("rules", []))
        return [r for r in current_rules if r not in prev_rules]
    return []


def find_agent_changes(history, top_agents_data):
    runs = history.get("runs", [])
    if len(runs) < 1:
        return []

    prev_agents = runs[-1].get("top_agents", {})
    changes = []

    for a in top_agents_data[:10]:
        prev = prev_agents.get(a["agent"], 0)
        if prev > 0:
            diff = a["total"] - prev
            pct = round(diff / prev * 100, 1)

            if abs(pct) > 20:
                changes.append({
                    "agent": a["agent"],
                    "before": prev,
                    "after": a["total"],
                    "diff": diff,
                    "pct": pct,
                })

    changes.sort(key=lambda x: -abs(x["pct"]))
    return changes[:5]
```


## 7. Lecture des alertes

`parse_alerts(days)` lit le journal courant et les archives, ne garde que la période demandée, puis **regroupe les alertes par règle**. Pour chaque règle : volume, niveau de gravité, description, postes concernés, références MITRE et dates de première/dernière apparition. C'est le cœur de la collecte de données.

```python

# =============================================================================
# LECTURE DES ALERTES
# =============================================================================

def parse_alerts(days=7):
    cutoff = datetime.now() - timedelta(days=days)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%S")

    rules = defaultdict(lambda: {
        "count": 0,
        "description": "",
        "level": 0,
        "groups": [],
        "agents": Counter(),
        "mitre_ids": set(),
        "mitre_tactics": set(),
        "first_seen": None,
        "last_seen": None,
    })

    total = 0
    errors = 0
    files_to_read = []

    if os.path.exists(ALERTS_FILE):
        files_to_read.append(ALERTS_FILE)

    if days > 1:
        archives = sorted(glob.glob(os.path.join(ALERTS_DIR, "*.json.gz")), reverse=True)
        for archive in archives[:days + 2]:
            files_to_read.append(archive)

    for filepath in files_to_read:
        opener = gzip.open if filepath.endswith(".gz") else open

        try:
            with opener(filepath, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    try:
                        alert = json.loads(line.strip())
                    except Exception:
                        errors += 1
                        continue

                    ts = alert.get("timestamp", "")
                    if ts < cutoff_str:
                        continue

                    total += 1

                    rule = alert.get("rule", {})
                    rid = str(rule.get("id", "unknown"))
                    agent_name = alert.get("agent", {}).get("name", "unknown")
                    mitre = rule.get("mitre", {})

                    entry = rules[rid]
                    entry["count"] += 1
                    entry["level"] = int(rule.get("level", 0) or 0)
                    entry["description"] = rule.get("description", "")
                    entry["agents"][agent_name] += 1

                    if not entry["groups"] and rule.get("groups"):
                        entry["groups"] = rule.get("groups", [])

                    if isinstance(mitre.get("id"), list):
                        entry["mitre_ids"].update(mitre["id"])

                    if isinstance(mitre.get("tactic"), list):
                        entry["mitre_tactics"].update(mitre["tactic"])

                    if not entry["first_seen"] or ts < entry["first_seen"]:
                        entry["first_seen"] = ts

                    if not entry["last_seen"] or ts > entry["last_seen"]:
                        entry["last_seen"] = ts

        except PermissionError:
            print(f"[ERREUR] Permission refusee : {filepath}")
            print("  Relancez avec sudo.")
            sys.exit(1)
        except Exception as e:
            print(f"[WARN] Erreur lecture {filepath}: {e}")

    print(f"  Alertes parsees : {total:,} sur {days} jours")
    print(f"  Regles distinctes : {len(rules)}")
    if errors:
        print(f"  Erreurs parsing : {errors}")

    return dict(rules), total
```


## 8. Analyse

`analyze(rules_data, total)` exploite les données collectées : il isole les alertes **graves** (niveau ≥ 12), calcule le **top des postes** les plus alertés, et repère les **règles bruyantes** (au-delà du seuil configuré).

```python

# =============================================================================
# ANALYSE
# =============================================================================

def analyze(rules_data, total):
    high_critical = []

    for rid, data in rules_data.items():
        if data["level"] >= 12:
            top_agents = data["agents"].most_common(5)
            high_critical.append({
                "rule_id": rid,
                "description": data["description"],
                "level": data["level"],
                "count": data["count"],
                "agents": top_agents,
                "agent_count": len(data["agents"]),
                "mitre": ", ".join(sorted(data["mitre_ids"])) or "-",
                "tactics": ", ".join(sorted(data["mitre_tactics"])) or "-",
            })

    high_critical.sort(key=lambda x: (-x["level"], -x["count"]))

    agent_totals = Counter()
    agent_high = Counter()

    for _, data in rules_data.items():
        for agent, count in data["agents"].items():
            agent_totals[agent] += count
            if data["level"] >= 12:
                agent_high[agent] += count

    top_agents = []

    for agent, count in agent_totals.most_common(20):
        top_agents.append({
            "agent": agent,
            "total": count,
            "high_critical": agent_high.get(agent, 0),
            "pct": round(count / total * 100, 1) if total else 0,
        })

    noisy = []

    for rid, data in rules_data.items():
        if data["count"] > SEUIL_NOUVELLE_REGLE_BRUYANTE:
            noisy.append({
                "rule_id": rid,
                "description": data["description"],
                "level": data["level"],
                "count": data["count"],
                "top_agents": data["agents"].most_common(3),
                "agent_count": len(data["agents"]),
                "mitre": ", ".join(sorted(data["mitre_ids"])) or "-",
                "tactics": ", ".join(sorted(data["mitre_tactics"])) or "-",
            })

    noisy.sort(key=lambda x: -x["count"])

    return high_critical, top_agents, noisy
```


## 9. Verdict « analyste sécurité » (logique SOC)

`soc_verdict_override` applique des règles métier **avant** l'IA : certaines règles connues sont classées d'office en faux positif, tandis que toute alerte évoquant un terme sensible (CVE, malware, PowerShell, RDP, exécutable déposé…) est forcée en « à investiguer ». C'est le garde-fou qui prime sur l'avis du modèle. `normalize_verdict` et `verdict_priority` uniformisent et ordonnent les verdicts.

```python

# =============================================================================
# VERDICT SOC PRIORITAIRE
# =============================================================================

def soc_verdict_override(alert):
    """Decision SOC prioritaire avant l'avis IA."""
    rule_id = str(alert.get("rule_id", ""))
    desc = alert.get("description", "").lower()
    level = int(alert.get("level", 0) or 0)
    count = int(alert.get("count", 0) or 0)
    agent_count = int(alert.get("agent_count", 0) or 0)

    known_false_positive = {
        "92058": "Application Compatibility Database : activite Windows generalement normale.",
        "204": "File d'evenements agent saturee : sujet de supervision, pas incident securite direct.",
    }

    if rule_id in known_false_positive:
        return "FAUX POSITIF", known_false_positive[rule_id]

    if rule_id == "92213":
        return "A INVESTIGUER", "Executable depose dans un dossier souvent utilise par des logiciels malveillants."

    dangerous_keywords = [
        "malware",
        "cve",
        "powershell",
        "remote desktop",
        "executable file dropped",
        "binary loaded",
        "dll file created",
        "credential",
        "privilege",
        "persistence",
        "temp",
        "ransom",
        "mimikatz",
        "lsass",
        "encodedcommand",
        "scheduled task",
        "registry run",
    ]

    if any(word in desc for word in dangerous_keywords):
        return "A INVESTIGUER", "Comportement potentiellement sensible, verification securite recommandee."

    if level >= 14:
        return "A INVESTIGUER", "Niveau d'alerte eleve, analyse prioritaire recommandee."

    if level >= 12 and count <= 20 and agent_count <= 3:
        return "A INVESTIGUER", "Alerte peu frequente sur peu de postes, contexte a verifier."

    if level >= 12:
        return "A VERIFIER", "Alerte importante a confirmer selon le contexte."

    return None, None


def normalize_verdict(verdict):
    value = (verdict or "").upper()
    if "INVESTIGUER" in value:
        return "A INVESTIGUER"
    if "VERIFIER" in value or "VÉRIFIER" in value:
        return "A VERIFIER"
    if "FAUX POSITIF" in value:
        return "FAUX POSITIF"
    return "A VERIFIER"


def verdict_priority(verdict):
    verdict = normalize_verdict(verdict)
    if verdict == "A INVESTIGUER":
        return 0
    if verdict == "A VERIFIER":
        return 1
    if verdict == "FAUX POSITIF":
        return 2
    return 3
```


## 10. Analyse par IA (Ollama, en local)

`call_ollama` interroge le modèle local (aucune donnée envoyée à l'extérieur). `analyze_alerts_with_ai` traite chaque alerte grave : si la logique SOC a déjà tranché, on garde son verdict ; sinon on demande au modèle un verdict puis une explication en trois points (signification / cause probable / action). Une vérification finale reclasse en « à investiguer » si un terme sensible apparaît, même si le modèle s'était trompé.

```python

# =============================================================================
# ANALYSE IA
# =============================================================================

def call_ollama(prompt, timeout=60):
    try:
        import requests

        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 120},
            },
            timeout=timeout,
        )

        if resp.status_code == 200:
            return resp.json().get("response", "").strip()
    except Exception:
        pass

    try:
        payload = json.dumps({
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 120},
        })

        result = subprocess.run(
            [
                "curl", "-s", "-X", "POST", OLLAMA_URL,
                "-H", "Content-Type: application/json",
                "-d", payload,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode == 0:
            return json.loads(result.stdout).get("response", "").strip()
    except Exception:
        pass

    return "Analyse IA indisponible"


def clean_reason(text):
    text = (text or "").strip().replace("\n", " ").replace("**", "").replace("*", "")
    text = re.sub(r"\s+", " ", text)

    for prefix in [
        "FAUX POSITIF:", "FAUX POSITIF -", "A INVESTIGUER:", "A INVESTIGUER -",
        "À INVESTIGUER:", "À INVESTIGUER -", "A VERIFIER:", "A VERIFIER -",
        "À VÉRIFIER:", "À VÉRIFIER -",
    ]:
        if text.upper().startswith(prefix.upper()):
            text = text[len(prefix):].strip()

    return text[:120] if text else "Analyse a confirmer."


def safe_detail_from_reason(reason, top_agent):
    return (
        f"SIGNIFICATION: {reason}\n"
        f"CAUSE PROBABLE: Activite systeme ou utilisateur detectee par une regle de securite.\n"
        f"ACTION: Verifier le poste {top_agent}, l'utilisateur, le processus parent et le contexte de l'evenement."
    )


def analyze_alerts_with_ai(high_critical, use_ai=True):
    if not use_ai:
        for a in high_critical:
            override_verdict, override_reason = soc_verdict_override(a)
            a["ai_verdict"] = override_verdict or "A VERIFIER"
            a["ai_reason"] = override_reason or "IA desactivee, verification manuelle recommandee."
            top_agent = a["agents"][0][0] if a["agents"] else "unknown"
            a["ai_detail"] = safe_detail_from_reason(a["ai_reason"], top_agent)
        return high_critical

    total = len(high_critical)

    for i, a in enumerate(high_critical):
        print(f"    [{i + 1}/{total}] Rule {a['rule_id']}...", end=" ", flush=True)

        top_agent = a["agents"][0][0] if a["agents"] else "unknown"

        override_verdict, override_reason = soc_verdict_override(a)
        if override_verdict:
            a["ai_verdict"] = override_verdict
            a["ai_reason"] = override_reason
            a["ai_detail"] = safe_detail_from_reason(override_reason, top_agent)
            print(override_verdict)
            continue

        prompt_court = (
            "Tu es analyste SOC. Reponds en francais simple.\n"
            "Tu dois choisir un seul verdict parmi : A INVESTIGUER, A VERIFIER, FAUX POSITIF.\n"
            "Important : ne classe jamais en FAUX POSITIF si l'alerte parle de CVE, malware, PowerShell, RDP, privilege ou executable depose.\n"
            "Format attendu : VERDICT - raison courte.\n\n"
            f"Alerte: {a['description']}\n"
            f"Niveau: {a['level']}\n"
            f"Volume: {a['count']} fois sur {a['agent_count']} poste(s)\n"
            f"MITRE: {a['mitre']}\n\n"
            "Reponse:"
        )

        response = call_ollama(prompt_court)
        resp_upper = response.upper()
        desc_upper = a["description"].upper()

        dangerous_context = any(w in desc_upper for w in [
            "CVE", "MALWARE", "POWERSHELL", "REMOTE DESKTOP", "EXECUTABLE",
            "DLL", "PRIVILEGE", "CREDENTIAL", "PERSISTENCE",
        ])

        if dangerous_context:
            verdict = "A INVESTIGUER"
        elif "FAUX POSITIF" in resp_upper or "PAS DANGEREUX" in resp_upper or "BENIN" in resp_upper or "BÉNIN" in resp_upper:
            verdict = "FAUX POSITIF"
        elif "INVESTIGUER" in resp_upper or "DANGEREUX" in resp_upper or "SUSPECT" in resp_upper:
            verdict = "A INVESTIGUER"
        else:
            verdict = "A VERIFIER"

        reason = clean_reason(response)

        prompt_detail = (
            "Tu es analyste SOC. Explique cette alerte pour un lecteur non technique.\n"
            "Garde le terme CVE si l'alerte concerne une CVE.\n"
            "Reponds exactement avec ces 3 lignes :\n"
            "SIGNIFICATION: ...\n"
            "CAUSE PROBABLE: ...\n"
            "ACTION: ...\n\n"
            f"Alerte: {a['description']}\n"
            f"Rule ID: {a['rule_id']}\n"
            f"Niveau: {a['level']}\n"
            f"Volume: {a['count']} fois sur {a['agent_count']} poste(s)\n"
            f"Agent principal: {top_agent}\n"
            f"MITRE: {a['mitre']}\n"
        )

        detail = call_ollama(prompt_detail, timeout=90)
        detail = detail.strip().replace("**", "").replace("*", "")
        detail = re.sub(r"\n{2,}", "\n", detail)

        if "SIGNIFICATION" not in detail.upper():
            detail = safe_detail_from_reason(reason, top_agent)

        a["ai_verdict"] = verdict
        a["ai_reason"] = reason
        a["ai_detail"] = detail[:650]

        print(verdict)

    high_critical.sort(key=lambda x: (verdict_priority(x.get("ai_verdict")), -x.get("level", 0), -x.get("count", 0)))
    return high_critical
```


## 11. Génération de l'Excel

`generate_excel` construit le classeur avec `openpyxl` : un onglet **synthèse** (chiffres clés, tendance, nouvelles règles, tableau des alertes graves, top des postes) et un onglet **détail filtrable**. Les lignes sont colorées selon le verdict (rouge / orange / vert). C'est la fonction la plus longue car elle gère toute la mise en forme.

```python

# =============================================================================
# EXCEL
# =============================================================================

def generate_excel(high_critical, top_agents, noisy, days, total, output_path,
                   trend=None, new_rules=None, agent_changes=None):
    try:
        import openpyxl
        from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    except ImportError:
        print("[ERREUR] openpyxl non installe.")
        sys.exit(1)

    wb = openpyxl.Workbook()

    BLEU_NUIT = "1F2A44"
    BLEU = "1B4F72"
    BLEU_CLAIR = "D6EAF8"
    VERT = "D5F5E3"
    VERT_FONCE = "1E8449"
    ROUGE = "FADBD8"
    ROUGE_FONCE = "922B21"
    ORANGE = "FEF5E7"
    ORANGE_FONCE = "B7950B"
    GRIS = "F4F6F7"
    GRIS_TEXTE = "566573"
    BLANC = "FFFFFF"
    BORDER = "BDC3C7"

    header_font = Font(name="Calibri", bold=True, size=11, color=BLANC)
    header_fill = PatternFill(start_color=BLEU, end_color=BLEU, fill_type="solid")
    title_font = Font(name="Calibri", bold=True, size=20, color=BLANC)
    subtitle_font = Font(name="Calibri", size=10, color="D6DBE5")
    section_font = Font(name="Calibri", bold=True, size=13, color=BLEU_NUIT)
    normal_font = Font(name="Calibri", size=11)
    small_font = Font(name="Calibri", size=9, color=GRIS_TEXTE)
    bold_font = Font(name="Calibri", bold=True, size=11)

    border = Border(
        left=Side(style="thin", color=BORDER),
        right=Side(style="thin", color=BORDER),
        top=Side(style="thin", color=BORDER),
        bottom=Side(style="thin", color=BORDER),
    )
    center = Alignment(horizontal="center", vertical="center")
    left = Alignment(horizontal="left", vertical="center")
    wrap = Alignment(vertical="center", wrap_text=True)

    now = datetime.now().strftime("%d/%m/%Y %H:%M")
    week = datetime.now().strftime("%W")
    hc_count = sum(a["count"] for a in high_critical)
    nb_fp = sum(1 for a in high_critical if normalize_verdict(a.get("ai_verdict")) == "FAUX POSITIF")
    nb_invest = sum(1 for a in high_critical if normalize_verdict(a.get("ai_verdict")) == "A INVESTIGUER")
    nb_verify = sum(1 for a in high_critical if normalize_verdict(a.get("ai_verdict")) == "A VERIFIER")

    # Onglet resume
    ws1 = wb.active
    ws1.title = "Resume"
    ws1.sheet_view.showGridLines = False
    ws1.sheet_view.zoomScale = 85
    ws1.freeze_panes = "B14"

    for col in ["A", "J"]:
        ws1.column_dimensions[col].width = 3

    ws1.column_dimensions["B"].width = 15
    ws1.column_dimensions["C"].width = 12
    ws1.column_dimensions["D"].width = 55
    ws1.column_dimensions["E"].width = 14
    ws1.column_dimensions["F"].width = 16
    ws1.column_dimensions["G"].width = 18
    ws1.column_dimensions["H"].width = 24
    ws1.column_dimensions["I"].width = 65

    ws1.merge_cells("B2:I2")
    ws1["B2"] = "RAPPORT SECURITE WAZUH"
    ws1["B2"].font = title_font
    ws1["B2"].fill = PatternFill(start_color=BLEU_NUIT, end_color=BLEU_NUIT, fill_type="solid")
    ws1["B2"].alignment = left

    ws1.merge_cells("B3:I3")
    ws1["B3"] = f"{ORG_NAME} | Semaine {week} | {days} jours | {now}"
    ws1["B3"].font = subtitle_font
    ws1["B3"].fill = PatternFill(start_color="2C3E50", end_color="2C3E50", fill_type="solid")
    ws1["B3"].alignment = left

    ws1.row_dimensions[2].height = 30
    ws1.row_dimensions[3].height = 22

    kpis = [
        ("Total alertes", f"{total:,}", BLEU),
        ("High / Critical", f"{hc_count:,}", ROUGE_FONCE),
        ("A investiguer", str(nb_invest), ROUGE_FONCE),
        ("A verifier", str(nb_verify), ORANGE_FONCE),
        ("Faux positifs", str(nb_fp), VERT_FONCE),
    ]

    start_cols = [2, 4, 6, 7, 8]
    for idx, (label, value, color) in enumerate(kpis):
        col = start_cols[idx]
        end_col = col + 1 if idx < 2 else col
        ws1.merge_cells(start_row=5, start_column=col, end_row=5, end_column=end_col)
        ws1.merge_cells(start_row=6, start_column=col, end_row=6, end_column=end_col)

        vcell = ws1.cell(row=5, column=col)
        vcell.value = value
        vcell.font = Font(name="Calibri", bold=True, size=22, color=color)
        vcell.alignment = center

        lcell = ws1.cell(row=6, column=col)
        lcell.value = label
        lcell.font = small_font
        lcell.alignment = center

    row = 8

    if trend and trend.get("total") is not None:
        ws1.merge_cells(start_row=row, start_column=2, end_row=row, end_column=5)
        ws1.cell(row=row, column=2).value = "TENDANCE VS RAPPORT PRECEDENT"
        ws1.cell(row=row, column=2).font = section_font
        row += 1

        headers = ["Indicateur", "Avant", "Maintenant", "Evolution"]
        for i, head in enumerate(headers, 2):
            cell = ws1.cell(row=row, column=i)
            cell.value = head
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = center
            cell.border = border
        row += 1

        prev_total = total - trend["total"]
        diff_total = trend["total"]
        sign = "+" if diff_total > 0 else ""
        color = ROUGE_FONCE if diff_total > 0 else VERT_FONCE

        values = ["Total alertes", f"{prev_total:,}", f"{total:,}", f"{sign}{diff_total:,} ({sign}{trend['total_pct']}%)"]
        for i, value in enumerate(values, 2):
            cell = ws1.cell(row=row, column=i)
            cell.value = value
            cell.border = border
            cell.alignment = center
            cell.font = Font(name="Calibri", bold=(i in [2, 4, 5]), size=11, color=color if i == 5 else "000000")
        row += 2

    if new_rules:
        ws1.merge_cells(start_row=row, start_column=2, end_row=row, end_column=6)
        ws1.cell(row=row, column=2).value = f"NOUVELLES REGLES DETECTEES ({len(new_rules)})"
        ws1.cell(row=row, column=2).font = Font(name="Calibri", bold=True, size=13, color=ROUGE_FONCE)
        row += 1

        for rid in new_rules[:5]:
            ws1.cell(row=row, column=2).value = f"Rule {rid}"
            ws1.cell(row=row, column=2).font = Font(name="Calibri", bold=True, size=11, color=ROUGE_FONCE)
            ws1.cell(row=row, column=3).value = "Nouvelle regle detectee"
            ws1.merge_cells(start_row=row, start_column=3, end_row=row, end_column=6)
            row += 1
        row += 1

    ws1.merge_cells(start_row=row, start_column=2, end_row=row, end_column=9)
    ws1.cell(row=row, column=2).value = "ALERTES HIGH / CRITICAL"
    ws1.cell(row=row, column=2).font = section_font
    row += 1

    headers = ["Rule ID", "Level", "Description", "Hits", "Agents", "MITRE", "Verdict", "Raison"]
    for i, head in enumerate(headers, 2):
        cell = ws1.cell(row=row, column=i)
        cell.value = head
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = center
        cell.border = border
    row += 1

    for a in high_critical:
        verdict = normalize_verdict(a.get("ai_verdict"))
        reason = a.get("ai_reason", "-")

        if verdict == "A INVESTIGUER":
            fill_color = ROUGE
        elif verdict == "A VERIFIER":
            fill_color = ORANGE
        else:
            fill_color = VERT

        fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")

        values = [
            a["rule_id"],
            a["level"],
            a["description"],
            a["count"],
            a["agent_count"],
            a.get("mitre", "-"),
            verdict,
            reason,
        ]

        for i, value in enumerate(values, 2):
            cell = ws1.cell(row=row, column=i)
            cell.value = value
            cell.font = normal_font
            cell.border = border
            cell.fill = fill
            cell.alignment = wrap if i in [4, 9] else center

        ws1.row_dimensions[row].height = 46
        row += 1

    row += 1

    ws1.merge_cells(start_row=row, start_column=2, end_row=row, end_column=7)
    ws1.cell(row=row, column=2).value = "TOP 10 AGENTS LES PLUS ALERTES"
    ws1.cell(row=row, column=2).font = section_font
    row += 1

    headers = ["#", "Agent", "Total alertes", "High/Critical", "% du total"]
    for i, head in enumerate(headers, 2):
        cell = ws1.cell(row=row, column=i)
        cell.value = head
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = center
        cell.border = border
    row += 1

    for idx, a in enumerate(top_agents[:10], 1):
        fill = PatternFill(start_color=BLEU_CLAIR, end_color=BLEU_CLAIR, fill_type="solid")
        values = [idx, a["agent"], a["total"], a["high_critical"], f"{a['pct']}%"]

        for i, value in enumerate(values, 2):
            cell = ws1.cell(row=row, column=i)
            cell.value = value
            cell.font = normal_font
            cell.border = border
            cell.fill = fill
            cell.alignment = center
        row += 1

    # Onglet toutes les alertes
    ws2 = wb.create_sheet("Toutes les alertes")
    ws2.sheet_view.showGridLines = False
    ws2.sheet_view.zoomScale = 85
    ws2.freeze_panes = "A2"

    headers = ["Rule ID", "Level", "Description", "Hits", "Nb agents", "MITRE", "Verdict", "Raison"]
    for i, head in enumerate(headers, 1):
        cell = ws2.cell(row=1, column=i)
        cell.value = head
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = center
        cell.border = border

    all_rules = list(high_critical)
    hc_ids = {a["rule_id"] for a in high_critical}

    for n in noisy:
        if n["rule_id"] not in hc_ids:
            n["ai_verdict"] = "Non analyse"
            n["ai_reason"] = "Regle bruyante, niveau inferieur a 12."
            all_rules.append(n)

    all_rules.sort(key=lambda x: (verdict_priority(x.get("ai_verdict")), -x.get("level", 0), -x.get("count", 0)))

    for a in all_rules:
        row_num = ws2.max_row + 1
        verdict = normalize_verdict(a.get("ai_verdict")) if a.get("ai_verdict") != "Non analyse" else "Non analyse"
        reason = a.get("ai_reason", "-")

        if verdict == "A INVESTIGUER":
            fill_color = ROUGE
        elif verdict == "A VERIFIER":
            fill_color = ORANGE
        elif verdict == "FAUX POSITIF":
            fill_color = VERT
        else:
            fill_color = GRIS

        fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
        values = [
            a.get("rule_id", ""),
            a.get("level", ""),
            a.get("description", ""),
            a.get("count", ""),
            a.get("agent_count", ""),
            a.get("mitre", "-"),
            verdict,
            reason,
        ]

        for i, value in enumerate(values, 1):
            cell = ws2.cell(row=row_num, column=i)
            cell.value = value
            cell.font = normal_font
            cell.border = border
            cell.fill = fill
            cell.alignment = wrap if i in [3, 8] else center

        ws2.row_dimensions[row_num].height = 42

    ws2.column_dimensions["A"].width = 12
    ws2.column_dimensions["B"].width = 8
    ws2.column_dimensions["C"].width = 70
    ws2.column_dimensions["D"].width = 12
    ws2.column_dimensions["E"].width = 12
    ws2.column_dimensions["F"].width = 18
    ws2.column_dimensions["G"].width = 18
    ws2.column_dimensions["H"].width = 75
    ws2.auto_filter.ref = f"A1:H{ws2.max_row}"

    wb.save(output_path)
    print(f"  [OK] Excel : {output_path}")
    return output_path
```


## 12. Génération du PDF

`generate_pdf` construit le document lisible avec `reportlab` : un bandeau de chiffres clés, puis les alertes regroupées en trois catégories (à investiguer / à vérifier / faux positifs), chacune expliquée en langage clair.

```python

# =============================================================================
# PDF
# =============================================================================

def generate_pdf(high_critical, days, total, output_path):
    try:
        from reportlab.lib.colors import HexColor
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        print("[WARN] reportlab non installe. PDF non genere.")
        return None

    BLEU_NUIT = HexColor("#1F2A44")
    BLEU = HexColor("#1B4F72")
    VERT = HexColor("#1E8449")
    ROUGE = HexColor("#922B21")
    ORANGE = HexColor("#B7950B")
    GRIS = HexColor("#7F8C8D")
    GRIS_CLAIR = HexColor("#F4F6F7")
    BLANC = HexColor("#FFFFFF")

    now = datetime.now().strftime("%d/%m/%Y %H:%M")
    hc_count = sum(a["count"] for a in high_critical)

    alerts_invest = [a for a in high_critical if normalize_verdict(a.get("ai_verdict")) == "A INVESTIGUER"]
    alerts_verify = [a for a in high_critical if normalize_verdict(a.get("ai_verdict")) == "A VERIFIER"]
    alerts_fp = [a for a in high_critical if normalize_verdict(a.get("ai_verdict")) == "FAUX POSITIF"]

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=1.6 * cm,
        rightMargin=1.6 * cm,
        topMargin=1.3 * cm,
        bottomMargin=1.3 * cm,
    )

    page_width = A4[0] - 3.2 * cm

    styles = {
        "title": ParagraphStyle("title", fontSize=22, fontName="Helvetica-Bold", textColor=BLANC),
        "subtitle": ParagraphStyle("subtitle", fontSize=9, fontName="Helvetica", textColor=HexColor("#D6DBE5")),
        "section": ParagraphStyle("section", fontSize=14, fontName="Helvetica-Bold", textColor=BLEU_NUIT, spaceBefore=14, spaceAfter=8),
        "normal": ParagraphStyle("normal", fontSize=9, fontName="Helvetica", textColor=HexColor("#2C3E50"), leading=12),
        "small": ParagraphStyle("small", fontSize=8, fontName="Helvetica", textColor=GRIS, leading=11),
        "badge": ParagraphStyle("badge", fontSize=9, fontName="Helvetica-Bold", textColor=BLANC),
    }

    story = []

    header = Table([[Paragraph("ANALYSE DES ALERTES WAZUH", styles["title"])]], colWidths=[page_width])
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BLEU_NUIT),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
    ]))
    story.append(header)

    subtitle = Table([[Paragraph(f"{ORG_NAME} | {days} jours | {now} | Analyse IA locale + validation SOC", styles["subtitle"])]], colWidths=[page_width])
    subtitle.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#2C3E50")),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(subtitle)
    story.append(Spacer(1, 12))

    kpis = Table([
        [f"{total:,}", f"{hc_count:,}", str(len(alerts_invest)), str(len(alerts_verify)), str(len(alerts_fp))],
        ["Total alertes", "High / Critical", "A investiguer", "A verifier", "Faux positifs"],
    ], colWidths=[page_width / 5] * 5)

    kpis.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), BLEU),
        ("BACKGROUND", (1, 0), (1, -1), ROUGE),
        ("BACKGROUND", (2, 0), (2, -1), ROUGE),
        ("BACKGROUND", (3, 0), (3, -1), ORANGE),
        ("BACKGROUND", (4, 0), (4, -1), VERT),
        ("TEXTCOLOR", (0, 0), (-1, -1), BLANC),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 17),
        ("FONTSIZE", (0, 1), (-1, 1), 7),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(kpis)
    story.append(Spacer(1, 14))

    intro = (
        "Ce rapport classe les alertes importantes en trois categories : "
        "<b>A investiguer</b>, <b>A verifier</b> et <b>Faux positifs probables</b>. "
        "Le verdict final applique une logique SOC avant l'analyse IA afin d'eviter de masquer "
        "les alertes sensibles comme les CVE, PowerShell, RDP ou depots d'executables."
    )
    story.append(Paragraph(intro, styles["normal"]))
    story.append(Spacer(1, 10))

    def add_alert_section(title, alerts, badge_text, badge_color, card_color):
        story.append(Paragraph(title, styles["section"]))

        if not alerts:
            story.append(Paragraph("Aucune alerte dans cette categorie.", styles["normal"]))
            story.append(Spacer(1, 8))
            return

        for a in alerts:
            detail = a.get("ai_detail", "Analyse indisponible")
            top_agent = a["agents"][0][0] if a.get("agents") else "-"

            title_para = Paragraph(f"<b>Rule {a['rule_id']}</b> - {a['description'][:100]}", styles["normal"])
            badge = Paragraph(f"<b>{badge_text}</b>", styles["badge"])

            top = Table([[title_para, badge]], colWidths=[page_width * 0.73, page_width * 0.23])
            top.setStyle(TableStyle([
                ("BACKGROUND", (1, 0), (1, 0), badge_color),
                ("ALIGN", (1, 0), (1, 0), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (1, 0), (1, 0), 5),
                ("BOTTOMPADDING", (1, 0), (1, 0), 5),
            ]))
            story.append(top)

            meta = (
                f"Level {a['level']} | {a['count']} hits | {a['agent_count']} agent(s) | "
                f"Agent principal : {top_agent} | MITRE : {a.get('mitre', '-')}"
            )
            story.append(Paragraph(meta, styles["small"]))

            detail_clean = detail.replace("\n", "<br/>")
            for label in ["SIGNIFICATION:", "CAUSE PROBABLE:", "ACTION:"]:
                detail_clean = detail_clean.replace(label, f"<b>{label}</b>")

            detail_table = Table([[Paragraph(detail_clean, styles["normal"])]], colWidths=[page_width])
            detail_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), card_color),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(detail_table)
            story.append(Spacer(1, 10))

    add_alert_section("1. Alertes a investiguer en priorite", alerts_invest, "A INVESTIGUER", ROUGE, HexColor("#FEF5E7"))
    add_alert_section("2. Alertes a verifier", alerts_verify, "A VERIFIER", ORANGE, GRIS_CLAIR)
    add_alert_section("3. Faux positifs probables", alerts_fp, "FAUX POSITIF", VERT, HexColor("#D5F5E3"))

    doc.build(story)
    print(f"  [OK] PDF : {output_path}")
    return output_path
```


## 13. Envoi de l'email

`send_email` prépare un message récapitulatif, y joint l'Excel et le PDF, puis l'envoie via SMTP (`STARTTLS` + login). L'option `--no-email` court-circuite l'envoi.

```python

# =============================================================================
# EMAIL
# =============================================================================

def send_email(excel_path, total, high_critical, days, use_email=True, pdf_path=None):
    if not use_email:
        print("  [INFO] Envoi email desactive (--no-email)")
        return

    if not SMTP_PASS or SMTP_PASS in ("VOTRE_CLE_SECRETE_SMTP", "TON_MOT_DE_PASSE_SMTP_ICI"):
        print("  [WARN] Mot de passe SMTP non configure. Email non envoye.")
        return

    week = datetime.now().strftime("%W")
    hc_count = sum(a["count"] for a in high_critical)
    nb_fp = sum(1 for a in high_critical if normalize_verdict(a.get("ai_verdict")) == "FAUX POSITIF")
    nb_invest = sum(1 for a in high_critical if normalize_verdict(a.get("ai_verdict")) == "A INVESTIGUER")
    nb_verify = sum(1 for a in high_critical if normalize_verdict(a.get("ai_verdict")) == "A VERIFIER")

    body = f"""Bonjour,

Veuillez trouver ci-joint le rapport de securite {ORG_NAME} pour les {days} derniers jours.

Resume general :
- Nombre total d'alertes : {total:,}
- Alertes importantes ou critiques : {hc_count:,}
- Alertes a investiguer en priorite : {nb_invest}
- Alertes a verifier : {nb_verify}
- Faux positifs probables : {nb_fp}

Lecture rapide :
Le fichier Excel donne une vue synthetique des volumes d'alertes, des tendances et des postes les plus concernes.
Le fichier PDF separe les alertes en trois categories :
- A investiguer
- A verifier
- Faux positifs probables

Points d'attention :
- Les alertes marquees "A investiguer" doivent etre traitees en priorite.
- Les alertes marquees "A verifier" necessitent une confirmation selon le contexte.
- Les alertes marquees "Faux positif" ne necessitent pas d'action immediate, sauf changement de contexte.
- Si une alerte concerne une CVE, un executable, PowerShell ou RDP, elle est conservee dans les alertes a verifier ou a investiguer.

Pieces jointes :
- Excel : synthese du rapport, tendances, agents concernes et detail des alertes
- PDF : analyse lisible des alertes importantes, triees par categorie

Ce rapport est genere automatiquement par la supervision securite {ORG_NAME}.

Cordialement,
Supervision securite {ORG_NAME}
"""

    msg = MIMEMultipart()
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(EMAIL_TO)
    msg["Subject"] = EMAIL_SUBJECT.format(week=week)
    msg.attach(MIMEText(body, "plain", "utf-8"))

    with open(excel_path, "rb") as f:
        attachment = MIMEBase("application", "octet-stream")
        attachment.set_payload(f.read())
        encoders.encode_base64(attachment)
        filename = os.path.basename(excel_path)
        attachment.add_header("Content-Disposition", f"attachment; filename={filename}")
        msg.attach(attachment)

    if pdf_path and os.path.exists(pdf_path):
        with open(pdf_path, "rb") as f:
            attachment_pdf = MIMEBase("application", "octet-stream")
            attachment_pdf.set_payload(f.read())
            encoders.encode_base64(attachment_pdf)
            pdf_filename = os.path.basename(pdf_path)
            attachment_pdf.add_header("Content-Disposition", f"attachment; filename={pdf_filename}")
            msg.attach(attachment_pdf)

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_SENDER, EMAIL_TO, msg.as_string())
        server.quit()
        print(f"  [OK] Email envoye a {', '.join(EMAIL_TO)}")
    except Exception as e:
        print(f"  [ERREUR] Envoi email echoue : {e}")
        print(f"  Rapport disponible : {excel_path}")
```


## 14. Orchestration (`main`)

Le `main` enchaîne les six étapes dans l'ordre : lecture → analyse → tri SOC + IA → comparaison avec le rapport précédent → génération Excel + PDF → envoi email. Il gère aussi les options de lancement : `--days` (période), `--no-email` et `--no-ai`.

```python

# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Rapport hebdomadaire securite Wazuh")
    parser.add_argument("--days", type=int, default=7, help="Periode en jours, defaut 7")
    parser.add_argument("--no-email", action="store_true", help="Ne pas envoyer par email")
    parser.add_argument("--no-ai", action="store_true", help="Desactiver l'analyse IA")
    args = parser.parse_args()

    print("=" * 60)
    print("  RAPPORT HEBDOMADAIRE WAZUH")
    print(f"  Periode : {args.days} jours")
    print(f"  Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    if not os.path.exists(ALERTS_FILE):
        print(f"\n[ERREUR] Fichier non trouve : {ALERTS_FILE}")
        sys.exit(1)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("\n[1/6] Lecture des alertes...")
    rules_data, total = parse_alerts(days=args.days)

    if total == 0:
        print("[WARN] Aucune alerte trouvee.")
        sys.exit(0)

    print("\n[2/6] Analyse...")
    high_critical, top_agents, noisy = analyze(rules_data, total)
    print(f"  Alertes High/Critical : {sum(a['count'] for a in high_critical):,}")
    print(f"  Top agents : {len(top_agents)}")
    print(f"  Regles bruyantes : {len(noisy)}")

    print("\n[3/6] Analyse IA + logique SOC...")
    if args.no_ai:
        high_critical = analyze_alerts_with_ai(high_critical, use_ai=False)
        print("  [INFO] IA desactivee (--no-ai)")
    else:
        high_critical = analyze_alerts_with_ai(high_critical, use_ai=True)
        nb_fp = sum(1 for a in high_critical if normalize_verdict(a.get("ai_verdict")) == "FAUX POSITIF")
        nb_invest = sum(1 for a in high_critical if normalize_verdict(a.get("ai_verdict")) == "A INVESTIGUER")
        nb_verify = sum(1 for a in high_critical if normalize_verdict(a.get("ai_verdict")) == "A VERIFIER")
        print(f"  [OK] A investiguer: {nb_invest} | A verifier: {nb_verify} | Faux positifs: {nb_fp}")

    print("\n[4/6] Comparaison avec le run precedent...")
    history = load_history()
    hc_count = sum(a["count"] for a in high_critical)
    current_rule_ids = list(rules_data.keys())
    trend = compute_trend(history, total, hc_count)
    new_rules = find_new_rules(history, current_rule_ids)
    agent_changes = find_agent_changes(history, top_agents)

    if trend.get("total") is not None:
        sign = "+" if trend["total"] > 0 else ""
        print(f"  Total : {sign}{trend['total']:,} ({sign}{trend['total_pct']}%)")
    else:
        print("  [INFO] Pas de run precedent")

    if new_rules:
        print(f"  {len(new_rules)} nouvelle(s) regle(s) detectee(s)")

    if agent_changes:
        print(f"  {len(agent_changes)} agent(s) avec changement important")

    print("\n[5/6] Generation Excel + PDF...")
    ts = datetime.now().strftime("%Y%m%d")
    week = datetime.now().strftime("%W")

    excel_path = os.path.join(OUTPUT_DIR, f"rapport_wazuh_S{week}_{ts}.xlsx")
    generate_excel(
        high_critical,
        top_agents,
        noisy,
        args.days,
        total,
        excel_path,
        trend=trend,
        new_rules=new_rules,
        agent_changes=agent_changes,
    )

    pdf_path = None
    if not args.no_ai:
        pdf_path = os.path.join(OUTPUT_DIR, f"analyse_ia_S{week}_{ts}.pdf")
        pdf_path = generate_pdf(high_critical, args.days, total, pdf_path)

    save_history(history, total, hc_count, current_rule_ids, top_agents)

    print("\n[6/6] Envoi email...")
    send_email(
        excel_path,
        total,
        high_critical,
        args.days,
        use_email=not args.no_email,
        pdf_path=pdf_path,
    )

    print("\n" + "=" * 60)
    print("  RAPPORT TERMINE")
    print(f"  Excel : {excel_path}")
    if pdf_path:
        print(f"  PDF   : {pdf_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
```


---

## 15. Utilisation

```bash
sudo python3 rapport_wazuh.py                # rapport sur 7 jours (défaut)
sudo python3 rapport_wazuh.py --days 14      # période personnalisée
sudo python3 rapport_wazuh.py --no-email     # générer sans envoyer
sudo python3 rapport_wazuh.py --no-ai        # désactiver l'analyse IA
```

Planification hebdomadaire (par ex. chaque lundi à 7h) via `crontab -e` :

```
0 7 * * 1 cd /chemin/vers/TON_REPO && set -a && . ./.env && set +a && /usr/bin/python3 rapport_wazuh.py >> /var/log/rapport_wazuh.log 2>&1
```

## 16. Points à adapter

- **`OLLAMA_MODEL`** : changer le modèle d'IA local utilisé.
- **`SEUIL_NOUVELLE_REGLE_BRUYANTE`** : ajuster ce qui est considéré comme une règle trop bavarde.
- **`EMAIL_TO`** : adapter la liste de diffusion.
- **Seuil de gravité** : le niveau 12 (alertes High/Critical) est codé dans `analyze` et `soc_verdict_override` ; à ajuster si votre politique diffère.
- **`--no-ai`** : permet de faire tourner le rapport même sans Ollama installé.
