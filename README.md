# Rapport hebdomadaire de sécurité Wazuh


<img src="1704200958877.png" width="100%">

Script Python qui lit les alertes d'un SIEM **Wazuh**, les trie et les classe
automatiquement, puis génère et envoie par email un rapport **Excel** + **PDF**.

Ce que j'ai fait, c'est un programme qui lit toutes ces alertes automatiquement, fait le tri, et décide lesquelles sont juste du bruit et lesquelles méritent vraiment qu'on s'en occupe. Le script s'aide d'une petite intelligence artificielle qui tourne directement sur le serveur en local, donc rien ne sort en public, pour expliquer chaque alerte de manière simple et non technique. Et il y a une règle de sécurité : si une alerte touche à quelque chose de potentiellement grave, elle est toujours mise en avant, jamais ignorée, que cela soit en excel ou en PDF. Le script s'occupe d'envoyer un mail tout les jours à la même heure dans une boîte mail.

L'objectif : transformer des centaines de milliers d'alertes hebdomadaires en une
poignée d'alertes réellement à traiter par un analyste.

> Sur une semaine type : **218 606 alertes** analysées → **9** classées « à investiguer ».

---

## Fonctionnalités

- Lecture directe des journaux d'alertes Wazuh (fichier courant + archives `.gz`)
- Classement automatique de chaque alerte importante : **À investiguer**, **À vérifier** ou **Faux positif**
- Logique « analyste sécurité » (SOC) appliquée **avant** l'IA, pour ne jamais masquer une alerte sensible (CVE, malware, PowerShell, RDP, exécutable déposé…)
- Analyse complétée par une **IA locale** (Ollama) — aucune donnée envoyée à l'extérieur
- Comparaison avec la semaine précédente : tendance, nouvelles règles, postes en hausse
- Rapport **Excel** (synthèse + détail filtrable) et **PDF** (analyse lisible)
- **Envoi automatique par email** à l'équipe

---

## Aperçu des livrables

### Excel — onglet de synthèse

<img src="excel_resume.png" width="100%">

Vue d'ensemble : nombre total d'alertes, combien sont graves, et celles à traiter en
priorité. La ligne « tendance » montre l'évolution par rapport à la semaine précédente.

### Excel — détail de toutes les alertes

<img src="excel_alertes.png" width="100%">

La liste complète. Chaque alerte reçoit un verdict et une explication ; les colonnes
sont triables et filtrables.

### PDF — analyse lisible, triée par priorité

<p>
  <img src="pdf_p1.png" width="49%">
  <img src="pdf_p2.png" width="49%">
</p>

La version la plus lisible : chaque alerte importante est résumée en trois points —
ce que ça signifie, la cause probable, et l'action à mener.

---

## Comment ça marche

1. **Lecture** — le script lit directement les journaux d'alertes de Wazuh.
2. **Analyse** — il repère les alertes graves, les postes les plus touchés et les règles bruyantes.
3. **Tri** — une logique SOC s'applique, complétée par une IA locale.
4. **Classement** — chaque alerte importante reçoit un verdict (à investiguer / à vérifier / faux positif).
5. **Rapports** — génération d'un Excel et d'un PDF, avec la tendance hebdomadaire.
6. **Envoi** — les deux fichiers partent automatiquement par email.

---

## L'IA utilisée

- **Outil** : [Ollama](https://ollama.com) — exécution de modèles d'IA en local
- **Modèle** : `gemma3:1b`
- **Réglages** : température `0.1` (réponses stables), réponses courtes

L'IA ne décide jamais seule : toute alerte évoquant une CVE, un malware, PowerShell,
RDP ou un exécutable déposé est **forcée en « à investiguer »**, quel que soit l'avis du modèle.

---

## Prérequis

- Python 3
- Accès en lecture aux journaux Wazuh (`/var/ossec/logs/alerts/`)
- Bibliothèques : `openpyxl`, `reportlab`, `requests`
- *(optionnel)* Ollama installé en local avec le modèle `gemma3:1b`

---

## Installation

```bash
git clone https://github.com/TON_USER/TON_REPO.git
cd TON_REPO
pip install openpyxl reportlab requests
```

---

## Configuration

Les secrets (identifiants SMTP, destinataires) ne sont **jamais** écrits dans le code.
Ils sont lus depuis des variables d'environnement.

Copiez le modèle fourni puis renseignez vos valeurs :

```bash
cp .env.example .env
# éditez .env avec vos vraies valeurs
```

Avant de lancer le script, chargez ces variables dans votre session :

```bash
set -a && source .env && set +a
```

> ⚠️ Le fichier `.env` contient vos secrets : il est listé dans `.gitignore` et ne doit
> **jamais** être poussé sur GitHub.

---

## Utilisation

```bash
sudo python3 rapport_wazuh.py                # rapport sur 7 jours (défaut)
sudo python3 rapport_wazuh.py --days 14      # période personnalisée
sudo python3 rapport_wazuh.py --no-email     # générer sans envoyer
sudo python3 rapport_wazuh.py --no-ai        # désactiver l'analyse IA
```

`sudo` sert uniquement à lire les journaux Wazuh.

---

## Documentation

Le fonctionnement détaillé, **code et explications réunis section par section**, est dans
[`GUIDE_TECHNIQUE_rapport_wazuh.md`](GUIDE_TECHNIQUE_rapport_wazuh.md).

---

## Structure du projet

```
.
├── rapport_wazuh.py     # script principal
├── .env.example         # modèle de configuration (sans valeurs réelles)
├── .env                 # vos secrets — ignoré par git, jamais commité
├── .gitignore
├──                 # captures utilisées dans ce README
└── README.md
```

---

## Sécurité

- Dépôt recommandé en **privé** (code de supervision sécurité).
- **Aucun secret dans le code** : tout passe par `.env` + variables d'environnement.
- Si un identifiant a déjà été exposé, considérez-le comme compromis et **régénérez-le**.
