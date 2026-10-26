# MongoPi — vérificateur d'exposition MongoDB sans authentification

Vérifie, sur une liste de cibles que vous fournissez explicitement, si une instance MongoDB répond sans authentification et, si oui, remonte les bases/collections exposées et une estimation du nombre de documents — comme preuve à joindre à un rapport de pentest, pas comme outil d'extraction en masse.
*Checks a list of explicitly provided targets for MongoDB instances answering without authentication, and reports exposed databases/collections with an approximate document count.*

> **Usage autorisé uniquement, labs de pentest.** Pas de scan internet ni de découverte automatique : seules les cibles listées via `--targets`/`--targets-file` sont jamais contactées, et `--authorized` doit être passé explicitement pour confirmer l'autorisation avant toute connexion.

## Portée, par construction
- Aucun mode de scan automatique/internet : uniquement les hôtes que vous listez.
- `--authorized` est **obligatoire** pour se connecter — un garde-fou volontaire, pas un simple avertissement.
- Rapporte l'exposition (authentification requise ou non, noms de bases/collections, nombre approximatif de documents) ; ne télécharge jamais les documents en masse — faites une requête ciblée vous-même si vous avez besoin d'un échantillon précis pour votre rapport.
- `--proxy` route tout le trafic vers **un seul** proxy configuré (SOCKS5/SOCKS4/HTTP — ex. un jump host ou une passerelle VPN de la mission), sans liste ni rotation : ce n'est pas un outil de dissimulation d'origine.

## Usage
```bash
pip install -r requirements.txt
python3 mongopi.py --targets 10.0.0.5,10.0.0.6:27018 --authorized
python3 mongopi.py --targets-file cibles.txt --authorized --json-report rapport.json
python3 mongopi.py --targets mongo.lab.local --authorized --proxy socks5://127.0.0.1:1080
```

## Options
| Option | Rôle |
|---|---|
| `--targets` | Liste `host[:port]` séparée par des virgules |
| `--targets-file` | Fichier avec un `host[:port]` par ligne (`#` pour les commentaires) |
| `--port` | Port par défaut si non précisé (défaut `27017`) |
| `--timeout-ms` | Timeout de connexion en ms (défaut `6000`) |
| `--retries` | Tentatives supplémentaires avant de marquer une cible inaccessible |
| `--workers` | Connexions concurrentes (défaut `5`) |
| `--include-system-dbs` | Inclut aussi `admin`/`local`/`config` dans l'énumération |
| `--tls` | Se connecte en TLS |
| `--tls-insecure` | Avec `--tls` : ignore la validation du certificat (certificats auto-signés de lab) |
| `--proxy` | Route via un unique proxy `socks5://`, `socks4://` ou `http://` |
| `--json-report` | Écrit le rapport complet en JSON à ce chemin |
| `--authorized` | **Obligatoire** : confirme l'autorisation explicite sur chaque cible listée |

## Dépendances
```
pymongo>=4.6
pyfiglet>=1.0
PySocks>=1.7
```
`pyfiglet` et `PySocks` sont optionnels à l'exécution (bannière et `--proxy` de secours sans eux) mais listés pour une installation sans surprise.
