# vigilien

**Évalue le risque d'hameçonnage (phishing) d'un lien, avant de cliquer.**

Au Bénin comme ailleurs, les arnaques passent par des liens reçus sur WhatsApp ou par SMS :
« votre compte MoMo est suspendu », « remboursement d'amende », « gagnez un bonus ».
`vigilien` prend un lien et rend un **score de risque de 0 à 100**, avec la liste des raisons,
écrites pour être comprises par quelqu'un qui n'est pas informaticien.

L'outil est **purement défensif** : il analyse un lien, il n'attaque rien. Il ne télécharge pas
les pages, n'exécute aucun JavaScript, n'envoie aucun formulaire, et refuse de contacter les
adresses du réseau interne (127.0.0.1, 192.168.x.x…), même si une redirection l'y pousse.

```
$ vigilien "http://mtn.bj.verification-compte.xyz/momo/login"
🔴 Risque élevé : 60/100
   Lien     : http://mtn.bj.verification-compte.xyz/momo/login
   Domaine  : verification-compte.xyz
   Signaux :
     +25  Le nom « mtn » apparaît, mais le site n'appartient pas à cette marque (domaine réel : verification-compte.xyz)
     +15  Mots typiques des demandes d'identifiants ou de paiement (compte, login, momo, verification)
     +10  Connexion non chiffrée (http)
     +10  Extension de domaine très utilisée par l'hameçonnage (.xyz)
```

## Installation

Python 3.10 ou plus récent.

```bash
git clone https://github.com/kabirADEMON/vigilien.git
cd vigilien
python -m venv .venv
.venv\Scripts\activate        # Windows  (Linux/macOS : source .venv/bin/activate)
pip install -e ".[dev]"
```

## Utilisation

```bash
vigilien "https://lien-a-verifier.com/page"          # analyse complète
vigilien lien1 lien2 lien3                            # plusieurs liens
vigilien --hors-ligne "https://..."                   # sans aucune connexion : texte du lien seulement
vigilien --json "https://..."                         # sortie JSON, pour un autre programme
```

Code de sortie : `0` risque faible, `1` modéré, `2` élevé, `3` lien illisible.
On peut donc l'utiliser dans un script (`vigilien "$lien" || echo "à vérifier"`).

Depuis Python :

```python
from vigilien import analyse

rapport = analyse("https://exemple.com/login")
print(rapport.score, rapport.verdict)   # 5 faible
print(rapport.to_dict())
```

## Ce qui est vérifié

| Vérification | Ce qu'elle repère | Points |
|---|---|---|
| **Usurpation de marque** | `mtn`, `paypal`, `fedapay`… dans le nom, alors que le domaine réel n'appartient pas à la marque | +25 |
| **Faux site public** | `gouv` dans le nom, mais hors de `.gouv.bj` | +25 |
| **Certificat invalide** | expiré, autosigné, ne correspond pas au site | +25 |
| **Adresse IP** | le lien pointe vers `http://41.x.x.x/` au lieu d'un nom | +25 |
| **Domaine très récent** | créé il y a moins de 30 jours (moins de 6 mois : +15) | +30 |
| **Homographe** | `pаypal.com` écrit avec un « а » cyrillique : invisible à l'œil | +20 |
| **Arobase** | `https://mtn.bj@site-pirate.com` : tout ce qui précède `@` est ignoré ; +35 si c'est un faux nom de site | +20 à +35 |
| **Change de site** | les redirections mènent vers un autre domaine | +15 |
| **Mots-clés** | `login`, `verify`, `compte`, `paiement`, `momo`… (5 par mot, 15 au plus) | +5 à +15 |
| Redirections multiples, perte du https, raccourcisseur, extension suspecte (`.xyz`, `.top`…), port inhabituel, connexion http, beaucoup de sous-domaines | | +10 chacun |
| Certificat émis il y a moins d'une semaine, chaîne de certificats incomplète, nom ou lien très long, tirets | | +5 chacun |

Score plafonné à 100. Verdict : **faible** sous 25, **modéré** de 25 à 59, **élevé** à partir de 60.
Les seuils sont prudents : un lien « modéré » mérite déjà qu'on vérifie par un autre moyen.

**Âge du domaine.** Il est lu via **RDAP**, le successeur normalisé de WHOIS : une réponse JSON
structurée au lieu d'un texte libre différent selon chaque registre.

## Limites, honnêtement

- **Un score faible n'est pas une garantie.** Un site piraté mais ancien, sur un vrai domaine, passera.
  L'outil repère des signaux, il ne lit pas le contenu des pages.
- **Le registre `.bj` ne publie pas l'âge des domaines** (pas de RDAP). Pour un `.bj`, l'âge reste
  « inconnu » et ne pèse pas dans le score.
- **Les listes** (marques et leurs domaines officiels, extensions suspectes, raccourcisseurs, mots-clés)
  sont dans [`src/vigilien/data.py`](src/vigilien/data.py) : elles résument des tendances et doivent être
  maintenues. Une marque absente de la liste ne sera pas reconnue.
- **Faux positifs possibles** : un site légitime peut cumuler des mots-clés (`/login`) et un
  certificat récent. C'est pourquoi chaque point est expliqué.
- Entre la vérification de l'adresse et la connexion, un nom de domaine pourrait changer d'adresse
  (DNS rebinding). Pour un usage en ligne de commande, le risque est faible ; un service web
  exposé devrait épingler l'adresse résolue.

## Vérifié sur de vrais sites

Le 12 octobre 2026, sur des sites légitimes : google.com, fr.wikipedia.org, numerique.gouv.bj,
service-public.bj, fedapay.com, ecobank.com et moov-africa.bj obtiennent tous un risque **faible**
(0 à 5/100). Les certificats expiré et autosigné de [badssl.com](https://badssl.com) sont bien
détectés, et `http://127.0.0.1` n'est jamais contacté.

## Tests

```bash
pytest
```

23 tests, **sans aucune connexion** : les réponses réseau (RDAP, redirections, certificats) sont
simulées. Ils couvrent chaque signal, le blocage des adresses internes (y compris par redirection),
le calcul du score et la ligne de commande. Ils tournent sur GitHub Actions à chaque envoi.

## Structure

```
src/vigilien/
  url_checks.py   analyse hors ligne du lien (marques, homographes, IP, mots-clés…)
  network.py      RDAP, redirections, certificat, blocage des adresses internes
  analyse.py      assemble les vérifications en un rapport
  signals.py      structure d'un signal, score et verdict
  data.py         listes de référence à maintenir
  cli.py          ligne de commande
```

## Licence

MIT. Auteur : [Kabir ADEMON](https://portfolio-six-opal-16.vercel.app).
