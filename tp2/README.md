# TP 2 – Construire une infrastructure de gestion de clés

**Auteur :** NEBIE Bonaventure Elisée  
**Module :** EC1 – Ingénierie de la cryptographie (Dr Zakaria Sawadogo, 2026–2027)  
**Environnement :** Kali Linux (machine virtuelle)

> **Règle de sécurité :** ce dépôt ne contient **aucune clé privée** ni mot de passe (`*.key` est exclu par `.gitignore`). Seuls les certificats publics sont fournis. Les noms utilisés sont des noms de laboratoire (`*.tp.local`), sur la machine locale.

## Description

Infrastructure de clés construite avec **OpenSSL** : une AC racine, une AC intermédiaire restreinte, des certificats de serveur et de client, et la révocation d'un certificat par une liste de révocation (CRL).

| Élément | Clé et durée | Extensions essentielles |
|---|---|---|
| AC racine | P-384, 10 ans, hors ligne | `CA:TRUE, pathlen:1` ; signature de certificats et de CRL |
| AC intermédiaire | P-256, 5 ans | `CA:TRUE, pathlen:0` ; contraintes de nom limitées à `tp.local` |
| Serveur `www.tp.local` | P-256, 90 jours | `CA:FALSE` ; usage serveur TLS ; noms alternatifs |
| Client `alice@tp.local` | P-256, 90 jours | `CA:FALSE` ; usage client TLS |

## Fichiers

- `pki.sh` : crée l'arborescence puis enchaîne racine, intermédiaire, serveur et Alice (`set -euo pipefail`, `umask 077`).
- `racine.cnf`, `inter.cnf` : configurations d'`openssl ca` fournies par l'énoncé.
- `racine.crt`, `inter.crt`, `serveur.crt`, `alice.crt` : certificats **publics**.
- `crls.pem` : CRL de l'intermédiaire et de la racine (le certificat d'Alice y est révoqué, `keyCompromise`).
- Compte rendu : [../docs/CR_TP2.docx](../docs/CR_TP2.docx)

## Utilisation

```bash
./pki.sh    # à lancer dans un dossier contenant racine.cnf et inter.cnf
```

Validations :

```bash
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt -verify_hostname www.tp.local serveur.crt
openssl verify -crl_check_all -CRLfile crls.pem -CAfile racine/racine.crt -untrusted inter/inter.crt alice.crt   # revoked
```
