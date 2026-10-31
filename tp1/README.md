# TP 1 – Chiffrement authentifié et dérivation de clés

**Auteur :** NEBIE Bonaventure Elisée  
**Module :** EC1 – Ingénierie de la cryptographie (Dr Zakaria Sawadogo, 2026–2027)  
**Environnement :** Kali Linux (machine virtuelle)

> **Règle de sécurité :** ce dépôt ne contient **aucune clé privée** ni mot de passe (`*.key` est exclu par `.gitignore`). Seuls les certificats publics sont fournis. Les noms utilisés sont des noms de laboratoire (`*.tp.local`), sur la machine locale.

## Description

Mini-coffre de fichiers en Python (`coffre.py`) : un fichier est chiffré avec un mot de passe. La clé est dérivée avec **Argon2id**, des sous-clés indépendantes sont produites avec **HKDF-SHA256**, et les données sont chiffrées avec **AES-256-GCM** (chiffrement authentifié). Aucune primitive n'est réimplémentée : on assemble des briques éprouvées (`cryptography`, `argon2-cffi`).

## Format du fichier chiffré (`CFR1`)

| Champ | Taille | Rôle |
|---|---|---|
| Identifiant `CFR1` | 4 octets | Reconnaître le format et sa version |
| Paramètres Argon2id (t, m, p) | 12 octets | Redériver la clé, durcir plus tard |
| Sel | 16 octets | Dérivation unique par fichier |
| Nonce | 12 octets | Unique pour chaque chiffrement |
| Chiffré + étiquette | variable | Données protégées par AES-GCM |

Les 44 premiers octets (l'en-tête) et le nom du fichier sont les **données associées** : authentifiés sans être chiffrés.
Paramètres retenus : `T = 3`, `M = 128 Mio`, `P = 4` (environ 0,5 s par dérivation sur la machine de test).

## Fichiers

- `coffre.py` : `cle_maitresse`, `sous_cle`, `chiffrer`, `dechiffrer`, `rechiffrer`.
- `test_coffre.py` : 6 tests pytest.
- Compte rendu : [../docs/CR_TP1.docx](../docs/CR_TP1.docx)

## Utilisation

```bash
python3 -m venv ~/ec1 && source ~/ec1/bin/activate
pip install cryptography argon2-cffi pytest
python3 -m pytest -v
```

## Tests (propriétés de sécurité vérifiées)

| Test | Propriété |
|---|---|
| Aller-retour | Correction |
| Chiffrer deux fois le même fichier | Chiffrement probabiliste (sel et nonce neufs) |
| Mauvais mot de passe | Authentification de la clé (`InvalidTag`) |
| Octet du chiffré modifié | Intégrité (`InvalidTag`) |
| Fichier renommé | Liaison au contexte par les données associées |
| Changement de mot de passe | `rechiffrer` conserve les données |
