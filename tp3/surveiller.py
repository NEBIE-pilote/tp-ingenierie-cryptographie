#!/usr/bin/env python3
"""surveiller.py - jours restants des certificats d'un dossier.
Usage : python3 surveiller.py [dossier]
Code de sortie : 0 = OK, 1 = ALERTE (<30 j), 2 = CRITIQUE (<7 j ou expire)."""
import sys
import pathlib
from datetime import datetime, timezone
from cryptography import x509

SEUIL_ALERTE = 30
SEUIL_CRITIQUE = 7


def niveau(jours):
    if jours < SEUIL_CRITIQUE:
        return 2, "CRITIQUE"
    if jours < SEUIL_ALERTE:
        return 1, "ALERTE"
    return 0, "OK"


def date_fin(cert):
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def main():
    dossier = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    maintenant = datetime.now(timezone.utc)
    pire = 0
    trouve = False
    for f in sorted(dossier.iterdir()):
        if not f.is_file() or f.suffix not in (".crt", ".pem", ".cer"):
            continue
        try:
            certs = x509.load_pem_x509_certificates(f.read_bytes())
        except ValueError:
            continue  # pas un certificat (ex. liste de revocation)
        for c in certs:
            trouve = True
            jours = (date_fin(c) - maintenant).days
            code, nom = niveau(jours)
            pire = max(pire, code)
            sujet = c.subject.rfc4514_string()
            print(f"{nom:<9} {jours:>5} j  {f.name:<16} {sujet}  (fin : {date_fin(c):%Y-%m-%d})")
    if not trouve:
        print("Aucun certificat trouve dans", dossier)
    return pire


if __name__ == "__main__":
    sys.exit(main())
