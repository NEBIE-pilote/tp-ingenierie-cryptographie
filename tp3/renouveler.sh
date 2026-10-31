#!/usr/bin/env bash
# renouveler.sh - renouvellement du certificat serveur www.tp.local
# Usage : sudo ./renouveler.sh [--force]
set -euo pipefail

PKI="$(cd "$(dirname "$0")" && pwd)"
TLS=/etc/nginx/tls
SEUIL_JOURS=30
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

cd "$PKI"
umask 077

# 0. Faut-il renouveler ?
if [ "$FORCE" -eq 0 ] && openssl x509 -in "$TLS/serveur_chaine.crt" -noout \
     -checkend $((SEUIL_JOURS * 86400)) >/dev/null; then
  echo "Certificat valable plus de $SEUIL_JOURS jours : rien a faire."
  exit 0
fi

HORO=$(date +%Y%m%d-%H%M%S)
NEW="renouv_$HORO"
mkdir "$NEW"
echo "== Renouvellement $HORO =="

# 1. Nouvelle cle et nouvelle demande
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$NEW/serveur.key"
openssl req -new -key "$NEW/serveur.key" -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out "$NEW/serveur.csr"

# 2. Signature par l'intermediaire
openssl ca -batch -notext -config inter.cnf -extensions ext_serveur -days 90 \
  -in "$NEW/serveur.csr" -out "$NEW/serveur.crt"
chown -R --reference="$PKI" inter "$NEW"

# 3. Verification AVANT deploiement
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local "$NEW/serveur.crt"
CERT_PUB=$(openssl x509 -in "$NEW/serveur.crt" -noout -pubkey)
KEY_PUB=$(openssl pkey -in "$NEW/serveur.key" -pubout)
if [ "$CERT_PUB" != "$KEY_PUB" ]; then
  echo "ERREUR : la cle ne correspond pas au certificat" >&2
  exit 1
fi
cat "$NEW/serveur.crt" inter/inter.crt > "$NEW/serveur_chaine.crt"

# 5. Conserver l'ancien certificat (retour arriere possible)
SAUV="$TLS/archive/$HORO"
install -d -m 700 "$SAUV"
cp -p "$TLS/serveur.key" "$TLS/serveur_chaine.crt" "$SAUV/"

# 4. Installer, tester, recharger sans interruption
install -m 600 "$NEW/serveur.key" "$TLS/serveur.key"
install -m 644 "$NEW/serveur_chaine.crt" "$TLS/serveur_chaine.crt"
if nginx -t && systemctl reload nginx; then
  echo "Deploiement OK. Nouvelle echeance :"
  openssl x509 -in "$TLS/serveur_chaine.crt" -noout -enddate
  echo "Ancienne version archivee dans $SAUV"
else
  echo "ECHEC nginx : retour arriere" >&2
  cp -p "$SAUV/serveur.key" "$TLS/serveur.key"
  cp -p "$SAUV/serveur_chaine.crt" "$TLS/serveur_chaine.crt"
  systemctl reload nginx
  exit 1
fi
