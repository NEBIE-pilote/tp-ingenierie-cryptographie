#!/usr/bin/env bash
# pki.sh - etapes 2 a 4 du TP2 : racine, intermediaire, serveur, client alice
# A lancer dans le dossier pki/ qui contient racine.cnf et inter.cnf (annexe B)
set -euo pipefail

[ -f racine.cnf ] && [ -f inter.cnf ] || { echo "Erreur : racine.cnf et inter.cnf introuvables ici" >&2; exit 1; }
[ ! -e racine ] && [ ! -e inter ] || { echo "Erreur : racine/ ou inter/ existe deja" >&2; exit 1; }
umask 077                      # cles privees lisibles par leur seul proprietaire

# Etape 1 : arborescence
for d in racine inter; do
  mkdir -p "$d/certs" "$d/crl" "$d/newcerts"
  : > "$d/index.txt"
done
echo 1000 > racine/serial; echo 1000 > racine/crlnumber
echo 2000 > inter/serial;  echo 2000 > inter/crlnumber

echo "== Etape 2 : AC racine =="
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
  -subj "/C=BF/O=Universite TP/CN=Racine TP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out racine/racine.crt

echo "== Etape 3 : AC intermediaire =="
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
openssl req -new -key inter/inter.key \
  -subj "/C=BF/O=Universite TP/CN=Intermediaire TP" -out inter/inter.csr
openssl ca -batch -notext -config racine.cnf -extensions ext_inter -days 1825 \
  -in inter/inter.csr -out inter/inter.crt

echo "== Etape 4 : serveur www.tp.local =="
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out serveur.key
openssl req -new -key serveur.key -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out serveur.csr
openssl ca -batch -notext -config inter.cnf -extensions ext_serveur -days 90 \
  -in serveur.csr -out serveur.crt

echo "== Etape 4 : client alice@tp.local =="
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out alice.key
openssl req -new -key alice.key -subj "/CN=alice@tp.local" \
  -addext "subjectAltName=email:alice@tp.local" -out alice.csr
openssl ca -batch -notext -config inter.cnf -extensions ext_client -days 90 \
  -in alice.csr -out alice.crt

echo "== Controle de la chaine =="
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local serveur.crt
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt -purpose sslclient alice.crt
