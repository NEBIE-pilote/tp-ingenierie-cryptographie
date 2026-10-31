import pytest
from cryptography.exceptions import InvalidTag

import coffre

MDP = "motdepasse"
NOM = "rapport.txt"
DONNEES = b"contenu secret du fichier"


def test_aller_retour():
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    assert coffre.dechiffrer(MDP, NOM, blob) == DONNEES


def test_chiffrer_deux_fois_donne_deux_resultats():
    a = coffre.chiffrer(MDP, NOM, DONNEES)
    b = coffre.chiffrer(MDP, NOM, DONNEES)
    assert a != b

def test_mauvais_mot_de_passe():
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        coffre.dechiffrer("mauvais", NOM, blob)


def test_octet_du_chiffre_modifie():
    blob = bytearray(coffre.chiffrer(MDP, NOM, DONNEES))
    blob[50] ^= 1                      # octet 50 : dans la zone chiffrée (après les 44 octets d'en-tête)
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, NOM, bytes(blob))


def test_fichier_renomme():
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, "autre.txt", blob)
def test_rechiffrer():
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    nouveau = coffre.rechiffrer(MDP, "nouveau", NOM, blob)
    assert coffre.dechiffrer("nouveau", NOM, nouveau) == DONNEES
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, NOM, nouveau)

