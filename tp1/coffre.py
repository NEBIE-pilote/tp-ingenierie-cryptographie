import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

T, M, P = 3, 128 * 1024, 4          # temps, memoire (Kio), parallelisme

def cle_maitresse(mot_de_passe: str, sel: bytes, t: int = T, m: int = M, p: int = P) -> bytes:
    """Argon2id -> 32 octets."""
    return hash_secret_raw(
        secret=mot_de_passe.encode("utf-8"),
        salt=sel,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=32,
        type=Type.ID,
    )

def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """HKDF-SHA256 avec info = b"coffre-v1|" + usage -> 32 octets."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"coffre-v1|" + usage,
    )
    return hkdf.derive(maitresse)
MAGIC = b"CFR1"

def chiffrer(mot_de_passe: str, nom: str, donnees: bytes) -> bytes:
    sel = os.urandom(16)
    nonce = os.urandom(12)
    entete = MAGIC + struct.pack(">III", T, M, P) + sel + nonce
    cle = sous_cle(cle_maitresse(mot_de_passe, sel), b"chiffrement-fichier")
    aad = entete + nom.encode("utf-8")
    chiffre = AESGCM(cle).encrypt(nonce, donnees, aad)
    return entete + chiffre

class FormatInconnu(ValueError):
    pass

def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    if blob[:4] != MAGIC:
        raise FormatInconnu("format inconnu")
    entete = blob[:44]
    t, m, p = struct.unpack(">III", blob[4:16])
    sel = blob[16:32]
    nonce = blob[32:44]
    cle = sous_cle(cle_maitresse(mot_de_passe, sel, t, m, p), b"chiffrement-fichier")
    aad = entete + nom.encode("utf-8")
    return AESGCM(cle).decrypt(nonce, blob[44:], aad)

def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes) -> bytes:
    donnees = dechiffrer(ancien_mdp, nom, blob)
    return chiffrer(nouveau_mdp, nom, donnees)

if __name__ == "__main__":
    sel = os.urandom(16)
    k = cle_maitresse("motdepasse", sel)
    print(len(k), k.hex())
    print(sous_cle(k, b"a") != sous_cle(k, b"b"))
    print(cle_maitresse("motdepasse", sel) == k)
    blob = chiffrer("motdepasse", "note.txt", b"bonjour")
    print(len(blob), blob[:4])
    print(dechiffrer("motdepasse", "note.txt", blob))

