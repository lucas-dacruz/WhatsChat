import secrets
from typing import Tuple

P = 0xFFFFFFFEFFFFEE37
G = 2


def generate_keys() -> Tuple[int, int]:
    """
    Gera (privado, publico) para Diffie-Hellman.
    """
    private = secrets.randbelow(P - 2) + 2
    public = pow(G, private, P)
    return private, public


def generate_shared_key(private: int, peer_public: int) -> int:
    """
    Deriva o segredo compartilhado (retorna inteiro).
    Nota: retorna int para ser compatível com transformações
    que o projeto usa ao codificar a chave.
    """
    return pow(peer_public, private, P)
