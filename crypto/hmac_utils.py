import hmac
import hashlib
from typing import Union


def generate_hmac(key: Union[int, bytes, str], message: str) -> str:
    """
    Gera HMAC-SHA256 e devolve em hexdigest.
    Chave aceita int/bytes/str (conversão interna).
    """
    if isinstance(key, int):
        k = str(key).encode()
    elif isinstance(key, str):
        k = key.encode()
    else:
        k = key
    tag = hmac.new(k, message.encode(), hashlib.sha256)
    return tag.hexdigest()


def verify_hmac(key: Union[int, bytes, str], message: str, tag: str) -> bool:
    """
    Compara de forma segura o HMAC esperado com o recebido.
    """
    expected = generate_hmac(key, message)
    return hmac.compare_digest(expected, tag)
