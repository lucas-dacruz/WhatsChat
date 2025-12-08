import os
import sys
import socket
import ssl
import threading
from typing import Optional

from crypto.tls_context import create_client_context
from crypto.dh_key_exchange import generate_keys, generate_shared_key
from crypto.hmac_utils import generate_hmac, verify_hmac


def listen_messages(conn: ssl.SSLSocket) -> None:
    """Thread que imprime mensagens recebidas do servidor/par."""
    while True:
        try:
            raw = conn.recv(4096)
            if not raw:
                break

            if raw == b"BAD":
                print("Aviso: integridade da mensagem inválida.")
                continue

            decoded = raw.decode()
            
            if "||" in decoded:
                # pode vir no formato "user: msg||tag" ou "msg||tag"
                left, _ = decoded.split("||", 1)
                print(left)
            else:
                print(decoded)
        except Exception:
            break


def connect_and_wrap() -> Optional[ssl.SSLSocket]:
    try:
        ctx = create_client_context()
        s = socket.socket()
        return ctx.wrap_socket(s, server_hostname="localhost")
    except Exception:
        return None


def do_key_exchange(conn: ssl.SSLSocket) -> Optional[int]:
    """
    Troca de chaves DH: recebe pub do servidor, envia o nosso e retorna segredo.
    """
    priv, pub = generate_keys()
    try:
        server_pub_raw = conn.recv(4096).decode()
        server_pub = int(server_pub_raw)
    except Exception:
        return None

    conn.send(str(pub).encode())
    shared = generate_shared_key(priv, server_pub)
    return shared


def main() -> None:
    username = input("Usuário: ")
    password = input("Senha: ")

    conn = connect_and_wrap()
    if conn is None:
        print("Não foi possível criar conexão TLS.")
        return

    try:
        conn.connect(("localhost", 5000))
    except Exception:
        print("Falha ao conectar ao servidor.")
        return

    # login simples
    conn.send(f"{username}:{password}".encode())
    resp = conn.recv(4096)
    if resp != b"OK":
        print("Login falhou.")
        return

    # handshake DH (recebe pub do servidor, envia o nosso)
    shared_key = do_key_exchange(conn)
    if shared_key is None:
        print("Erro no handshake.")
        return

    # receber mensagem de boas-vindas (geralmente info de pareamento)
    try:
        welcome = conn.recv(4096).decode()
        print(welcome)
    except Exception:
        pass

    # start listener
    t = threading.Thread(target=listen_messages, args=(conn,), daemon=True)
    t.start()

    while True:
        try:
            msg = input().strip()
        except EOFError:
            msg = "/exit"

        if msg == "/exit":
            try:
                conn.send(b"__EXIT__")
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
            print("Encerrando cliente.")
            break

        if msg == "/users":
            conn.send(b"__CMD__:USERS")
            continue

        if msg == "/online":
            conn.send(b"__CMD__:ONLINE")
            continue

        if msg == "/me":
            conn.send(b"__CMD__:PARTNER")
            continue

        # Gera tag HMAC com a chave compartilhada (int -> str encode)
        tag = generate_hmac(shared_key, msg)
        try:
            conn.send(f"{msg}||{tag}".encode())
        except Exception:
            # se falhar no envio, tenta seguir (comportamento simples)
            pass


if __name__ == "__main__":
    main()
