import os
import sys
import socket
import ssl
import threading

# garantir que crypto seja importado mesmo em subprocesso
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from crypto.tls_context import create_client_context
from crypto.dh_key_exchange import generate_keys, generate_shared_key
from crypto.hmac_utils import generate_hmac


def main():
    username = input("Usuário: ")
    password = input("Senha: ")

    context = create_client_context()

    sock = socket.socket()
    conn = context.wrap_socket(sock, server_hostname="localhost")
    conn.connect(("localhost", 5000))

    # LOGIN
    conn.send(f"{username}:{password}".encode())
    if conn.recv(4096) != b"OK":
        print("❌ Login falhou!")
        return

    # DH
    priv, pub = generate_keys()
    server_pub = int(conn.recv(4096).decode())
    conn.send(str(pub).encode())
    shared_key = generate_shared_key(priv, server_pub)

    print(conn.recv(4096).decode())  # "Você está conectado com X"

    # THREAD PARA RECEBER MENSAGENS
    def listen():
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break

                if data == b"BAD":
                    print("⚠️ ALERTA: Integridade quebrada! Mensagem adulterada!")
                    continue

                print(data.decode())

            except:
                break

    threading.Thread(target=listen, daemon=True).start()

    # LOOP DE ENVIO
    while True:
        msg = input("> ").strip()

        # sair
        if msg == "/exit":
            conn.send(b"__EXIT__")
            print("👋 Você saiu do chat.")
            conn.close()
            break

        # comandos
        if msg == "/users":
            conn.send(b"__CMD__:USERS")
            continue

        if msg == "/online":
            conn.send(b"__CMD__:ONLINE")
            continue

        if msg == "/me":
            conn.send(b"__CMD__:PARTNER")
            continue

        # mensagem normal
        tag = generate_hmac(shared_key, msg)
        conn.send((msg + "||" + tag).encode())


main()
