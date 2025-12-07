import os
import sys
import json
import socket
import ssl
import threading
import hashlib
import time

# Garantir import do módulo crypto mesmo quando executado via subprocess
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from crypto.tls_context import create_server_context
from crypto.dh_key_exchange import generate_keys, generate_shared_key
from crypto.hmac_utils import generate_hmac, verify_hmac

# listas globais
waiting_list = []
active_pairs = {}
connections = {}
online_users = set()


# ========================
#   AUTENTICAÇÃO
# ========================
def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

def authenticate(conn):
    data = conn.recv(4096).decode()
    user, password = data.split(":")

    with open(os.path.join(ROOT, "user_db.json")) as f:
        db = json.load(f)

    hashed = hash_password(password)

    if user in db and db[user] == hashed:
        conn.send(b"OK")
        return user
    else:
        conn.send(b"FAIL")
        return None


# =======================================
#   PAREAMENTO AUTOMÁTICO ENTRE CLIENTES
# =======================================
def match_user(username):
    if waiting_list and waiting_list[0] != username:
        other = waiting_list.pop(0)
        active_pairs[username] = other
        active_pairs[other] = username
        return other

    waiting_list.append(username)
    return None


# =======================================
#   COMANDOS DO CLIENTE
# =======================================
def handle_command(packet, conn, username):
    cmd = packet.replace("__CMD__:", "")

    if cmd == "USERS":
        with open(os.path.join(ROOT, "user_db.json")) as f:
            db = json.load(f)
        conn.send(("Usuários registrados: " + ", ".join(db.keys())).encode())

    elif cmd == "ONLINE":
        conn.send(("Usuários online: " + ", ".join(online_users)).encode())

    elif cmd == "PARTNER":
        p = active_pairs.get(username, None)
        if p:
            conn.send(f"Você está conectado com: {p}".encode())
        else:
            conn.send("Você ainda não foi pareado.".encode())


# =======================================
#  TRATAR CADA CLIENTE
# =======================================
def handle_client(conn):

    # LOGIN
    username = authenticate(conn)
    if not username:
        conn.close()
        return

    online_users.add(username)

    # DH
    priv, pub = generate_keys()
    conn.send(str(pub).encode())

    peer_pub = int(conn.recv(4096).decode())
    shared_key = generate_shared_key(priv, peer_pub)

    connections[username] = (conn, shared_key)
    print(f"✔ {username} conectado. Aguardando par...")

    # PAREAMENTO
    partner = match_user(username)
    while partner is None:
        time.sleep(0.1)
        partner = active_pairs.get(username)

    # Notificar ambos
    conn.send(f"Você está conectado com {partner}".encode())

    p_conn, _ = connections[partner]
    p_conn.send(f"Você está conectado com {username}".encode())

    print(f"🔗 PAR FORMADO: {username} ↔ {partner}")

    # LOOP DE CHAT
    while True:
        try:
            packet = conn.recv(4096).decode()
            if not packet:
                break

            # cliente pediu para sair
            if packet == "__EXIT__":
                break

            # comandos do chat
            if packet.startswith("__CMD__"):
                handle_command(packet, conn, username)
                continue

            # mensagem normal com HMAC
            msg, tag = packet.split("||")

            if not verify_hmac(shared_key, msg, tag):
                conn.send(b"BAD")
                continue

            p_conn, p_key = connections[partner]
            new_tag = generate_hmac(p_key, msg)

            p_conn.send(f"{username}: {msg}||{new_tag}".encode())

        except:
            break

    # DESCONECTAR
    print(f"❌ {username} desconectou")

    # avisar o parceiro
    if username in active_pairs:
        p = active_pairs[username]
        p_conn, _ = connections.get(p, (None, None))
        if p_conn:
            try:
                p_conn.send(f"⚠️ {username} saiu do chat.".encode())
            except:
                pass
        del active_pairs[p]
        del active_pairs[username]

    online_users.discard(username)
    if username in waiting_list:
        waiting_list.remove(username)

    conn.close()


# =======================================
#     MAIN
# =======================================
def main():
    context = create_server_context()

    s = socket.socket()
    s.bind(("0.0.0.0", 5000))
    s.listen(10)

    print("🚀 Servidor iniciado! Aguardando clientes...")

    while True:
        client, _ = s.accept()
        conn = context.wrap_socket(client, server_side=True)
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


main()
