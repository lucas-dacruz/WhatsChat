import json
import socket
import ssl
import threading
import hashlib

from crypto.tls_context import create_server_context
from crypto.dh_key_exchange import generate_keys, generate_shared_key
from crypto.hmac_utils import generate_hmac, verify_hmac

waiting_list = []
active_pairs = {}
connections = {}


def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()


def authenticate(conn):
    data = conn.recv(4096).decode()
    user, password = data.split(":")

    with open("user_db.json") as f:
        db = json.load(f)

    hashed = hash_password(password)

    if user in db and db[user] == hashed:
        conn.send(b"OK")
        return user
    else:
        conn.send(b"FAIL")
        return None


def match_user(username):
    if waiting_list and waiting_list[0] != username:
        other = waiting_list.pop(0)
        active_pairs[username] = other
        active_pairs[other] = username
        return other

    waiting_list.append(username)
    return None


def handle_client(conn):

    username = authenticate(conn)
    if not username:
        conn.close()
        return

    # DH
    priv, pub = generate_keys()
    conn.send(str(pub).encode())
    peer_pub = int(conn.recv(4096).decode())
    shared_key = generate_shared_key(priv, peer_pub)

    connections[username] = (conn, shared_key)

    print(f"✔ {username} conectado e aguardando um par...")

    partner = match_user(username)
    while partner is None:
        partner = match_user(username)

    conn.send(f"Você está conectado com {partner}".encode())
    p_conn, _ = connections[partner]
    p_conn.send(f"Você está conectado com {username}".encode())

    print(f"🔗 PAR FORMADO: {username} ↔ {partner}")

    # loop de chat
    while True:
        try:
            packet = conn.recv(4096).decode()
            if not packet:
                break

            msg, tag = packet.split("||")

            if not verify_hmac(shared_key, msg, tag):
                conn.send(b"BAD")
                continue

            p_conn, p_key = connections[partner]
            new_tag = generate_hmac(p_key, msg)

            p_conn.send(f"{username}: {msg}||{new_tag}".encode())

        except:
            break

    print(f"❌ {username} desconectou")

    if username in active_pairs:
        p = active_pairs[username]
        del active_pairs[p]
        del active_pairs[username]

    conn.close()


def main():
    context = create_server_context()

    s = socket.socket()
    s.bind(("0.0.0.0", 5000))
    s.listen(10)

    print("Servidor rodando e aguardando usuários...")

    while True:
        client, _ = s.accept()
        conn = context.wrap_socket(client, server_side=True)
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


main()
