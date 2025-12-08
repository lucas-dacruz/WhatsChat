import os
import sys
import json
import socket
import ssl
import threading
import hashlib
import time
from typing import Optional, Tuple, Dict

from crypto.tls_context import create_server_context
from crypto.dh_key_exchange import generate_keys, generate_shared_key
from crypto.hmac_utils import generate_hmac, verify_hmac

waiting_list = []
active_pairs: Dict[str, str] = {}
connections: Dict[str, Tuple[ssl.SSLSocket, int]] = {}
online_users = set()


def hash_password(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()


def match_user(username: str) -> Optional[str]:
    # se tiver alguém esperando, pareia; senão, entra na fila
    if waiting_list and waiting_list[0] != username:
        other = waiting_list.pop(0)
        active_pairs[username] = other
        active_pairs[other] = username
        return other
    waiting_list.append(username)
    return None


def handle_command(packet: str, conn: ssl.SSLSocket, username: str) -> None:
    cmd = packet.replace("__CMD__:", "")
    if cmd == "USERS":
        with open("user_db.json") as f:
            db = json.load(f)
        conn.send(", ".join(db.keys()).encode())
        return

    if cmd == "ONLINE":
        conn.send(", ".join(sorted(online_users)).encode())
        return

    if cmd == "PARTNER":
        partner = active_pairs.get(username)
        msg = partner if partner else "Nenhum pareamento ativo."
        conn.send(msg.encode())
        return


def authenticate(conn: ssl.SSLSocket) -> Optional[str]:
    """
    Lê credenciais (formato user:pass) e verifica no user_db.json.
    """
    raw = conn.recv(4096).decode()
    try:
        user, password = raw.split(":", 1)
    except ValueError:
        conn.send(b"FAIL")
        return None

    db_path = os.path.join("user_db.json")
    if not os.path.exists(db_path):
        conn.send(b"FAIL")
        return None

    with open(db_path) as f:
        db = json.load(f)

    if db.get(user) == hash_password(password):
        conn.send(b"OK")
        return user

    conn.send(b"FAIL")
    return None


def handle_client(conn: ssl.SSLSocket) -> None:
    """
    Fluxo por cliente: autenticação, DH, pareamento, loop de chat.
    Ordem das pequenas operações é propositalmente um pouco solta
    (como num cenário de trabalho rápido), sem perder coerência.
    """
    username = authenticate(conn)
    if not username:
        conn.close()
        return

    online_users.add(username)
    # handshake DH (envia pub, recebe pub)
    priv, pub = generate_keys()
    conn.send(str(pub).encode())

    try:
        peer_raw = conn.recv(4096).decode()
        peer_pub = int(peer_raw)
    except Exception:
        conn.close()
        online_users.discard(username)
        return

    shared = generate_shared_key(priv, peer_pub)
    connections[username] = (conn, shared)

    print(f"[INFO] {username} autenticado, aguardando pareamento.")

    # pareamento (espera ativo)
    partner = match_user(username)
    while partner is None:
        time.sleep(0.1)
        partner = active_pairs.get(username)

    p_conn, _ = connections.get(partner, (None, None))
    if p_conn:
        try:
            p_conn.send(f"Conectado com {username}".encode())
        except Exception:
            pass

    print(f"[INFO] Par formado: {username} <-> {partner}")

    # loop de mensagens
    while True:
        try:
            raw = conn.recv(4096)
            if not raw:
                break
            packet = raw.decode()

            if packet == "__EXIT__":
                break

            if packet.startswith("__CMD__"):
                handle_command(packet, conn, username)
                continue

            # conteúdo normal: "mensagem||tag"
            try:
                msg, tag = packet.split("||", 1)
            except ValueError:
                # formato inválido, simplesmente ignorar
                continue

            # verificar integridade com a chave do usuário local
            _, user_key = connections[username]
            if not verify_hmac(user_key, msg, tag):
                conn.send(b"BAD")
                continue

            # re-empacotar para o parceiro usando chave dele
            partner_conn, partner_key = connections.get(partner, (None, None))
            if not partner_conn:
                # parceiro não mais disponível
                conn.send(b"NOPART")
                continue

            new_tag = generate_hmac(partner_key, msg)
            try:
                partner_conn.send(f"{username}: {msg}||{new_tag}".encode())
            except Exception:
                # se falhar ao enviar, só ignorar e continuar
                pass

        except Exception:
            # erro genérico no loop — encerra
            break

    # desconectar e limpar estado
    print(f"[INFO] {username} desconectando.")
    online_users.discard(username)
    # remover da fila, se estiver
    if username in waiting_list:
        try:
            waiting_list.remove(username)
        except ValueError:
            pass

    # avisar parceiro (se houver)
    if username in active_pairs:
        p = active_pairs.pop(username)
        # garantir remoção do par também
        active_pairs.pop(p, None)
        partner_conn, _ = connections.get(p, (None, None))
        if partner_conn:
            try:
                partner_conn.send(f"{username} saiu do chat.".encode())
            except Exception:
                pass

    # remover conexão local
    connections.pop(username, None)

    try:
        conn.close()
    except Exception:
        pass


def main() -> None:
    ctx = create_server_context()
    sock = socket.socket()
    sock.bind(("0.0.0.0", 5000))
    sock.listen(10)

    print("Servidor iniciado. Aguardando conexões...")

    while True:
        client, _ = sock.accept()
        try:
            secure = ctx.wrap_socket(client, server_side=True)
        except Exception:
            client.close()
            continue

        t = threading.Thread(target=handle_client, args=(secure,), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
