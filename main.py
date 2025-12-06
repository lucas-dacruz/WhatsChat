import socket, ssl, threading, hmac, hashlib, secrets

# --- DIFFIE-HELLMAN SIMPLES ---
p = 23
g = 5
a = secrets.randbelow(p)
A = pow(g, a, p)

segredo = None
sock_tls = None

def receber():
    global segredo
    while True:
        data = sock_tls.recv(4096)
        if not data:
            break

        msg, mac = data.split(b'|||')
        local_mac = hmac.new(str(segredo).encode(), msg, hashlib.sha256).hexdigest().encode()

        if mac != local_mac:
            print("[ALERTA] Integridade violada!")
        else:
            print("Outro:", msg.decode())

def main():
    global sock_tls, segredo

    contexto = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    contexto.load_cert_chain(certfile="lucas.crt", keyfile="lucas.key")
    contexto.load_verify_locations("ca.crt")

    sock = socket.socket()
    sock_tls = contexto.wrap_socket(sock, server_hostname="ServidorChat")
    sock_tls.connect(("127.0.0.1", 4443))

    # Difusão do valor público A
    sock_tls.send(str(A).encode())

    # Receber B
    B = int(sock_tls.recv(4096).decode())
    segredo = pow(B, a, p)

    threading.Thread(target=receber).start()

    while True:
        msg = input()
        mac = hmac.new(str(segredo).encode(), msg.encode(), hashlib.sha256).hexdigest()
        final = msg.encode() + b"|||" + mac.encode()
        sock_tls.send(final)

main()
