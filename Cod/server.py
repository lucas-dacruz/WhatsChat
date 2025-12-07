import socket
import ssl
import threading
import secrets
import hmac
import hashlib
import json  
# Útil para encaminhar mensagens formatadas

# --- CONSTANTES ---
HOST = '127.0.0.1'
PORT = 4443

# --- VARIAVEIS GLOBAIS ---
CLIENTS = {}  # {username: (sock_tls, segredo_dh)}
DH_PARAMS = {
    'p': 23,
    'g': 5
}

# --- FUNÇÃO DE PROCESSAMENTO DE CLIENTE ---
def handle_client(conn_tls):
    """Lida com a comunicação e DH para um único cliente."""
    
    # 1. Obter Nome de Usuário (Da Autenticação mTLS)
    # A identidade do cliente está no seu certificado!
    cert = conn_tls.getpeercert()
    if not cert:
        print("[ERRO] Cliente sem certificado. Fechando conexão.")
        return

    # Extrai o nome comum (CN) do certificado, usado como username
    try:
        subject = dict(x[0] for x in cert['subject'])
        username = subject['commonName']
    except Exception as e:
        print(f"[ERRO] Falha ao obter username do certificado: {e}")
        return

    print(f"\n[INFO] Cliente autenticado com sucesso: {username}")
    
    # 2. Executar Diffie-Hellman (DH)
    try:
        # 2a. Receber o valor público A do cliente
        A = int(conn_tls.recv(4096).decode())
        
        # 2b. Gerar chave privada (b) e pública (B) do servidor para ESTE cliente
        b = secrets.randbelow(DH_PARAMS['p'])
        B = pow(DH_PARAMS['g'], b, DH_PARAMS['p'])
        
        # 2c. Enviar B de volta para o cliente
        conn_tls.send(str(B).encode())
        
        # 2d. Calcular o segredo compartilhado (K)
        segredo_dh = pow(A, b, DH_PARAMS['p'])
        
        # 3. Armazenar o cliente
        # Neste ponto, o segredo DH é único para este canal.
        CLIENTS[username] = (conn_tls, segredo_dh)
        print(f"[INFO] Segredo DH estabelecido com {username}: {segredo_dh}")

    except Exception as e:
        print(f"[ERRO] Falha na troca DH com {username}: {e}")
        conn_tls.close()
        return

    # 4. Loop de Recebimento e Encaminhamento de Mensagens
    while True:
        try:
            data = conn_tls.recv(4096)
            if not data:
                break

            # A mensagem já está descriptografada pelo TLS, mas precisamos verificar o HMAC
            msg_bytes, mac_bytes = data.split(b'|||')
            
            # Recálculo do MAC (usando o segredo DH específico deste cliente)
            local_mac = hmac.new(str(segredo_dh).encode(), msg_bytes, hashlib.sha256).hexdigest().encode()

            if mac_bytes != local_mac:
                print(f"[ALERTA] Integridade violada na mensagem de {username}!")
                # Você deve decidir se fecha a conexão ou apenas ignora a mensagem.
            else:
                # Se o HMAC for válido, encaminhe para os outros clientes
                mensagem_formatada = f"[{username}]: {msg_bytes.decode()}"
                print(f"[RECEBIDO] {mensagem_formatada}")
                broadcast(mensagem_formatada, username) # Encaminha para todos, exceto o remetente

        except ssl.SSLError as e:
            print(f"[ERRO TLS] Conexão com {username} falhou: {e}")
            break
        except Exception as e:
            print(f"[ERRO GERAL] Conexão com {username} falhou: {e}")
            break
            
    # Limpeza
    print(f"[INFO] Cliente {username} desconectado.")
    del CLIENTS[username]
    conn_tls.close()


# --- FUNÇÃO DE BROADCAST ---
def broadcast(message, sender_username):
    """Encaminha uma mensagem para todos os clientes ativos, exceto o remetente."""
    for user, (sock, segredo) in CLIENTS.items():
        if user != sender_username:
            try:
                # A mensagem encaminhada PRECISA ser assinada com o HMAC 
                # do canal do REMETENTE para o DESTINATÁRIO.
                # Como é um chat *centralizado*, o servidor PRECISA saber 
                # o segredo DH de *ambos* os lados (remetente e destinatário).
                
                # Simplificação: Como o segredo DH é ÚNICO entre (Cliente X <-> Servidor),
                # o servidor tem que reembalar a mensagem para CADA cliente,
                # usando o segredo DH ESPECÍFICO desse cliente.

                # NO SEU PROJETO: Recomenda-se que o Servidor APENAS repasse a mensagem criptografada
                # (já que a confidencialidade é garantida pelo TLS) E o HMAC, 
                # mas o HMAC faz sentido apenas entre o Servidor e o Cliente.
                
                # Para fins de demonstração (e devido ao segredo DH ser único), o Servidor não pode
                # reencaminhar a mensagem original com o HMAC do remetente.

                # Melhor abordagem para o Chat Centralizado:
                # O servidor só reenvia a mensagem (msg_bytes.decode()) sem HMAC.
                # O HMAC neste caso é apenas um cheque de integridade entre Cliente<->Servidor.
                
                # Se a mensagem for reencaminhada:
                # sock.send(message.encode()) # Se for reencaminhar texto claro dentro do TLS

                # Para simplificar e cumprir a autenticidade/integridade Cliente<->Servidor:
                # Se você realmente quer integridade PONTO-A-PONTO (o ideal), 
                # você precisaria de uma troca de chaves DH entre cada par de usuários.
                
                # MANTENDO A SIMPLICIDADE (Servidor <-> Cliente):
                # Apenas avisa o cliente sobre a nova mensagem.
                sock.send(f"[CHAT] {message}".encode()) 
            
            except Exception as e:
                print(f"[ERRO BROADCAST] Falha ao enviar para {user}: {e}")
                # Aqui você removeria o cliente da lista e fecharia a conexão, mas vamos simplificar.


# --- FUNÇÃO PRINCIPAL DO SERVIDOR ---
def run_server():
    """Configura o contexto TLS, sockets e aceita conexões."""

    # 1. Configurar o Contexto mTLS
    contexto = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # Carrega a identidade do servidor (chave privada e certificado)
    contexto.load_cert_chain(certfile="server.crt", keyfile="server.key")
    
    # Exige que os clientes apresentem um certificado assinado pela nossa CA
    contexto.load_verify_locations("ca.crt")
    contexto.verify_mode = ssl.CERT_REQUIRED
    
    # 2. Configurar o Socket de Escuta
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"[INFO] Servidor escutando em {HOST}:{PORT}")

    # 3. Loop de Aceitação de Conexões
    while True:
        try:
            conn, addr = sock.accept()
            print(f"[CONEXÃO] Conexão recebida de {addr}")
            
            # 4. Encapsular em TLS (Handshake e Autenticação mútua)
            # O Servidor faz o wrap_socket na conexão aceita
            conn_tls = contexto.wrap_socket(conn, server_side=True)
            
            # 5. Iniciar Thread para Cliente
            client_thread = threading.Thread(target=handle_client, args=(conn_tls,))
            client_thread.daemon = True # Permite que o programa principal saia mesmo com threads ativas
            client_thread.start()

        except ssl.SSLError as e:
            # Captura erros de handshake (ex: Cliente não apresentou certificado válido)
            print(f"[ERRO HANDSHAKE] Conexão rejeitada (mTLS falhou): {e}")
            conn.close() # Garante que o socket subjacente seja fechado
        except KeyboardInterrupt:
            print("[INFO] Servidor encerrado.")
            break
        except Exception as e:
            print(f"[ERRO CRÍTICO] Falha ao aceitar conexão: {e}")
            
# --- Ponto de Entrada ---
if __name__ == "__main__":
    run_server()