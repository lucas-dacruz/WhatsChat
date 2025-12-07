import socket
import ssl
import threading
import hmac
import hashlib
import secrets
import sys
import json

# --- CONFIGURAÇÕES DE CONEXÃO ---
HOST = '127.0.0.1'
PORT = 4443

# --- PARÂMETROS DIFFIE-HELLMAN SIMPLES (CLIENTE) ---
# Os parâmetros p e g devem ser os mesmos do Servidor
p = 23 
g = 5
a = secrets.randbelow(p)  # Chave privada 'a' do cliente
A = pow(g, a, p)          # Valor público 'A' do cliente

# --- VARIÁVEIS GLOBAIS DE SEGURANÇA ---
segredo_dh = None       # O segredo compartilhado (K) para o HMAC
sock_tls = None         # O socket seguro

# --- NOME DE USUÁRIO (AJUSTE CONFORME SEU CERTIFICADO) ---
# Você deve mudar 'user1' para o nome comum (CN) exato do seu certificado de cliente (ex: 'lucas.crt')
# O servidor usará este nome para identificá-lo!
CERT_FILENAME = "user1.crt"
KEY_FILENAME = "user1.key"
CA_FILENAME = "ca.crt"
CLIENT_ID = "user1" # O CN no seu certificado, para o servidor identificá-lo

# ----------------------------------------------------------------------
# FUNÇÕES DE LÓGICA DO CHAT
# ----------------------------------------------------------------------

def receive_messages():
    """Thread dedicada a receber mensagens do servidor."""
    global segredo_dh
    
    # Espera até que o segredo DH seja estabelecido
    while segredo_dh is None:
        pass # Loop vazio

    print("\n[INFO] HMAC ativo. Você pode começar a digitar:")

    while True:
        try:
            # 1. Receber dados
            data = sock_tls.recv(4096)
            if not data:
                break
            
            # 2. Processamento da Mensagem (HMAC)
            # O Servidor pode enviar mensagens de controle que não têm HMAC, como a lista de usuários.
            if b'|||' in data:
                msg_bytes, mac_bytes = data.split(b'|||')
                
                # Recálculo do MAC
                local_mac = hmac.new(str(segredo_dh).encode(), msg_bytes, hashlib.sha256).hexdigest().encode()

                if mac_bytes != local_mac:
                    # ALERTA DE INTEGRIDADE VIOLADA
                    print("\n[ALERTA DE SEGURANÇA] Integridade da mensagem violada! (HMAC Inválido)")
                    print(">> Mensagem original interceptada e alterada ou chave DH incorreta.")
                else:
                    # HMAC Válido
                    print("\r" + " " * 80, end='\r') # Limpa a linha de input
                    print(msg_bytes.decode())
                    sys.stdout.flush() # Força a impressão imediata
                    print(f"[{CLIENT_ID}]: ", end='', flush=True) # Volta a mostrar o prompt de input
            
            else:
                # Mensagens de controle ou broadcast do servidor (sem HMAC)
                print("\r" + " " * 80, end='\r') 
                print(data.decode())
                print(f"[{CLIENT_ID}]: ", end='', flush=True)

        except Exception as e:
            print(f"[ERRO RECEBIMENTO] Falha na conexão: {e}")
            break
            
    print("[INFO] Conexão com o servidor encerrada.")
    sock_tls.close()
    sys.exit(0)


def send_messages():
    """Thread dedicada à leitura de input do usuário e envio."""
    global segredo_dh
    
    # Espera até que o segredo DH seja estabelecido
    while segredo_dh is None:
        pass
        
    while True:
        try:
            # Pega o input do usuário e adiciona o prompt
            msg = input(f"[{CLIENT_ID}]: ")
            if not msg:
                continue

            # 1. Geração do MAC para a Integridade
            mac = hmac.new(str(segredo_dh).encode(), msg.encode(), hashlib.sha256).hexdigest()
            
            # 2. Formato de Transmissão (Mensagem + Separador + MAC)
            final_message = msg.encode() + b"|||" + mac.encode()
            
            # 3. Envio (Pelo canal TLS SEGURO)
            sock_tls.send(final_message)
            
        except Exception as e:
            print(f"[ERRO ENVIO] Falha ao enviar mensagem: {e}")
            break


# ----------------------------------------------------------------------
# FUNÇÃO PRINCIPAL
# ----------------------------------------------------------------------

def main():
    global sock_tls, segredo_dh

    print("[INFO] Iniciando cliente seguro...")

    try:
        # 1. Configurar o Contexto TLS (PARA AUTENTICAÇÃO MÚTUA)
        contexto = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        # Carrega a identidade do cliente (chave privada e certificado)
        contexto.load_cert_chain(certfile=CERT_FILENAME, keyfile=KEY_FILENAME)
        
        # Diz ao cliente para confiar nos certificados assinados pela nossa CA (para verificar o servidor)
        contexto.load_verify_locations(CA_FILENAME)
        contexto.check_hostname = False # Para testes locais com CN simples

        # 2. Conectar e Executar Handshake TLS (mTLS)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_tls = contexto.wrap_socket(sock, server_side=False, server_hostname=HOST)
        sock_tls.connect((HOST, PORT))

        # A conexão foi estabelecida: Autenticidade do canal garantida pelo mTLS.
        print(f"[INFO] Conexão mTLS estabelecida com sucesso com {HOST}:{PORT}")
        
        # 3. Executar o Diffie-Hellman Simples para o Segredo HMAC
        
        # 3a. Difusão do valor público A
        sock_tls.send(str(A).encode())
        print(f"[DH] Enviado valor público A: {A}")

        # 3b. Receber B do Servidor
        B = int(sock_tls.recv(4096).decode())
        
        # 3c. Calcular o segredo
        segredo_dh = pow(B, a, p)
        print(f"[DH] Segredo compartilhado (K) estabelecido: {segredo_dh}")

        # 4. Iniciar Threads
        threading.Thread(target=receive_messages, daemon=True).start()
        threading.Thread(target=send_messages, daemon=True).start()
        
        # Mantém a thread principal viva
        while threading.active_count() > 0:
            threading.current_thread().join(0.1)

    except FileNotFoundError:
        print("[ERRO] Arquivos de certificado não encontrados. Execute 'generate_certs.sh'!")
    except ConnectionRefusedError:
        print("[ERRO] Conexão recusada. O servidor está rodando?")
    except ssl.SSLError as e:
        print(f"[ERRO TLS] Falha no Handshake (Autenticação): {e}")
        print(">> Verifique se os certificados (user1.crt, user1.key, ca.crt) estão corretos.")
    except Exception as e:
        print(f"[ERRO GERAL] Um erro ocorreu: {e}")
        
    finally:
        if sock_tls:
            sock_tls.close()

if __name__ == "__main__":
    main()