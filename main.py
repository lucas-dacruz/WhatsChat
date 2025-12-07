import os
import subprocess
import json
import hashlib

DB_PATH = "user_db.json"


# ---------------------------
# UTILIDADES DO BANCO
# ---------------------------

def load_db():
    if not os.path.exists(DB_PATH):
        return {}
    with open(DB_PATH, "r") as f:
        return json.load(f)

def save_db(db):
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=4)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# ---------------------------
# FUNÇÃO DE REGISTRO
# ---------------------------

def register_user():
    db = load_db()

    username = input("Novo usuário: ").strip()
    if username in db:
        print("❌ Usuário já existe!")
        return

    password = input("Senha: ").strip()
    hashed = hash_password(password)

    db[username] = hashed
    save_db(db)

    print(f"✔ Usuário '{username}' registrado com sucesso!")


# ---------------------------
# LISTAR USUÁRIOS
# ---------------------------

def list_users():
    db = load_db()
    if not db:
        print("Nenhum usuário registrado.")
        return

    print("\nUsuários cadastrados:")
    for u in db.keys():
        print(f" - {u}")
    print()


# ---------------------------
# RODAR SERVIDOR
# ---------------------------

def run_server():
    print("Iniciando servidor...\n")
    subprocess.call(["python", "server/server.py"])


# ---------------------------
# RODAR CLIENTE
# ---------------------------

def run_client():
    print("Iniciando cliente...\n")
    subprocess.call(["python", "client/client.py"])


# ---------------------------
# MENU
# ---------------------------

def main_menu():
    while True:
        print("\n===== WHATSCHAT - MENU PRINCIPAL =====")
        print("1 - Registrar usuário")
        print("2 - Listar usuários cadastrados")
        print("3 - Iniciar servidor")
        print("4 - Iniciar cliente")
        print("5 - Sair")
        opc = input("Escolha: ").strip()

        if opc == "1":
            register_user()
        elif opc == "2":
            list_users()
        elif opc == "3":
            run_server()
        elif opc == "4":
            run_client()
        elif opc == "5":
            print("Saindo...")
            break
        else:
            print("Opção inválida!")


if __name__ == "__main__":
    main_menu()
