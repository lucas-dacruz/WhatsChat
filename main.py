import os
import subprocess
import json
import hashlib

DB_PATH = "user_db.json"


# ==============================
# Funções do banco de usuários
# ==============================
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


# ==============================
# Registrar usuários
# ==============================
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


# ==============================
# Listar usuários
# ==============================
def list_users():
    db = load_db()
    if not db:
        print("Nenhum usuário registrado.")
        return

    print("\nUsuários cadastrados:")
    for u in db:
        print(" -", u)
    print()


# ==============================
# Iniciar cliente
# ==============================
def run_client():
    ROOT = os.path.dirname(os.path.abspath(__file__))
    subprocess.call(["python", os.path.join(ROOT, "client", "client.py")])


# ==============================
# Menu principal
# ==============================
def main_menu():
    while True:
        print("\n===== WHATSCHAT - MENU PRINCIPAL =====")
        print("1 - Registrar usuário")
        print("2 - Listar usuários cadastrados")
        print("3 - Iniciar cliente")
        print("4 - Sair")
        
        opc = input("Escolha: ").strip()

        if opc == "1":
            register_user()
        elif opc == "2":
            list_users()
        elif opc == "3":
            run_client()
        elif opc == "4":
            print("Saindo...")
            break
        else:
            print("Opção inválida!")


if __name__ == "__main__":
    main_menu()
