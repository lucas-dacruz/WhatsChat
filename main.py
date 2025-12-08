import os
import subprocess
import json
import hashlib

DB_PATH = "user_db.json"


# --- Database ---

def load_db() -> dict:
    """
    Carrega o banco de usuários a partir do arquivo JSON.
    Retorna um dicionário vazio caso o arquivo não exista
    ou não possa ser lido.
    """
    if not os.path.exists(DB_PATH):
        return {}

    try:
        with open(DB_PATH, "r") as f:
            return json.load(f)
    except Exception:
        # Em caso de erro no arquivo, não interrompe o fluxo do menu.
        return {}


def save_db(db: dict) -> None:
    """
    Salva o dicionário de usuários no arquivo JSON.
    """
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=4)


def hash_password(password: str) -> str:
    """
    Retorna um hash SHA-256 da senha informada.
    """
    return hashlib.sha256(password.encode()).hexdigest()


# --- User Management ---

def register_user() -> None:
    """
    Processa o fluxo de cadastro de um novo usuário.
    Valida entrada mínima e evita sobrescrita.
    """
    db = load_db()

    username = input("Novo usuário: ").strip()
    if not username:
        print("Nome inválido.")
        return

    if username in db:
        print("Usuário já existe.")
        return

    pwd = input("Senha: ").strip()
    if not pwd:
        print("Senha inválida.")
        return

    db[username] = hash_password(pwd)
    save_db(db)

    print(f"Usuário '{username}' registrado.")


def list_users() -> None:
    """
    Exibe os usuários cadastrados no banco local.
    """
    db = load_db()

    if not db:
        print("Nenhum usuário cadastrado.")
        return

    print("\n--- Usuários registrados ---")
    for user in db:
        print(f" • {user}")
    print()


# --- Client Runner ---

def run_client() -> None:
    """
    Executa o cliente em um subprocesso.
    """
    try:
        subprocess.call(["python", "-m", "client.client"])
    except FileNotFoundError:
        print("client.py não encontrado.")
    except Exception as exc:
        print("Erro ao iniciar cliente:", exc)


# --- Menu Principal ---

def main_menu() -> None:
    """
    Exibe o menu principal e controla as ações do usuário.
    """
    while True:
        print("\n===== WHATSCHAT - MENU PRINCIPAL =====")
        print("1 - Registrar usuário")
        print("2 - Listar usuários")
        print("3 - Iniciar chat")
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
            print("Opção inválida.")


if __name__ == "__main__":
    main_menu()
