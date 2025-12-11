# README -- WHATSCHAT (Chat Seguro)

Este projeto implementa um sistema de chat simples com **servidor seguro
(TLS)**, **Diffie--Hellman**, **HMAC** e autenticação de usuários.

------------------------------------------------------------------------

# 1. Pré-requisitos

## 1.1 Instalar Python

### Windows

1.  Baixe o instalador: https://www.python.org/downloads/
2.  Marque: **Add Python to PATH**
3.  Instale.

### Linux

``` bash
sudo apt update
sudo apt install python3 python3-pip -y
```

### macOS

``` bash
brew install python
```

------------------------------------------------------------------------

# 1.2 Instalar dependências

``` bash
pip install cryptography
```

------------------------------------------------------------------------

# 2. Estrutura do projeto

    /projeto/
    │
    ├── main.py
    ├── client.py
    ├── server.py
    └── crypto/
         ├── tls_context.py
         ├── dh_key_exchange.py
         └── hmac_utils.py
    └── certs/

------------------------------------------------------------------------

# 3. Executando o projeto

## 3.1 Rodar o servidor

``` bash
python -m server.server
```

## 3.2 Rodar os clientes (2 terminais separados)

``` bash
python main.py
```

------------------------------------------------------------------------

# 4. Fluxo de uso

1.  Cadastre usuários
2.  Entre no chat
3.  Aguarde o pareamento automático
4.  Envie mensagens

------------------------------------------------------------------------

# 5. Comandos no chat

  Comando   Ação
  --------- ------------------------------
  /users    Lista usuários cadastrados
  /online   Lista usuários online
  /me       Mostra com quem está pareado
  /exit     Sai do chat

------------------------------------------------------------------------

# 6. Segurança Aplicada

-   TLS 1.3
-   Diffie--Hellman para chave compartilhada
-   HMAC-SHA256
-   Hash de senha com SHA-256
-   Pareamento 1x1 automático

------------------------------------------------------------------------

# 7. Erros Comuns

**Falha ao conectar:** servidor não iniciado\
**Login falhou:** usuário não cadastrado\
**crypto não encontrado:** verifique a pasta na raiz