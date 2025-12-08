import ssl


def create_server_context() -> ssl.SSLContext:
    """
    Retorna um contexto TLS configurado para o servidor.
    Usa certificados em certs/.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("certs/server.crt", "certs/server.key")
    ctx.load_verify_locations("certs/client.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def create_client_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain("certs/client.crt", "certs/client.key")
    ctx.load_verify_locations("certs/server.crt")
    return ctx
