import ssl

def create_server_context():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain("certs/server.crt", "certs/server.key")
    context.load_verify_locations("certs/client.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def create_client_context():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain("certs/client.crt", "certs/client.key")
    context.load_verify_locations("certs/server.crt")
    return context
