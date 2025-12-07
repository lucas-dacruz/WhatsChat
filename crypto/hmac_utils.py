import hmac
import hashlib

def generate_hmac(key, message):
    key = str(key).encode()
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(key, message, tag):
    return generate_hmac(key, message) == tag
