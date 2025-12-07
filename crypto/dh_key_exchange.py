import random

# número primo seguro
P = 0xFFFFFFFEFFFFEE37
G = 2

def generate_keys():
    private = random.randint(2, P-2)
    public = pow(G, private, P)
    return private, public

def generate_shared_key(private, peer_public):
    return pow(peer_public, private, P)
