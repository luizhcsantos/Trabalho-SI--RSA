import random
from sympy import isprime, mod_inverse

def generate_prime_candidate(length):
    # Gera um número ímpar aleatório
    p = random.getrandbits(length)
    # Aplica máscara para garantir comprimento correto
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=1024):
    p = 4
    # Continua até que seja um número primo
    while not isprime(p):
        p = generate_prime_candidate(length)
    return p

def generate_rsa_keys(bit_length=1024):
    p = generate_prime_number(bit_length // 2)
    q = generate_prime_number(bit_length // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

public_key, private_key = generate_rsa_keys()

print(f"Public Key: {public_key}")
print(f"Private Key: {private_key}")
