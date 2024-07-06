import random
from sympy import isprime, mod_inverse

# Programa que gera uma chave pública e uma privada



def gerar_candidato_primo(comprimento):
    # Gera um número ímpar aleatório
    p = random.getrandbits(comprimento)
    # Aplica máscara para garantir comprimento correto
    p |= (1 << comprimento - 1) | 1
    return p

def gerar_numero_primo(comprimento=1024):
    p = 4
    # Continua até que seja um número primo
    while not isprime(p):
        p = gerar_candidato_primo(comprimento)
    return p

def gerar_chave_rsa(comprimento_bit=1024):
    p = gerar_numero_primo(comprimento_bit // 2)
    q = gerar_numero_primo(comprimento_bit // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

chave_publica, chave_privada = gerar_chave_rsa()

print(f"Chave pública: {chave_publica}")
print(f"Chave privada: {chave_privada}")
