from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# Programa que gera uma chave pública e uma privada
# utilizando o algortimo RSA da biblioteca 'cryptography'


# Gera chave privada
chave_privada = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Gera chave pública
chave_publica = chave_privada.public_key()

# Serializa a chave privada
private_pem = chave_privada.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Serializa a chave pública
public_pem = chave_publica.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print(private_pem.decode('utf-8'))
print(public_pem.decode('utf-8'))
