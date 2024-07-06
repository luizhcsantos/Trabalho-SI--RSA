import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import DSA
from Crypto.Random import random
from hashlib import sha256

# Configurações do cliente
HOST = 'localhost'
PORT = 5000

# Gerar par de chaves DH
def generate_dh_key():
    key = DSA.generate(1024)
    private_key = random.StrongRandom().randint(1, key.q - 1)
    public_key = pow(2, private_key, key.p)
    return private_key, public_key, key.p, key.q

# Calcular a chave compartilhada
def calculate_shared_key(private_key, public_key, p):
    shared_key = pow(public_key, private_key, p)
    return sha256(shared_key.to_bytes(128, 'big')).digest()[:16]

# Configurar socket do cliente
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# Troca de chaves DH
private_key, public_key, p, q = generate_dh_key()
server_data = client_socket.recv(1024).decode()
server_public_key, p, q = map(int, server_data.split(','))
client_socket.sendall(f'{public_key}'.encode())
shared_key = calculate_shared_key(private_key, server_public_key, p)
print('Chave compartilhada estabelecida.')

# Função para criptografar mensagens
def encrypt_message(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    iv = cipher.iv
    encrypted_message = iv + ct_bytes
    print(f'IV: {iv.hex()}')
    print(f'Texto cifrado: {ct_bytes.hex()}')
    return encrypted_message

# Função para descriptografar mensagens
def decrypt_message(key, ciphertext):
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    print(f'Recebido IV: {iv.hex()}')
    print(f'Recebido texto cifrado: {ct.hex()}')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# Comunicação criptografada
try:
    while True:
        message = input('Cliente: ')
        encrypted_message = encrypt_message(shared_key, message)
        client_socket.sendall(encrypted_message)
        
        encrypted_response = client_socket.recv(2048)
        response = decrypt_message(shared_key, encrypted_response)
        print(f'Servidor: {response}')
except Exception as e:
    print(f'Erro: {e}')
finally:
    client_socket.close()
