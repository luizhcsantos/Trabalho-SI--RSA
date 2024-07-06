import socket
from diffiehellman import DiffieHellman
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_message(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = base64.b64encode(cipher.encrypt(pad(plaintext.encode(), AES.block_size)))
    return ciphertext

def decrypt_message(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return plaintext

# Configurações do servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('200.145.184.166', 65432))
server_socket.listen(1)

print("Servidor aguardando conexão...")

# Aceita conexão do cliente
conn, addr = server_socket.accept()
print(f"Conectado por {addr}")

# DH parameters
dh_server = DiffieHellman()
dh_server.generate_public_key()

# Envia chave pública do servidor para o cliente
conn.sendall(dh_server.public_key.to_bytes(256, 'big'))

# Recebe chave pública do cliente
client_public_key_bytes = conn.recv(256)
client_public_key = int.from_bytes(client_public_key_bytes, 'big')

# Calcula chave simétrica compartilhada
shared_key = dh_server.generate_shared_secret(client_public_key).to_bytes(32, 'big')

print(f"Chave compartilhada: {shared_key.hex()}")

# Comunica-se com o cliente
while True:
    data = conn.recv(1024)
    if not data:
        break
    message = decrypt_message(shared_key, data)
    print(f"Cliente: {message.decode()}")
    response = input("Servidor: ")
    conn.sendall(encrypt_message(shared_key, response))

conn.close()
