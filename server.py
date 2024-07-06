import socket
from Cryptodome.PublicKey import DSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64
import hashlib

def encrypt_message(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = base64.b64encode(cipher.encrypt(pad(plaintext.encode(), AES.block_size)))
    return ciphertext

def decrypt_message(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return plaintext

# Função para ler credenciais do arquivo
def read_credentials(filepath):
    with open(filepath, 'r') as file:
        lines = file.readlines()
        username = lines[0].strip().split(': ')[1]
        password = lines[1].strip().split(': ')[1]
    return username, password

# Leia as credenciais do arquivo
credentials_file = 'credentials.txt'
expected_username, expected_password = read_credentials(credentials_file)

# Configurações do servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 40665))  # Bind to all interfaces
server_socket.listen(1)

print("Servidor aguardando conexão...")

# Aceita conexão do cliente
conn, addr = server_socket.accept()
print(f"Conectado por {addr}")

# Autenticação
try:
    # Recebe nome de usuário
    username = conn.recv(1024).decode()
    print(f"Nome de usuário recebido: {username}")
    conn.sendall(b"Username received")

    # Recebe senha
    password = conn.recv(1024).decode()
    print(f"Senha recebida: {password}")

    if username == expected_username and password == expected_password:
        conn.sendall(b"Authentication successful")
        print("Autenticação bem-sucedida")
    else:
        conn.sendall(b"Authentication failed")
        print("Autenticação falhou")
        conn.close()
        exit()
except Exception as e:
    print(f"Erro durante a autenticação: {e}")
    conn.close()
    exit()

# DH parameters
try:
    private_key = DSA.generate(2048)
    public_key = private_key.publickey()

    # Envia chave pública do servidor para o cliente
    conn.sendall(public_key.export_key())
    print("Chave pública do servidor enviada")

    # Recebe chave pública do cliente
    client_public_key_data = conn.recv(1024)
    client_public_key = DSA.import_key(client_public_key_data)
    print("Chave pública do cliente recebida")

    # Calcula chave simétrica compartilhada
    shared_secret = pow(int.from_bytes(client_public_key.y, 'big'), private_key.x, int.from_bytes(client_public_key.p, 'big'))
    shared_key = hashlib.sha256(shared_secret.to_bytes(256, 'big')).digest()

    print(f"Chave compartilhada: {shared_key.hex()}")
except Exception as e:
    print(f"Erro durante a troca de chaves DH: {e}")
    conn.close()
    exit()

# Comunica-se com o cliente
while True:
    try:
        data = conn.recv(1024)
        if not data:
            break
        message = decrypt_message(shared_key, data)
        print(f"Cliente: {message.decode()}")
        response = input("Servidor: ")
        conn.sendall(encrypt_message(shared_key, response))
    except Exception as e:
        print(f"Erro durante a comunicação: {e}")
        conn.close()
        break
