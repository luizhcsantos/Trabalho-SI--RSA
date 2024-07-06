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
username, password = read_credentials(credentials_file)

# Configurações do cliente
try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Tentando conectar ao servidor...")
    client_socket.connect(('200.145.184.166', 40665))  # Usando a porta 5000
    print("Conectado ao servidor")
except Exception as e:
    print(f"Erro ao conectar: {e}")
    exit()

try:
    # Envia nome de usuário
    client_socket.sendall(username.encode())
    response = client_socket.recv(1024).decode()
    print(f"Resposta do servidor após enviar nome de usuário: {response}")

    # Envia senha
    client_socket.sendall(password.encode())
    response = client_socket.recv(1024).decode()
    print(f"Resposta do servidor após enviar senha: {response}")

    if response == "Authentication failed":
        print("Autenticação falhou")
        client_socket.close()
        exit()
except Exception as e:
    print(f"Erro durante a autenticação: {e}")
    client_socket.close()
    exit()

# DH parameters
try:
    private_key = DSA.generate(2048)
    public_key = private_key.publickey()

    # Recebe chave pública do servidor
    server_public_key_data = client_socket.recv(1024)
    server_public_key = DSA.import_key(server_public_key_data)
    print("Chave pública do servidor recebida")

    # Envia chave pública do cliente para o servidor
    client_socket.sendall(public_key.export_key())
    print("Chave pública do cliente enviada ao servidor")

    # Calcula chave simétrica compartilhada
    shared_secret = pow(int.from_bytes(server_public_key.y, 'big'), private_key.x, int.from_bytes(server_public_key.p, 'big'))
    shared_key = hashlib.sha256(shared_secret.to_bytes(256, 'big')).digest()

    print(f"Chave compartilhada: {shared_key.hex()}")
except Exception as e:
    print(f"Erro durante a troca de chaves DH: {e}")
    client_socket.close()
    exit()

# Comunica-se com o servidor
while True:
    try:
        message = input("Cliente: ")
        client_socket.sendall(encrypt_message(shared_key, message))
        data = client_socket.recv(1024)
        response = decrypt_message(shared_key, data)
        print(f"Servidor: {response.decode()}")
    except Exception as e:
        print(f"Erro durante a comunicação: {e}")
        client_socket.close()
        break
