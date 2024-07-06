import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import DSA
from Crypto.Random import random
from hashlib import sha256

# Configurações do servidor
HOST = 'localhost'
PORT = 5000

# Gerar par de chaves DH
def generate_dh_key():
    key = DSA.generate(1024)
    private_key = random.StrongRandom().randint(1, key.q - 1)
    public_key = pow(2, private_key, key.p)
    # print("public key: ", public_key, "\nprivate key: ", private_key)
    return private_key, public_key, key.p, key.q

# Calcular a chave compartilhada
def calculate_shared_key(private_key, public_key, p):
    shared_key = pow(public_key, private_key, p)
    return sha256(shared_key.to_bytes(128, 'big')).digest()[:16]

# Configurar socket do servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)
print(f'Servidor ouvindo em {HOST}:{PORT}...')

conn, addr = server_socket.accept()
print(f'Conexão estabelecida com {addr}')

# Troca de chaves DH
private_key, public_key, p, q = generate_dh_key()
conn.sendall(f'{public_key},{p},{q}'.encode())
client_data = conn.recv(1024).decode()
client_public_key = int(client_data.split(',')[0])
shared_key = calculate_shared_key(private_key, client_public_key, p)
print('Chave compartilhada estabelecida.')

# Função para criptografar mensagens
def encrypt_message(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    iv = cipher.iv
    encrypted_message = iv + ct_bytes
    print(f'Mensagem criptografada: {encrypted_message.hex()}')
    return encrypted_message

# Função para descriptografar mensagens
def decrypt_message(key, ciphertext):
    print(f'Mensagem recebida criptografada: {ciphertext.hex()}')
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    obj = cipher.decrypt(ct)
    pt = unpad(obj, AES.block_size)
    return pt.decode()

# Comunicação criptografada
try:
    while True:
        encrypted_msg = conn.recv(2048)  # Aumentando o buffer de recebimento
        if not encrypted_msg:
            break
        try:
            decrypted_msg = decrypt_message(shared_key, encrypted_msg)
            print(f'Cliente: {decrypted_msg}')
            response = input('Servidor: ')
            encrypted_response = encrypt_message(shared_key, response)
            conn.sendall(encrypted_response)
        except Exception as e: 
            print(f'Erro durante descriptografia: {e}')
            break; 
except Exception as e:
    print(f'Erro: {e}')
finally:
    conn.close()
    server_socket.close()
