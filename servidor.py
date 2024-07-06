import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import DSA
from Crypto.Random import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from hashlib import sha256

# Configurações do servidor
HOST = 'localhost'
PORT = 5000

# Gerar parâmetros primo e gerador para Diffie-Hellman
primo = getPrime(1024)
gerador = 2

# Gerar par de chaves Diffie-Hellman
def gerar_chave_dh(primo, gerador):
    chave_privada = random.StrongRandom().randint(1, primo - 1)
    chave_publica = pow(gerador, chave_privada, primo)
    return chave_privada, chave_publica

# Calcular a chave compartilhada
def calcular_chave_compartilhada(chave_privada, chave_publica, primo):
    chave_compartilhada = pow(chave_publica, chave_privada, primo)
    return sha256(long_to_bytes(chave_compartilhada)).digest()[:16]

# Configurar socket do servidor
socket_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_servidor.bind((HOST, PORT))
socket_servidor.listen(1)
print(f'Servidor ouvindo em {HOST}:{PORT}...')

conn, addr = socket_servidor.accept()
print(f'Conexão estabelecida com {addr}')

# Enviar parâmetros primo e gerador para o cliente
conn.sendall(f'{primo},{gerador}'.encode())

# Gerar par de chaves Diffie-Hellman
chave_privada, chave_publica = gerar_chave_dh(primo, gerador)
chave_publica_cliente = int(conn.recv(1024).decode())
conn.sendall(f'{chave_publica}'.encode())
chave_compartilhada = calcular_chave_compartilhada(chave_privada, chave_publica_cliente, primo)
print('Chave compartilhada estabelecida:', chave_compartilhada.hex())

# Função para criptografar mensagens
def criptografar_mensagem(chave, mensagem):
    cifra = AES.new(chave, AES.MODE_CBC)
    mensagem_preenchida = pad(mensagem.encode(), AES.block_size)
    mensagem_cifrada = cifra.encrypt(mensagem_preenchida)
    iv = cifra.iv
    mensagem_encriptada = iv + mensagem_cifrada
    hash_integridade = sha256(mensagem_encriptada).hexdigest()
    print(f'IV: {iv.hex()}')
    print(f'Texto cifrado: {mensagem_cifrada.hex()}')
    print(f'Hash de integridade: {hash_integridade}')
    return mensagem_encriptada + hash_integridade.encode()

# Função para descriptografar mensagens
def descriptografar_mensagem(chave, mensagem_cifrada):
    iv = mensagem_cifrada[:AES.block_size]
    mensagem_cifrada_real = mensagem_cifrada[AES.block_size:-64]
    hash_integridade_recebido = mensagem_cifrada[-64:].decode()
    hash_integridade_calculado = sha256(iv + mensagem_cifrada_real).hexdigest()
    if hash_integridade_recebido != hash_integridade_calculado:
        raise ValueError("Hash de integridade não corresponde")
    print(f'Recebido IV: {iv.hex()}')
    print(f'Recebido texto cifrado: {mensagem_cifrada_real.hex()}')
    print(f'Recebido hash de integridade: {hash_integridade_recebido}')
    cifra = AES.new(chave, AES.MODE_CBC, iv)
    mensagem_preenchida = cifra.decrypt(mensagem_cifrada_real)
    print(f'Texto descriptografado antes do unpad: {mensagem_preenchida.hex()}')
    print(f'Texto descriptografado em ASCII: {mensagem_preenchida}')
    try:
        mensagem_decifrada = unpad(mensagem_preenchida, AES.block_size)
    except ValueError as e:
        print(f"Erro no unpad: {e}")
        raise
    return mensagem_decifrada.decode()

# Comunicação criptografada
try:
    while True:
        mensagem_cifrada = conn.recv(2048)
        if not mensagem_cifrada:
            break
        try:
            mensagem_decifrada = descriptografar_mensagem(chave_compartilhada, mensagem_cifrada)
            print(f'Cliente: {mensagem_decifrada}')
            resposta = input('Servidor: ')
            mensagem_encriptada = criptografar_mensagem(chave_compartilhada, resposta)
            conn.sendall(mensagem_encriptada)
        except Exception as e:
            print(f'Erro durante descriptografia: {e}')
            break
except Exception as e:
    print(f'Erro: {e}')
finally:
    conn.close()
    socket_servidor.close()
